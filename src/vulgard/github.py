from __future__ import annotations

import base64
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

API_URL = "https://api.github.com"

EMPTY_BODY_RETRIES = 2
SEARCH_RESULT_CAP = 1000  # GitHub search returns at most this many results for one query
SEARCH_START = datetime(2008, 1, 1, tzinfo=UTC)  # before any PR on GitHub was created

# GitHub cuts off GraphQL requests after about 10 seconds. A 50-PR page of this query takes
# 7 to 11, mostly computing `mergeable` and the CI rollup, and 20 takes about 4.
DEPENDABOT_PRS_QUERY = """
query($q: String!, $after: String) {
  search(query: $q, type: ISSUE, first: 20, after: $after) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on PullRequest {
        number title body url createdAt isDraft mergeable
        repository { name }
        commits(last: 1) { nodes { commit { statusCheckRollup { state } } } }
      }
    }
  }
}
"""


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, url: str):
        super().__init__(f"GitHub API {status} on {url}: {message}")
        self.status = status


def _pr_from_node(org: str, node: dict[str, Any]) -> dict[str, Any]:
    commits = node["commits"]["nodes"]
    rollup = commits[0]["commit"]["statusCheckRollup"] if commits else None
    return {
        "number": node["number"],
        "title": node["title"],
        "body": node["body"],
        "html_url": node["url"],
        "repository_url": f"{API_URL}/repos/{org}/{node['repository']['name']}",
        "created_at": node["createdAt"],
        "draft": node["isDraft"],
        "mergeable": node["mergeable"],
        "ci_state": rollup["state"] if rollup else None,
    }


class GitHub:
    """Thin GitHub REST client covering only the endpoints vulgard needs."""

    def __init__(self, token: str | None = None, base_url: str | None = None):
        token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            raise ValueError("A GitHub token is required (set GITHUB_TOKEN or GH_TOKEN)")
        self._http = httpx.Client(
            base_url=base_url or os.environ.get("GITHUB_API_URL", API_URL),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "vulgard",
            },
            timeout=30.0,
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(4):
            resp = self._http.request(method, url, **kwargs)
            rate_limited = resp.status_code in (403, 429) and (
                resp.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in resp.headers
            )
            if not rate_limited and resp.status_code < 500:
                break
            if attempt == 3:
                break
            wait = float(resp.headers.get("retry-after") or 2 ** (attempt + 1))
            reset = resp.headers.get("x-ratelimit-reset")
            if rate_limited and reset:
                wait = max(wait, min(float(reset) - time.time(), 300))
            time.sleep(max(wait, 1))
        if resp.status_code >= 400:
            try:
                message = resp.json().get("message", resp.text)
            except ValueError:
                message = resp.text
            raise GitHubError(resp.status_code, message, str(resp.url))
        return resp

    def _json(self, method: str, url: str, **kwargs: Any) -> Any:
        resp = self._request(method, url, **kwargs)
        return resp.json() if resp.content else None

    def _paginate(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        until: Callable[[Any], bool] | None = None,
    ) -> list[Any]:
        """Fetch every page; with `until`, stop at the first item it matches (exclusive)."""
        items: list[Any] = []
        next_url: str | None = url
        next_params: dict[str, Any] | None = {"per_page": 100, **(params or {})}
        while next_url:
            resp = self._request("GET", next_url, params=next_params)
            data = resp.json()
            for item in data["items"] if isinstance(data, dict) and "items" in data else data:
                if until and until(item):
                    return items
                items.append(item)
            next_url = resp.links.get("next", {}).get("url")
            next_params = None
        return items

    # --- reads -----------------------------------------------------------

    def list_repos(self, org: str) -> list[dict[str, Any]]:
        return self._paginate(f"/orgs/{org}/repos", {"type": "all"})

    def get_repo(self, org: str, repo: str) -> dict[str, Any]:
        return self._json("GET", f"/repos/{org}/{repo}")

    def list_open_alerts(self, org: str) -> list[dict[str, Any]]:
        return self._paginate(f"/orgs/{org}/dependabot/alerts", {"state": "open"})

    def get_sbom(self, org: str, repo: str) -> dict[str, Any] | None:
        """The default branch's dependency graph as SPDX, or None when the repo has none."""
        try:
            return self._json("GET", f"/repos/{org}/{repo}/dependency-graph/sbom")
        except GitHubError as e:
            if e.status == 404:
                return None
            raise

    def list_closed_alerts(self, org: str, since: datetime) -> list[dict[str, Any]]:
        return self._paginate(
            f"/orgs/{org}/dependabot/alerts",
            {"state": "fixed,dismissed", "sort": "updated", "direction": "desc"},
            until=lambda a: datetime.fromisoformat(a["updated_at"].replace("Z", "+00:00")) < since,
        )

    def list_dependabot_prs(self, org: str) -> list[dict[str, Any]]:
        search = f"org:{org} is:pr is:open author:app/dependabot archived:false"
        return self._search_prs(org, search, SEARCH_START, datetime.now(UTC).replace(microsecond=0))

    def _search_prs(
        self, org: str, search: str, start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        """Every PR created in [start, end]. A range with more PRs than search returns is split
        in half by creation time until each half fits."""
        query = f"{search} created:{start:%Y-%m-%dT%H:%M:%SZ}..{end:%Y-%m-%dT%H:%M:%SZ}"
        prs: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            result = self._search_page(query, after)
            if after is None and result["issueCount"] > SEARCH_RESULT_CAP and end > start:
                middle = (start + (end - start) / 2).replace(microsecond=0)
                return self._search_prs(org, search, start, middle) + self._search_prs(
                    org, search, middle + timedelta(seconds=1), end
                )
            prs += [_pr_from_node(org, node) for node in result["nodes"] if node]
            if not result["pageInfo"]["hasNextPage"]:
                return prs
            after = result["pageInfo"]["endCursor"]

    def _search_page(self, query: str, after: str | None) -> dict[str, Any]:
        """GitHub's GraphQL search sometimes answers 200 with an empty body, so that is retried
        like a 5xx."""
        for attempt in range(EMPTY_BODY_RETRIES + 1):
            data = self._json(
                "POST",
                "/graphql",
                json={"query": DEPENDABOT_PRS_QUERY, "variables": {"q": query, "after": after}},
            )
            if data:
                break
            time.sleep(2 ** (attempt + 1))
        else:
            raise GitHubError(200, "empty response from the search", "/graphql")
        if data.get("errors"):
            messages = "; ".join(e.get("message", "") for e in data["errors"])
            raise GitHubError(200, messages, "/graphql")
        return data["data"]["search"]

    def get_file(self, org: str, repo: str, path: str, ref: str | None = None) -> str | None:
        try:
            data = self._json(
                "GET", f"/repos/{org}/{repo}/contents/{path}", params={"ref": ref} if ref else None
            )
        except GitHubError as e:
            if e.status == 404:
                return None
            raise
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    def list_tree_paths(self, org: str, repo: str, branch: str) -> list[str]:
        try:
            data = self._json(
                "GET", f"/repos/{org}/{repo}/git/trees/{branch}", params={"recursive": "1"}
            )
        except GitHubError as e:
            if e.status in (404, 409):
                return []
            raise
        return [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"]

    def list_commits(self, org: str, repo: str, branch: str, n: int = 30) -> list[dict[str, Any]]:
        """The latest `n` commits on `branch`, newest first. Empty for an empty repo."""
        try:
            return self._json(
                "GET", f"/repos/{org}/{repo}/commits", params={"sha": branch, "per_page": n}
            )
        except GitHubError as e:
            if e.status in (404, 409):
                return []
            raise

    def find_issue(self, org: str, repo: str, label: str) -> dict[str, Any] | None:
        """The open issue with this label, else the most recently created closed one."""
        issues = self._json(
            "GET",
            f"/repos/{org}/{repo}/issues",
            params={"labels": label, "state": "all", "sort": "created", "per_page": 20},
        )
        issues = [i for i in issues if "pull_request" not in i]
        return next((i for i in issues if i["state"] == "open"), issues[0] if issues else None)

    def repos_with_open_issues(self, org: str, label: str) -> list[str]:
        """Names of the org's unarchived repos that have an open issue with this label, found
        with one search instead of a lookup per repo."""
        found = self._paginate(
            "/search/issues",
            {"q": f'org:{org} is:issue is:open archived:false label:"{label}"'},
        )
        return sorted({i["repository_url"].rstrip("/").rsplit("/", 1)[-1] for i in found})

    def find_workflow_run(
        self, org: str, repo: str, workflow: str, marker: str
    ) -> dict[str, Any] | None:
        """The newest recent dispatched run of `workflow` whose run name contains `marker`."""
        try:
            data = self._json(
                "GET",
                f"/repos/{org}/{repo}/actions/workflows/{workflow}/runs",
                params={"event": "workflow_dispatch", "per_page": 50},
            )
        except GitHubError as e:
            if e.status == 404:
                return None
            raise
        runs = data.get("workflow_runs", [])
        return next((r for r in runs if marker in (r.get("display_title") or "")), None)

    def dispatch_workflow(
        self, org: str, repo: str, workflow: str, ref: str, inputs: dict[str, str]
    ) -> None:
        self._json(
            "POST",
            f"/repos/{org}/{repo}/actions/workflows/{workflow}/dispatches",
            json={"ref": ref, "inputs": inputs},
        )

    def list_issue_comments(self, org: str, repo: str, number: int) -> list[dict[str, Any]]:
        return self._paginate(f"/repos/{org}/{repo}/issues/{number}/comments")

    def can_write(self, org: str, repo: str, user: str) -> bool:
        """Whether `user` has write, maintain or admin access to the repo. `permission` is the
        legacy four-level field, where maintain reads as write; `role_name` names the role."""
        try:
            data = self._json("GET", f"/repos/{org}/{repo}/collaborators/{user}/permission")
        except GitHubError as e:
            if e.status == 404:
                return False
            raise
        return data.get("permission") in ("write", "admin") or data.get("role_name") in (
            "write",
            "maintain",
            "admin",
        )

    def find_open_pr(self, org: str, repo: str, head_branch: str) -> dict[str, Any] | None:
        prs = self._json(
            "GET",
            f"/repos/{org}/{repo}/pulls",
            params={"head": f"{org}:{head_branch}", "state": "open"},
        )
        return prs[0] if prs else None

    def get_branch_sha(self, org: str, repo: str, branch: str) -> str | None:
        try:
            data = self._json("GET", f"/repos/{org}/{repo}/git/ref/heads/{branch}")
        except GitHubError as e:
            if e.status == 404:
                return None
            raise
        return data["object"]["sha"]

    def list_org_rulesets(self, org: str) -> list[dict[str, Any]]:
        return self._paginate(f"/orgs/{org}/rulesets")

    # --- writes ----------------------------------------------------------

    def ensure_label(self, org: str, repo: str, label: str) -> None:
        try:
            self._json(
                "POST",
                f"/repos/{org}/{repo}/labels",
                json={"name": label, "color": "b60205", "description": "Tracked by vulgard"},
            )
        except GitHubError as e:
            if e.status != 422:
                raise

    def create_issue(
        self,
        org: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str],
        assignees: list[str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": title, "body": body, "labels": labels}
        if assignees:
            try:
                return self._json(
                    "POST", f"/repos/{org}/{repo}/issues", json={**payload, "assignees": assignees}
                )
            except GitHubError as e:
                # An owner without repo access can't be assigned; still open the issue.
                if e.status != 422:
                    raise
        return self._json("POST", f"/repos/{org}/{repo}/issues", json=payload)

    def update_issue(self, org: str, repo: str, number: int, **fields: Any) -> dict[str, Any]:
        return self._json("PATCH", f"/repos/{org}/{repo}/issues/{number}", json=fields)

    def comment_issue(self, org: str, repo: str, number: int, body: str) -> None:
        self._json("POST", f"/repos/{org}/{repo}/issues/{number}/comments", json={"body": body})

    def create_branch(self, org: str, repo: str, branch: str, sha: str) -> None:
        self._json(
            "POST",
            f"/repos/{org}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )

    def update_branch(self, org: str, repo: str, branch: str, sha: str, *, force: bool) -> None:
        payload: dict[str, Any] = {"sha": sha}
        if force:
            payload["force"] = True
        self._json("PATCH", f"/repos/{org}/{repo}/git/refs/heads/{branch}", json=payload)

    def merge_pull_request(
        self, org: str, repo: str, number: int, merge_method: str = "squash"
    ) -> None:
        self._json(
            "PUT",
            f"/repos/{org}/{repo}/pulls/{number}/merge",
            json={"merge_method": merge_method},
        )

    def put_file(
        self, org: str, repo: str, path: str, content: str, message: str, branch: str
    ) -> None:
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        try:
            existing = self._json(
                "GET", f"/repos/{org}/{repo}/contents/{path}", params={"ref": branch}
            )
            payload["sha"] = existing["sha"]
        except GitHubError as e:
            if e.status != 404:
                raise
        self._json("PUT", f"/repos/{org}/{repo}/contents/{path}", json=payload)

    def create_pr(
        self, org: str, repo: str, title: str, body: str, head: str, base: str
    ) -> dict[str, Any]:
        """A POST retried after a 5xx can hit the PR it already opened, so a 422 returns that."""
        try:
            return self._json(
                "POST",
                f"/repos/{org}/{repo}/pulls",
                json={"title": title, "body": body, "head": head, "base": base},
            )
        except GitHubError as e:
            existing = self.find_open_pr(org, repo, head) if e.status == 422 else None
            if existing is None:
                raise
            return existing

    def enable_security_features(self, org: str, repo: str, allow_auto_merge: bool) -> None:
        self._request("PUT", f"/repos/{org}/{repo}/vulnerability-alerts")
        self._request("PUT", f"/repos/{org}/{repo}/automated-security-fixes")
        if allow_auto_merge:
            self._json(
                "PATCH",
                f"/repos/{org}/{repo}",
                json={"allow_auto_merge": True, "delete_branch_on_merge": True},
            )

    def create_org_ruleset(self, org: str, ruleset: dict[str, Any]) -> dict[str, Any]:
        return self._json("POST", f"/orgs/{org}/rulesets", json=ruleset)

    def update_org_ruleset(self, org: str, ruleset_id: int, ruleset: dict[str, Any]) -> None:
        self._json("PUT", f"/orgs/{org}/rulesets/{ruleset_id}", json=ruleset)
