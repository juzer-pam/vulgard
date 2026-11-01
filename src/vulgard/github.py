from __future__ import annotations

import base64
import os
import time
from datetime import datetime
from typing import Any

import httpx

API_URL = "https://api.github.com"

DEPENDABOT_PRS_QUERY = """
query($q: String!, $after: String) {
  search(query: $q, type: ISSUE, first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on PullRequest {
        number title url createdAt isDraft mergeable
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

    def _paginate(self, url: str, params: dict[str, Any] | None = None) -> list[Any]:
        items: list[Any] = []
        next_url: str | None = url
        next_params = {"per_page": 100, **(params or {})}
        while next_url:
            resp = self._request("GET", next_url, params=next_params)
            data = resp.json()
            items.extend(data["items"] if isinstance(data, dict) and "items" in data else data)
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

    def list_closed_alerts(self, org: str, since: datetime) -> list[dict[str, Any]]:
        """Alerts fixed or dismissed since `since`, newest first (stops paging once older)."""
        items: list[dict[str, Any]] = []
        next_url: str | None = f"/orgs/{org}/dependabot/alerts"
        params: dict[str, Any] | None = {
            "state": "fixed,dismissed",
            "sort": "updated",
            "direction": "desc",
            "per_page": 100,
        }
        while next_url:
            resp = self._request("GET", next_url, params=params)
            for alert in resp.json():
                if datetime.fromisoformat(alert["updated_at"].replace("Z", "+00:00")) < since:
                    return items
                items.append(alert)
            next_url = resp.links.get("next", {}).get("url")
            params = None
        return items

    def list_dependabot_prs(self, org: str) -> list[dict[str, Any]]:
        search = f"org:{org} is:pr is:open author:app/dependabot archived:false"
        prs: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            variables = {"q": search, "after": after}
            data = self._json(
                "POST", "/graphql", json={"query": DEPENDABOT_PRS_QUERY, "variables": variables}
            )
            if data.get("errors"):
                messages = "; ".join(e.get("message", "") for e in data["errors"])
                raise GitHubError(200, messages, "/graphql")
            result = data["data"]["search"]
            for node in result["nodes"]:
                if not node:
                    continue
                commits = node["commits"]["nodes"]
                rollup = commits[0]["commit"]["statusCheckRollup"] if commits else None
                prs.append(
                    {
                        "number": node["number"],
                        "title": node["title"],
                        "html_url": node["url"],
                        "repository_url": f"{API_URL}/repos/{org}/{node['repository']['name']}",
                        "created_at": node["createdAt"],
                        "draft": node["isDraft"],
                        "mergeable": node["mergeable"],
                        "ci_state": rollup["state"] if rollup else None,
                    }
                )
            if not result["pageInfo"]["hasNextPage"]:
                return prs
            after = result["pageInfo"]["endCursor"]

    def get_file(self, org: str, repo: str, path: str) -> str | None:
        try:
            data = self._json("GET", f"/repos/{org}/{repo}/contents/{path}")
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

    def find_open_issue(self, org: str, repo: str, label: str) -> dict[str, Any] | None:
        issues = self._json(
            "GET",
            f"/repos/{org}/{repo}/issues",
            params={"labels": label, "state": "open", "per_page": 10},
        )
        issues = [i for i in issues if "pull_request" not in i]
        return issues[0] if issues else None

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
        return self._json(
            "POST",
            f"/repos/{org}/{repo}/pulls",
            json={"title": title, "body": body, "head": head, "base": base},
        )

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
