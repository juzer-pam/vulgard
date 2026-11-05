from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .aws import sight_amplify_branch, sight_cfn_stack, sight_finding, sight_sst_objects
from .clients import Clients
from .config import IssueConfig
from .estate import Deployment, Found, NativeRef, RunState, Sighting
from .inspector import Finding
from .lifecycle import Op, SafeDelete, Verb
from .policy import now_utc
from .vercel import sight_vercel_project

RELATIVE_RE = re.compile(r"^@-(\d+)d$")


def _resolve_dates(value: Any, now: datetime) -> Any:
    """Turn "@-12d" into an ISO timestamp 12 days before now so demo data never goes stale."""
    if isinstance(value, dict):
        return {k: _resolve_dates(v, now) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_dates(v, now) for v in value]
    if isinstance(value, str) and (m := RELATIVE_RE.match(value)):
        return (now - timedelta(days=int(m.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def issue_key(repo: str, label: str) -> str:
    """Fixture key for a repo's tracking issue: the repo for the default label, else repo#label."""
    return repo if label == IssueConfig().label else f"{repo}#{label}"


class FixtureGitHub:
    """In-memory stand-in for the GitHub client, backed by a JSON file. Writes are recorded."""

    def __init__(self, data: dict[str, Any], now: datetime | None = None):
        self.now = now or now_utc()
        self.data = _resolve_dates(copy.deepcopy(data), self.now)
        self.writes: list[tuple[str, tuple[Any, ...]]] = []
        self._next_issue = 1000
        self._next_comment = 5000

    @classmethod
    def from_file(cls, path: str | Path, now: datetime | None = None) -> FixtureGitHub:
        return cls(json.loads(Path(path).read_text()), now)

    def _record(self, op: str, *args: Any) -> None:
        self.writes.append((op, args))

    def list_repos(self, org: str) -> list[dict[str, Any]]:
        return self.data.get("repos", [])

    def get_repo(self, org: str, repo: str) -> dict[str, Any]:
        return next(r for r in self.data.get("repos", []) if r["name"] == repo)

    def list_open_alerts(self, org: str) -> list[dict[str, Any]]:
        return self.data.get("alerts", [])

    def get_sbom(self, org: str, repo: str) -> dict[str, Any] | None:
        return self.data.get("sboms", {}).get(repo)

    def list_closed_alerts(self, org: str, since: datetime) -> list[dict[str, Any]]:
        return self.data.get("closed_alerts", [])

    def list_dependabot_prs(self, org: str) -> list[dict[str, Any]]:
        return self.data.get("dependabot_prs", [])

    def get_file(self, org: str, repo: str, path: str, ref: str | None = None) -> str | None:
        return self.data.get("files", {}).get(repo, {}).get(path)

    def list_tree_paths(self, org: str, repo: str, branch: str) -> list[str]:
        return self.data.get("trees", {}).get(repo, [])

    def list_commits(self, org: str, repo: str, branch: str, n: int = 30) -> list[dict[str, Any]]:
        return [
            {"commit": {"committer": {"date": c["date"]}}, "author": {"login": c.get("login", "")}}
            for c in self.data.get("commits", {}).get(repo, [])
        ][:n]

    def find_issue(self, org: str, repo: str, label: str) -> dict[str, Any] | None:
        return self.data.get("issues", {}).get(issue_key(repo, label))

    def list_issue_comments(self, org: str, repo: str, number: int) -> list[dict[str, Any]]:
        return self.data.get("comments", {}).get(f"{repo}#{number}", [])

    def can_write(self, org: str, repo: str, user: str) -> bool:
        writers = self.data.get("writers")
        return writers is None or user in writers

    def find_open_pr(self, org: str, repo: str, head_branch: str) -> dict[str, Any] | None:
        return self.data.get("open_prs", {}).get(repo, {}).get(head_branch)

    def get_branch_sha(self, org: str, repo: str, branch: str) -> str | None:
        return "0" * 40 if branch == self.get_repo(org, repo).get("default_branch") else None

    def list_org_rulesets(self, org: str) -> list[dict[str, Any]]:
        return self.data.get("rulesets", [])

    def ensure_label(self, org: str, repo: str, label: str) -> None:
        self._record("ensure_label", repo, label)

    def create_issue(
        self,
        org: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str],
        assignees: list[str] | None = None,
    ) -> dict[str, Any]:
        self._next_issue += 1
        issue = {
            "number": self._next_issue,
            "title": title,
            "body": body,
            "state": "open",
            "html_url": f"https://github.com/{org}/{repo}/issues/{self._next_issue}",
            "assignees": assignees or [],
        }
        self.data.setdefault("issues", {})[issue_key(repo, labels[0])] = issue
        self._record("create_issue", repo, title, body)
        return issue

    def update_issue(self, org: str, repo: str, number: int, **fields: Any) -> dict[str, Any]:
        issue = next(
            i
            for key, i in self.data["issues"].items()
            if key.split("#")[0] == repo and i["number"] == number
        )
        issue.update(fields)
        self._record("update_issue", repo, number, fields)
        return issue

    def comment_issue(self, org: str, repo: str, number: int, body: str) -> None:
        """Recorded, and added to the thread as the bot, so later runs read it back."""
        self._record("comment_issue", repo, number, body)
        self._next_comment += 1
        thread = self.data.setdefault("comments", {}).setdefault(f"{repo}#{number}", [])
        thread.append(
            {
                "id": self._next_comment,
                "user": {"login": "vulgard[bot]"},
                "body": body,
                "created_at": self.now.isoformat(),
                "html_url": f"https://github.com/{org}/{repo}/issues/{number}"
                f"#issuecomment-{self._next_comment}",
            }
        )

    def create_branch(self, org: str, repo: str, branch: str, sha: str) -> None:
        self._record("create_branch", repo, branch)

    def update_branch(self, org: str, repo: str, branch: str, sha: str, *, force: bool) -> None:
        self._record("update_branch", repo, branch, sha, force)

    def merge_pull_request(
        self, org: str, repo: str, number: int, merge_method: str = "squash"
    ) -> None:
        self._record("merge_pull_request", repo, number, merge_method)

    def put_file(
        self, org: str, repo: str, path: str, content: str, message: str, branch: str
    ) -> None:
        self._record("put_file", repo, path, content)

    def create_pr(
        self, org: str, repo: str, title: str, body: str, head: str, base: str
    ) -> dict[str, Any]:
        self._record("create_pr", repo, title)
        return {"html_url": f"https://github.com/{org}/{repo}/pull/1"}

    def enable_security_features(self, org: str, repo: str, allow_auto_merge: bool) -> None:
        self._record("enable_security_features", repo, allow_auto_merge)

    def create_org_ruleset(self, org: str, ruleset: dict[str, Any]) -> dict[str, Any]:
        self._record("create_org_ruleset", ruleset)
        return {"id": 1}

    def update_org_ruleset(self, org: str, ruleset_id: int, ruleset: dict[str, Any]) -> None:
        self._record("update_org_ruleset", ruleset_id, ruleset)


STATE_TYPES = {
    "triage": "triage",
    "todo": "unstarted",
    "doing": "started",
    "done": "completed",
    "wontdo": "canceled",
}


class FakeLinear:
    """In-memory Linear: every team key and project exists, with Triage/Todo/…/Won't-do states."""

    def __init__(self) -> None:
        self.issues: dict[str, dict[str, Any]] = {}
        self.writes: list[tuple[str, tuple[Any, ...]]] = []

    def team(self, key: str) -> dict[str, Any]:
        return {
            "id": f"team-{key}",
            "key": key,
            "states": [
                {"id": f"{key}:{name}", "name": name.title(), "type": kind, "position": i}
                for i, (name, kind) in enumerate(STATE_TYPES.items())
            ],
        }

    def user_id(self, email: str) -> str:
        return f"user:{email}"

    def label_id(self, name: str, team_id: str) -> str:
        return f"label:{name}"

    def project_id(self, name: str) -> str:
        return f"project:{name}"

    def get_issue(self, issue_id: str) -> dict[str, Any] | None:
        return self.issues.get(issue_id)

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        key = fields["teamId"].removeprefix("team-")
        number = len(self.issues) + 1
        issue = {
            "id": f"lin-{number}",
            "identifier": f"{key}-{number}",
            "url": f"https://linear.app/acme/issue/{key}-{number}",
            "title": fields["title"],
            "description": fields.get("description"),
            "parent": {"id": fields["parentId"]} if fields.get("parentId") else None,
            "state": {"type": STATE_TYPES[fields.get("stateId", ":todo").split(":", 1)[1]]},
            "team": {"key": key},
            "labels": {"nodes": [{"id": i} for i in fields.get("labelIds", [])]},
            "fields": dict(fields),
        }
        self.issues[issue["id"]] = issue
        self.writes.append(("create_issue", (issue["identifier"], fields)))
        return issue

    def update_issue(self, issue_id: str, fields: dict[str, Any]) -> None:
        issue = self.issues[issue_id]
        issue["fields"].update(fields)
        if "description" in fields:
            issue["description"] = fields["description"]
        if "parentId" in fields:
            issue["parent"] = {"id": fields["parentId"]}
        if "stateId" in fields:
            issue["state"] = {"type": STATE_TYPES[fields["stateId"].split(":", 1)[1]]}
        labels = [n["id"] for n in issue["labels"]["nodes"]]
        labels = [i for i in labels if i not in fields.get("removedLabelIds", [])]
        labels += [i for i in fields.get("addedLabelIds", []) if i not in labels]
        issue["labels"] = {"nodes": [{"id": i} for i in labels]}
        self.writes.append(("update_issue", (issue_id, fields)))

    def comment(self, issue_id: str, body: str) -> None:
        self.writes.append(("comment", (issue_id, body)))

    def attach_url(self, issue_id: str, url: str, title: str) -> None:
        self.writes.append(("attach_url", (issue_id, url)))

    def find_issue(self, team_key: str, title: str) -> dict[str, Any] | None:
        for issue in self.issues.values():
            if issue["team"]["key"] == team_key and issue["title"] == title:
                return issue
        return None

    def sub_issues(self, issue_id: str) -> list[dict[str, Any]]:
        return [i for i in self.issues.values() if (i.get("parent") or {}).get("id") == issue_id]


class FixtureScanner:
    """Replays raw AWS and Vercel API shapes from the fixture through the real parsers."""

    def __init__(self, data: dict[str, Any]):
        self._aws = data.get("aws") or {}
        self._vercel = data.get("vercel") or {}

    def scan(self) -> list[Sighting]:
        account, region = self._aws.get("account", "000000000000"), "us-east-1"
        found = [
            s for st in self._aws.get("stacks", []) if (s := sight_cfn_stack(st, account, region))
        ]
        sst = self._aws.get("sst")
        if sst:
            found += sight_sst_objects(sst["objects"], sst["bucket"], account, region)
        for entry in self._aws.get("amplify", []):
            for b in entry["branches"]:
                found.append(sight_amplify_branch(entry["app"], b, b.get("job"), account, region))
        team = self._vercel.get("team_id", "team_demo")
        found += [
            s for p in self._vercel.get("projects", []) if (s := sight_vercel_project(p, team))
        ]
        return found


class FixtureInspector:
    """Replays raw ListFindings shapes from the fixture through the real parser."""

    def __init__(self, data: dict[str, Any]):
        self._raw = ((data.get("aws") or {}).get("inspector") or {}).get("findings", [])

    def findings(self) -> list[Finding]:
        return [finding for raw in self._raw if (finding := sight_finding(raw))]


class FakeSlack:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []
        self.blocks: list[list[dict[str, Any]]] = []

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> None:
        self.messages.append((channel, text))
        self.blocks.append(blocks or [])


class FixtureExecutor:
    """Records the ops it is asked to start. `data["ops"]` maps the request ids of ops that
    already exist to a link, or to `{"url", "state", "why"}` for one that ended. `observe`
    re-reads targets from the same estate the scanner replays."""

    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.started: list[tuple[Verb, Deployment, str]] = []

    def observe(self, native: NativeRef) -> Sighting | None:
        return next((s for s in FixtureScanner(self.data).scan() if s.native == native), None)

    def find(self, op: Op) -> Found | None:
        existing = self.data.get("ops", {}).get(op.request_id)
        if existing is None:
            return None
        if isinstance(existing, str):
            return Found(existing)
        return Found(existing["url"], RunState(existing["state"]), existing.get("why", ""))

    def redeploy(self, d: Deployment, request_id: str) -> str:
        return self._start(Verb.REDEPLOY, d, request_id)

    def delete(self, proof: SafeDelete, request_id: str) -> str:
        return self._start(Verb.DELETE, proof.deployment, request_id)

    def _start(self, verb: Verb, d: Deployment, request_id: str) -> str:
        self.started.append((verb, d, request_id))
        url = f"https://example.test/ops/{request_id}"
        self.data.setdefault("ops", {})[request_id] = url
        return url


def fixture_clients(path: str | Path) -> Clients:
    gh = FixtureGitHub.from_file(path)
    kev = frozenset(gh.data.get("kev", []))
    executor = FixtureExecutor(gh.data)
    return Clients(
        github=gh,
        linear=FakeLinear(),
        slack=FakeSlack(),
        slack_webhook=None,
        kev=lambda: kev,
        scanners=lambda: [FixtureScanner(gh.data)],
        executor=lambda: executor,
        inspector=lambda: FixtureInspector(gh.data),
    )
