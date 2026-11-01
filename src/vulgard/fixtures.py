from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .clients import Clients
from .policy import now_utc

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


class FixtureGitHub:
    """In-memory stand-in for the GitHub client, backed by a JSON file. Writes are recorded."""

    def __init__(self, data: dict[str, Any], now: datetime | None = None):
        self.data = _resolve_dates(copy.deepcopy(data), now or now_utc())
        self.writes: list[tuple[str, tuple[Any, ...]]] = []
        self._next_issue = 1000

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

    def list_closed_alerts(self, org: str, since: datetime) -> list[dict[str, Any]]:
        return self.data.get("closed_alerts", [])

    def list_dependabot_prs(self, org: str) -> list[dict[str, Any]]:
        return self.data.get("dependabot_prs", [])

    def get_file(self, org: str, repo: str, path: str) -> str | None:
        return self.data.get("files", {}).get(repo, {}).get(path)

    def list_tree_paths(self, org: str, repo: str, branch: str) -> list[str]:
        return self.data.get("trees", {}).get(repo, [])

    def find_open_issue(self, org: str, repo: str, label: str) -> dict[str, Any] | None:
        issue = self.data.get("issues", {}).get(repo)
        return issue if issue and issue.get("state", "open") == "open" else None

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
        self.data.setdefault("issues", {})[repo] = issue
        self._record("create_issue", repo, title, body)
        return issue

    def update_issue(self, org: str, repo: str, number: int, **fields: Any) -> dict[str, Any]:
        issue = self.data["issues"][repo]
        issue.update(fields)
        self._record("update_issue", repo, number, fields)
        return issue

    def comment_issue(self, org: str, repo: str, number: int, body: str) -> None:
        self._record("comment_issue", repo, number, body)

    def create_branch(self, org: str, repo: str, branch: str, sha: str) -> None:
        self._record("create_branch", repo, branch)

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


STATE_TYPES = {"todo": "unstarted", "doing": "started", "done": "completed", "wontdo": "canceled"}


class FakeLinear:
    """In-memory Linear: every team key exists, with Todo/Doing/Done/Won't-do states."""

    def __init__(self) -> None:
        self.issues: dict[str, dict[str, Any]] = {}
        self.writes: list[tuple[str, tuple[Any, ...]]] = []

    def team(self, key: str) -> dict[str, Any]:
        return {
            "id": f"team-{key}",
            "key": key,
            "states": [
                {"id": f"{key}:{name}", "type": kind, "position": i}
                for i, (name, kind) in enumerate(STATE_TYPES.items())
            ],
        }

    def user_id(self, email: str) -> str:
        return f"user:{email}"

    def label_id(self, name: str) -> str:
        return f"label:{name}"

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
            "state": {"type": "unstarted"},
            "team": {"key": key},
            "fields": dict(fields),
        }
        self.issues[issue["id"]] = issue
        self.writes.append(("create_issue", (issue["identifier"], fields)))
        return issue

    def update_issue(self, issue_id: str, fields: dict[str, Any]) -> None:
        issue = self.issues[issue_id]
        issue["fields"].update(fields)
        if "stateId" in fields:
            issue["state"] = {"type": STATE_TYPES[fields["stateId"].split(":", 1)[1]]}
        self.writes.append(("update_issue", (issue_id, fields)))

    def comment(self, issue_id: str, body: str) -> None:
        self.writes.append(("comment", (issue_id, body)))

    def attach_url(self, issue_id: str, url: str, title: str) -> None:
        self.writes.append(("attach_url", (issue_id, url)))


class FakeSlack:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> None:
        self.messages.append((channel, text))


def fixture_clients(path: str | Path) -> Clients:
    gh = FixtureGitHub.from_file(path)
    kev = frozenset(gh.data.get("kev", []))
    return Clients(
        github=gh, linear=FakeLinear(), slack=FakeSlack(), slack_webhook=None, kev=lambda: kev
    )
