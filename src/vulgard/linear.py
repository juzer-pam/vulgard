from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, assert_never

import httpx

from .config import SEVERITIES, Config, route
from .plan import Action, ActionKind, IssueOp, LinearRef, RepoPlan
from .policy import RepoReport, SlaStatus
from .render import (
    alert_sections,
    escalation_md,
    newly_overdue_md,
    newly_ready_md,
    pr_sections,
    severity_summary,
)

API_URL = "https://api.linear.app/graphql"
PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4}  # Linear: 1 urgent … 4 low
CLOSED_STATES = ("completed", "canceled")

ISSUE_FIELDS = "id identifier url title state { type } team { key }"


class LinearError(RuntimeError):
    pass


class LinearClient(Protocol):
    def team(self, key: str) -> dict[str, Any]: ...
    def user_id(self, email: str) -> str | None: ...
    def label_id(self, name: str) -> str: ...
    def get_issue(self, issue_id: str) -> dict[str, Any] | None: ...
    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]: ...
    def update_issue(self, issue_id: str, fields: dict[str, Any]) -> None: ...
    def comment(self, issue_id: str, body: str) -> None: ...
    def attach_url(self, issue_id: str, url: str, title: str) -> None: ...


class Linear:
    def __init__(self, api_key: str, url: str = API_URL):
        self._url = url
        self._http = httpx.Client(
            headers={"Authorization": api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )
        self._teams: dict[str, dict[str, Any]] = {}
        self._labels: dict[str, str] = {}
        self._users: dict[str, str | None] = {}

    def _gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._http.post(self._url, json={"query": query, "variables": variables or {}})
        try:
            data = resp.json()
        except ValueError as e:
            raise LinearError(f"Linear API {resp.status_code}: {resp.text[:200]}") from e
        if resp.status_code >= 400 or data.get("errors"):
            messages = "; ".join(e.get("message", "") for e in data.get("errors") or [])
            raise LinearError(f"Linear API {resp.status_code}: {messages or resp.text[:200]}")
        return data["data"]

    def team(self, key: str) -> dict[str, Any]:
        if key not in self._teams:
            data = self._gql(
                "query($key: String!) { teams(filter: { key: { eq: $key } }) "
                "{ nodes { id key states { nodes { id type position } } } } }",
                {"key": key},
            )
            nodes = data["teams"]["nodes"]
            if not nodes:
                raise LinearError(f"Linear team '{key}' not found")
            team = nodes[0]
            team["states"] = team["states"]["nodes"]
            self._teams[key] = team
        return self._teams[key]

    def user_id(self, email: str) -> str | None:
        if email not in self._users:
            data = self._gql(
                "query($email: String!) { users(filter: { email: { eq: $email } }) "
                "{ nodes { id } } }",
                {"email": email},
            )
            nodes = data["users"]["nodes"]
            self._users[email] = nodes[0]["id"] if nodes else None
        return self._users[email]

    def label_id(self, name: str) -> str:
        if name not in self._labels:
            data = self._gql(
                "query($name: String!) { issueLabels(filter: "
                "{ name: { eq: $name }, team: { null: true } }) { nodes { id } } }",
                {"name": name},
            )
            nodes = data["issueLabels"]["nodes"]
            if nodes:
                self._labels[name] = nodes[0]["id"]
            else:
                created = self._gql(
                    "mutation($name: String!) { issueLabelCreate(input: "
                    '{ name: $name, color: "#b60205" }) { issueLabel { id } } }',
                    {"name": name},
                )
                self._labels[name] = created["issueLabelCreate"]["issueLabel"]["id"]
        return self._labels[name]

    def get_issue(self, issue_id: str) -> dict[str, Any] | None:
        try:
            data = self._gql(
                f"query($id: String!) {{ issue(id: $id) {{ {ISSUE_FIELDS} }} }}",
                {"id": issue_id},
            )
        except LinearError as e:
            if "not found" in str(e).lower():
                return None
            raise
        return data["issue"]

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        data = self._gql(
            "mutation($input: IssueCreateInput!) { issueCreate(input: $input) "
            f"{{ issue {{ {ISSUE_FIELDS} }} }} }}",
            {"input": fields},
        )
        return data["issueCreate"]["issue"]

    def update_issue(self, issue_id: str, fields: dict[str, Any]) -> None:
        self._gql(
            "mutation($id: String!, $input: IssueUpdateInput!) "
            "{ issueUpdate(id: $id, input: $input) { success } }",
            {"id": issue_id, "input": fields},
        )

    def comment(self, issue_id: str, body: str) -> None:
        self._gql(
            "mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success } }",
            {"input": {"issueId": issue_id, "body": body}},
        )

    def attach_url(self, issue_id: str, url: str, title: str) -> None:
        self._gql(
            "mutation($input: AttachmentCreateInput!) "
            "{ attachmentCreate(input: $input) { success } }",
            {"input": {"issueId": issue_id, "url": url, "title": title}},
        )


def state_id(team: dict[str, Any], state_type: str) -> str:
    states = sorted(
        (s for s in team["states"] if s["type"] == state_type), key=lambda s: s["position"]
    )
    if not states:
        raise LinearError(f"Linear team {team['key']} has no '{state_type}' workflow state")
    return states[0]["id"]


def issue_title(repo: str, config: Config) -> str:
    return f"{repo}: {config.issue.title}"


def render_description(report: RepoReport) -> str:
    n = len(report.alerts)
    lines = [
        f"**{report.repo}** has {n} open vulnerable dependenc{'y' if n == 1 else 'ies'}: "
        f"{severity_summary(report.severity_counts())}.",
        *alert_sections(report, relative=False),
        *pr_sections(report, relative=False),
        "",
        "---",
        "_Synced by vulgard from GitHub. The description, priority, and due date are "
        "overwritten on each run, and the issue closes itself once every alert is resolved._",
    ]
    return "\n".join(lines)


def issue_fields(report: RepoReport, config: Config) -> dict[str, Any]:
    counts = report.severity_counts()
    worst = next((s for s in SEVERITIES if counts[s]), "low")
    urgent = any(
        a.known_exploited or (a.severity == "critical" and a.status == SlaStatus.OVERDUE)
        for a in report.alerts
    )
    fields: dict[str, Any] = {
        "title": issue_title(report.repo, config),
        "description": render_description(report),
        "priority": 1 if urgent else PRIORITY[worst],
    }
    deadlines = [a.deadline for a in report.alerts if a.deadline]
    if deadlines:
        fields["dueDate"] = min(deadlines).date().isoformat()
    return fields


def _digest(fields: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:12]


@dataclass
class LinearResult:
    ref: LinearRef | None
    actions: list[Action] = field(default_factory=list)
    created: bool = False


def _owned_issue(
    client: LinearClient, plan: RepoPlan
) -> tuple[LinearRef, dict[str, Any]] | None:
    """The tracked Linear issue, if it still exists and belongs to this repo.

    The ref comes from the GitHub issue body, which anyone with write access can edit, so a
    ref pointing at an unrelated issue is ignored instead of overwritten.
    """
    ref = plan.state.linear
    if ref is None:
        return None
    issue = client.get_issue(ref.id)
    if issue is None or not issue["title"].startswith(f"{plan.repo}: "):
        return None
    return ref, issue


def _close(client: LinearClient, plan: RepoPlan, apply: bool) -> LinearResult:
    owned = _owned_issue(client, plan)
    if owned is None:
        return LinearResult(plan.state.linear)
    ref, issue = owned
    if issue["state"]["type"] in CLOSED_STATES:
        return LinearResult(ref)
    if apply:
        client.comment(ref.id, "✅ All Dependabot alerts are resolved. Closing.")
        done = state_id(client.team(issue["team"]["key"]), "completed")
        client.update_issue(ref.id, {"stateId": done})
    return LinearResult(ref, [Action(plan.repo, ActionKind.LINEAR_CLOSE, ref.identifier)])


def _assignee_id(client: LinearClient, config: Config, owners: list[str]) -> str | None:
    for owner in owners:
        email = config.linear.users.get(owner)
        if email:
            user = client.user_id(email)
            if user:
                return user
    return None


def _create(
    client: LinearClient, config: Config, plan: RepoPlan, fields: dict[str, Any], apply: bool
) -> LinearResult:
    repo = plan.repo
    team_key = route(config.linear.teams, repo, plan.report.owners, config.linear.default_team)
    if not team_key:
        skip = Action(repo, ActionKind.LINEAR_SKIP, "no team mapped; set linear.default_team")
        return LinearResult(None, [skip])
    if not apply:
        return LinearResult(None, [Action(repo, ActionKind.LINEAR_CREATE, f"in team {team_key}")])
    payload = {
        **fields,
        "teamId": client.team(team_key)["id"],
        "labelIds": [client.label_id(config.linear.label)],
    }
    assignee = _assignee_id(client, config, plan.report.owners)
    if assignee:
        payload["assigneeId"] = assignee
    created = client.create_issue(payload)
    ref = LinearRef(created["id"], created["identifier"], created["url"], _digest(fields))
    if plan.escalate:
        client.comment(ref.id, escalation_md(plan.escalate, config.escalation, relative=False))
    return LinearResult(ref, [Action(repo, ActionKind.LINEAR_CREATE, ref.identifier)], True)


def _update_comments(plan: RepoPlan, config: Config, reopened: bool) -> list[str]:
    comments = []
    if reopened:
        comments.append(
            f"Reopened by vulgard: {len(plan.report.alerts)} alert(s) are still open in GitHub. "
            "This issue closes itself once they're fixed. To accept a risk instead, dismiss the "
            "alert in GitHub with a reason or add an exception with an expiry date to vulgard.yml."
        )
    if plan.newly_overdue:
        comments.append(newly_overdue_md(plan.newly_overdue, relative=False))
    if plan.newly_ready:
        comments.append(newly_ready_md(plan.newly_ready, relative=False))
    if plan.escalate:
        comments.append(escalation_md(plan.escalate, config.escalation, relative=False))
    return comments


def _update(
    client: LinearClient,
    config: Config,
    plan: RepoPlan,
    fields: dict[str, Any],
    ref: LinearRef,
    issue: dict[str, Any],
    apply: bool,
) -> LinearResult:
    digest = _digest(fields)
    reopened = issue["state"]["type"] in CLOSED_STATES
    changed = digest != ref.digest
    comments = _update_comments(plan, config, reopened)
    if not (changed or reopened or comments):
        return LinearResult(ref)
    action = Action(
        plan.repo, ActionKind.LINEAR_UPDATE, ref.identifier + (" (reopened)" if reopened else "")
    )
    if not apply:
        return LinearResult(ref, [action])
    if changed or reopened:
        update = dict(fields)
        if reopened:
            update["stateId"] = state_id(client.team(issue["team"]["key"]), "unstarted")
        client.update_issue(ref.id, update)
    for comment in comments:
        client.comment(ref.id, comment)
    return LinearResult(LinearRef(ref.id, ref.identifier, ref.url, digest), [action])


def sync_linear(client: LinearClient, config: Config, plan: RepoPlan, apply: bool) -> LinearResult:
    match plan.op:
        case IssueOp.NONE:
            return LinearResult(plan.state.linear)
        case IssueOp.CLOSE:
            return _close(client, plan, apply)
        case IssueOp.CREATE | IssueOp.UPDATE:
            fields = issue_fields(plan.report, config)
            owned = _owned_issue(client, plan)
            if owned is None:
                return _create(client, config, plan, fields, apply)
            return _update(client, config, plan, fields, *owned, apply)
        case _ as unreachable:
            assert_never(unreachable)
