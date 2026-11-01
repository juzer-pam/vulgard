from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from .config import SEVERITIES, Config, route
from .events import Action, ActionKind, RepoPlan
from .policy import RepoReport, SlaStatus

API_URL = "https://api.linear.app/graphql"
PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4}  # Linear: 1 urgent … 4 low
CLOSED_STATES = ("completed", "canceled")

ISSUE_FIELDS = "id identifier url state { type } team { key }"


class LinearError(RuntimeError):
    pass


class Linear:
    def __init__(self, api_key: str, url: str = API_URL):
        self._url = url
        self._http = httpx.Client(
            headers={"Authorization": api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )
        self._teams: dict[str, dict[str, Any] | None] = {}
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

    def team(self, key: str) -> dict[str, Any] | None:
        if key not in self._teams:
            data = self._gql(
                "query($key: String!) { teams(filter: { key: { eq: $key } }) "
                "{ nodes { id key states { nodes { id type position } } } } }",
                {"key": key},
            )
            nodes = data["teams"]["nodes"]
            if nodes:
                team = nodes[0]
                team["states"] = team["states"]["nodes"]
                self._teams[key] = team
            else:
                self._teams[key] = None
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


def render_description(report: RepoReport, config: Config, issue_url: str | None) -> str:
    counts = report.severity_counts()
    lines = [
        f"**{report.repo}** has {len(report.alerts)} open vulnerable dependenc"
        f"{'y' if len(report.alerts) == 1 else 'ies'}: "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
        + ".",
    ]
    if issue_url:
        lines += ["", f"GitHub tracking issue: {issue_url}"]
    for title, alerts in (
        ("🚨 Overdue", report.overdue),
        ("⏳ Due soon", report.due_soon),
        ("Within SLA", report.by_status(SlaStatus.OK)),
    ):
        if alerts:
            lines += ["", f"### {title} ({len(alerts)})", *[a.markdown_line() for a in alerts]]
    ready = report.ready_prs(config.ready_pr_days)
    if ready:
        lines += ["", f"### ✅ Ready to merge ({len(ready)})"]
        lines += [p.markdown_line(config.stale_pr_days) for p in ready]
    stale = [p for p in report.stale_prs(config.stale_pr_days) if p not in ready]
    if stale:
        lines += ["", f"### Dependabot PRs open {config.stale_pr_days}+ days ({len(stale)})"]
        lines += [p.markdown_line(config.stale_pr_days) for p in stale]
    lines += [
        "",
        "---",
        "_Synced by vulgard from GitHub. The description, priority, and due date are "
        "overwritten on each run, and the issue closes itself once every alert is resolved._",
    ]
    return "\n".join(lines)


def issue_fields(report: RepoReport, config: Config, issue_url: str | None) -> dict[str, Any]:
    counts = report.severity_counts()
    worst = next((s for s in SEVERITIES if counts[s]), "low")
    urgent = any(
        a.known_exploited or (a.severity == "critical" and a.status == SlaStatus.OVERDUE)
        for a in report.alerts
    )
    fields: dict[str, Any] = {
        "title": f"{report.repo}: {config.issue.title}",
        "description": render_description(report, config, issue_url),
        "priority": 1 if urgent else PRIORITY[worst],
    }
    deadlines = [a.deadline for a in report.alerts if a.deadline]
    if deadlines:
        fields["dueDate"] = min(deadlines).date().isoformat()
    return fields


def _digest(fields: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:12]


def _assignee_id(client: Any, config: Config, owners: list[str]) -> str | None:
    for owner in owners:
        email = config.linear.users.get(owner)
        if email:
            user = client.user_id(email)
            if user:
                return user
    return None


def _comments(plan: RepoPlan, config: Config, reopened: bool) -> list[str]:
    comments = []
    if reopened:
        comments.append(
            f"Reopened by vulgard: {len(plan.report.alerts)} alert(s) are still open in GitHub. "
            "This issue closes itself once they're fixed. To accept a risk instead, dismiss the "
            "alert in GitHub with a reason or add an exception with an expiry date to vulgard.yml."
        )
    if plan.newly_overdue:
        comments.append(
            f"{len(plan.newly_overdue)} alert(s) just went past their fix deadline:\n\n"
            + "\n".join(a.markdown_line() for a in plan.newly_overdue)
        )
    if plan.newly_ready:
        comments.append(
            f"{len(plan.newly_ready)} Dependabot PR(s) pass CI and only need a review and merge:"
            "\n\n" + "\n".join(p.markdown_line(config.stale_pr_days) for p in plan.newly_ready)
        )
    if plan.escalate:
        comments.append(
            "Escalated to security leads: these alerts are well past their deadline.\n\n"
            + "\n".join(a.markdown_line() for a in plan.escalate)
        )
    return comments


def sync_linear(
    client: Any, config: Config, plan: RepoPlan, apply: bool
) -> tuple[list[Action], dict[str, Any] | None]:
    repo = plan.repo
    ref = plan.state.get("linear")

    if plan.closing:
        if not ref:
            return [], None
        if apply:
            issue = client.get_issue(ref["id"])
            if issue and issue["state"]["type"] not in CLOSED_STATES:
                client.comment(ref["id"], "✅ All Dependabot alerts are resolved. Closing.")
                team = client.team(issue["team"]["key"])
                client.update_issue(ref["id"], {"stateId": state_id(team, "completed")})
        return [Action(repo, ActionKind.LINEAR_CLOSE, ref["identifier"])], ref

    fields = issue_fields(plan.report, config, plan.issue_url)
    digest = _digest(fields)
    existing = client.get_issue(ref["id"]) if ref else None

    if existing is None:
        team_key = route(
            config.linear.teams, repo, plan.report.owners, config.linear.default_team
        )
        if not team_key:
            skip = Action(repo, ActionKind.LINEAR_SKIP, "no team mapped; set linear.default_team")
            return [skip], ref
        if not apply:
            return [Action(repo, ActionKind.LINEAR_CREATE, f"in team {team_key}")], ref
        team = client.team(team_key)
        if team is None:
            raise LinearError(f"Linear team '{team_key}' not found")
        payload = {
            **fields,
            "teamId": team["id"],
            "labelIds": [client.label_id(config.linear.label)],
        }
        assignee = _assignee_id(client, config, plan.report.owners)
        if assignee:
            payload["assigneeId"] = assignee
        created = client.create_issue(payload)
        if plan.issue_url:
            client.attach_url(created["id"], plan.issue_url, f"{repo} tracking issue")
        new_ref = {
            "id": created["id"],
            "identifier": created["identifier"],
            "url": created["url"],
            "digest": digest,
        }
        return [Action(repo, ActionKind.LINEAR_CREATE, created["identifier"])], new_ref

    reopened = existing["state"]["type"] in CLOSED_STATES
    comments = _comments(plan, config, reopened)
    changed = digest != ref.get("digest")
    if not (changed or reopened or comments):
        return [], ref
    detail = ref["identifier"] + (" (reopened)" if reopened else "")
    if not apply:
        return [Action(repo, ActionKind.LINEAR_UPDATE, detail)], ref
    if changed or reopened:
        update = dict(fields)
        if reopened:
            update["stateId"] = state_id(client.team(existing["team"]["key"]), "unstarted")
        client.update_issue(ref["id"], update)
    for comment in comments:
        client.comment(ref["id"], comment)
    return [Action(repo, ActionKind.LINEAR_UPDATE, detail)], {**ref, "digest": digest}
