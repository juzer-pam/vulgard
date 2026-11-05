from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, assert_never

import httpx

from .config import Config, LinearTarget
from .plan import Action, ActionKind, IssueOp, LinearContent, LinearRef, RepoPlan

API_URL = "https://api.linear.app/graphql"
PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4}  # Linear: 1 urgent … 4 low
CLOSED_STATES = ("completed", "canceled")

ISSUE_FIELDS = (
    "id identifier url title state { type } team { key } labels { nodes { id } } "
    "attachments { nodes { url title } }"
)


class LinearError(RuntimeError):
    pass


@dataclass(frozen=True)
class LinearIssue:
    identifier: str
    title: str
    url: str


class LinearClient(Protocol):
    def team(self, key: str) -> dict[str, Any]: ...
    def user_id(self, email: str) -> str | None: ...
    def label_id(self, name: str, team_id: str) -> str: ...
    def project_id(self, name: str) -> str: ...
    def get_issue(self, issue_id: str) -> dict[str, Any] | None: ...
    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]: ...
    def update_issue(self, issue_id: str, fields: dict[str, Any]) -> None: ...
    def comment(self, issue_id: str, body: str) -> None: ...
    def attach_url(self, issue_id: str, url: str, title: str) -> None: ...
    def find_issue(self, team_key: str, title: str) -> dict[str, Any] | None: ...
    def open_issues_with_labels(self, labels: list[str]) -> list[LinearIssue]: ...


class Linear:
    def __init__(self, api_key: str, url: str = API_URL):
        self._url = url
        self._http = httpx.Client(
            headers={"Authorization": api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )
        self._teams: dict[str, dict[str, Any]] = {}
        self._labels: dict[tuple[str, str], str] = {}
        self._projects: dict[str, str] = {}
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
                "{ nodes { id key states { nodes { id name type position } } } } }",
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

    def label_id(self, name: str, team_id: str) -> str:
        """The team's label with this name, else the workspace label, created if missing."""
        key = (name.lower(), team_id)
        if key not in self._labels:
            data = self._gql(
                "query($name: String!, $team: ID!) { issueLabels(filter: "
                "{ name: { eqIgnoreCase: $name }, "
                "or: [{ team: { null: true } }, { team: { id: { eq: $team } } }] }) "
                "{ nodes { id team { id } } } }",
                {"name": name, "team": team_id},
            )
            nodes = sorted(data["issueLabels"]["nodes"], key=lambda n: n["team"] is None)
            if nodes:
                self._labels[key] = nodes[0]["id"]
            else:
                created = self._gql(
                    "mutation($name: String!) { issueLabelCreate(input: "
                    '{ name: $name, color: "#b60205" }) { issueLabel { id } } }',
                    {"name": name},
                )
                self._labels[key] = created["issueLabelCreate"]["issueLabel"]["id"]
        return self._labels[key]

    def project_id(self, name: str) -> str:
        if name not in self._projects:
            data = self._gql(
                "query($name: String!) { projects(filter: { name: { eqIgnoreCase: $name } }) "
                "{ nodes { id } } }",
                {"name": name},
            )
            nodes = data["projects"]["nodes"]
            if not nodes:
                raise LinearError(f"Linear project '{name}' not found")
            self._projects[name] = nodes[0]["id"]
        return self._projects[name]

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

    def find_issue(self, team_key: str, title: str) -> dict[str, Any] | None:
        team_id = self.team(team_key)["id"]
        data = self._gql(
            "query($team: ID!, $title: String!) { issues("
            "filter: { team: { id: { eq: $team } }, title: { eq: $title } }, first: 1) "
            f"{{ nodes {{ {ISSUE_FIELDS} }} }} }}",
            {"team": team_id, "title": title},
        )
        nodes = data["issues"]["nodes"]
        return nodes[0] if nodes else None

    def open_issues_with_labels(self, labels: list[str]) -> list[LinearIssue]:
        """Issues not completed or canceled that carry any of these label names."""
        issues: list[LinearIssue] = []
        after: str | None = None
        while True:
            data = self._gql(
                "query($labels: [String!]!, $closed: [String!]!, $after: String) { issues("
                "filter: { labels: { some: { name: { in: $labels } } }, "
                "state: { type: { nin: $closed } } }, first: 100, after: $after) "
                "{ nodes { identifier title url } pageInfo { hasNextPage endCursor } } }",
                {"labels": labels, "closed": list(CLOSED_STATES), "after": after},
            )
            page = data["issues"]
            issues += [LinearIssue(n["identifier"], n["title"], n["url"]) for n in page["nodes"]]
            if not page["pageInfo"]["hasNextPage"]:
                return issues
            after = page["pageInfo"]["endCursor"]


def state_id(team: dict[str, Any], state_type: str) -> str:
    states = sorted(
        (s for s in team["states"] if s["type"] == state_type), key=lambda s: s["position"]
    )
    if not states:
        raise LinearError(f"Linear team {team['key']} has no '{state_type}' workflow state")
    return states[0]["id"]


def state_named(team: dict[str, Any], name: str) -> str:
    for s in team["states"]:
        if s["name"].lower() == name.lower():
            return s["id"]
    names = ", ".join(s["name"] for s in team["states"])
    raise LinearError(f"Linear team {team['key']} has no '{name}' state (has: {names})")


def _open_state(team: dict[str, Any], target: LinearTarget) -> str:
    return state_named(team, target.state) if target.state else state_id(team, "unstarted")


def _target(config: Config, plan: RepoPlan[Any]) -> LinearTarget | None:
    target = config.linear.target(plan.repo, plan.owners)
    return plan.spec.linear.apply(target) if target is not None else None


def _issue_target(config: Config, plan: RepoPlan[Any], team_key: str) -> LinearTarget:
    """Settings for an existing issue: its route if that still points at the issue's team."""
    target = _target(config, plan)
    if target is not None and target.team == team_key:
        return target
    linear = config.linear
    fallback = LinearTarget(
        team_key, tuple(linear.labels), None, linear.state, linear.severity_labels
    )
    return plan.spec.linear.apply(fallback)


def _severity_label_changes(
    client: LinearClient,
    target: LinearTarget,
    team_id: str,
    worst: str | None,
    current: set[str],
) -> dict[str, list[str]]:
    """Swap the severity label so only the worst open severity's label is on the issue."""
    if not target.severity_labels:
        return {}
    ids = {name: client.label_id(name, team_id) for name in set(target.severity_labels.values())}
    want = ids.get(target.severity_labels.get(worst, "")) if worst else None
    changes: dict[str, list[str]] = {}
    if want and want not in current:
        changes["addedLabelIds"] = [want]
    removed = sorted(i for i in ids.values() if i != want and i in current)
    if removed:
        changes["removedLabelIds"] = removed
    return changes


def _digest(fields: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:12]


@dataclass
class LinearResult:
    ref: LinearRef | None
    actions: list[Action] = field(default_factory=list)
    created: bool = False


def _owned_issue(
    client: LinearClient, plan: RepoPlan[Any]
) -> tuple[LinearRef, dict[str, Any]] | None:
    """The tracked Linear issue, if it still exists and belongs to this repo and topic.

    The ref comes from the GitHub issue body, which anyone with write access can edit, so a
    ref pointing at an unrelated issue is ignored instead of overwritten.
    """
    ref = plan.state.linear
    if ref is None:
        return None
    issue = client.get_issue(ref.id)
    if issue is None or issue["title"] != f"{plan.repo}: {plan.spec.title}":
        return None
    return ref, issue


def _close(client: LinearClient, plan: RepoPlan[Any], apply: bool) -> LinearResult:
    owned = _owned_issue(client, plan)
    if owned is None:
        return LinearResult(plan.state.linear)
    ref, issue = owned
    if issue["state"]["type"] in CLOSED_STATES:
        return LinearResult(ref)
    if apply:
        client.comment(ref.id, plan.spec.linear_closed)
        done = state_id(client.team(issue["team"]["key"]), "completed")
        client.update_issue(ref.id, {"stateId": done})
    return LinearResult(ref, [Action(plan.repo, ActionKind.LINEAR_CLOSE, ref.identifier)])


def _assignee_id(
    client: LinearClient, config: Config, owners: list[str], team: str
) -> str | None:
    linear = config.linear
    for email in [*(linear.users.get(owner) for owner in owners), linear.leads.get(team)]:
        if email:
            user = client.user_id(email)
            if user:
                return user
    return None


def _create(
    client: LinearClient,
    config: Config,
    plan: RepoPlan[Any],
    content: LinearContent,
    apply: bool,
) -> LinearResult:
    repo = plan.repo
    target = _target(config, plan)
    if target is None:
        skip = Action(repo, ActionKind.LINEAR_SKIP, "no team mapped; set linear.default_team")
        return LinearResult(None, [skip])
    if not apply:
        project = f", project {target.project}" if target.project else ""
        detail = f"in team {target.team}{project}"
        return LinearResult(None, [Action(repo, ActionKind.LINEAR_CREATE, detail)])
    team = client.team(target.team)
    labels = list(target.labels)
    worst = content.worst_severity
    if worst in target.severity_labels:
        labels.append(target.severity_labels[worst])
    payload = {
        **content.fields,
        "teamId": team["id"],
        "labelIds": [client.label_id(name, team["id"]) for name in labels],
    }
    if target.project:
        payload["projectId"] = client.project_id(target.project)
    if target.state:
        payload["stateId"] = state_named(team, target.state)
    assignee = _assignee_id(client, config, plan.owners, target.team)
    if assignee:
        payload["assigneeId"] = assignee
    created = client.create_issue(payload)
    ref = LinearRef(created["id"], created["identifier"], created["url"], _digest(content.fields))
    if plan.escalation:
        client.comment(ref.id, plan.escalation.linear_md)
    return LinearResult(ref, [Action(repo, ActionKind.LINEAR_CREATE, ref.identifier)], True)


def _update(
    client: LinearClient,
    config: Config,
    plan: RepoPlan[Any],
    content: LinearContent,
    ref: LinearRef,
    issue: dict[str, Any],
    apply: bool,
) -> LinearResult:
    digest = _digest(content.fields)
    reopened = issue["state"]["type"] in CLOSED_STATES
    changed = digest != ref.digest
    comments = [content.reopened] if reopened else []
    comments += content.news
    if plan.escalation:
        comments.append(plan.escalation.linear_md)
    if not (changed or reopened or comments):
        return LinearResult(ref)
    action = Action(
        plan.repo, ActionKind.LINEAR_UPDATE, ref.identifier + (" (reopened)" if reopened else "")
    )
    if not apply:
        return LinearResult(ref, [action])
    if changed or reopened:
        update: dict[str, Any] = dict(content.fields)
        team_key = issue["team"]["key"]
        team = client.team(team_key)
        target = _issue_target(config, plan, team_key)
        if reopened:
            update["stateId"] = _open_state(team, target)
        current = {n["id"] for n in (issue.get("labels") or {}).get("nodes", [])}
        update |= _severity_label_changes(
            client, target, team["id"], content.worst_severity, current
        )
        client.update_issue(ref.id, update)
    for comment in comments:
        client.comment(ref.id, comment)
    return LinearResult(LinearRef(ref.id, ref.identifier, ref.url, digest), [action])


def sync_linear(
    client: LinearClient, config: Config, plan: RepoPlan[Any], apply: bool
) -> LinearResult:
    match plan.op:
        case IssueOp.NONE:
            return LinearResult(plan.state.linear)
        case IssueOp.CLOSE:
            return _close(client, plan, apply)
        case IssueOp.CREATE | IssueOp.REOPEN | IssueOp.UPDATE:
            assert plan.linear is not None
            owned = _owned_issue(client, plan)
            if owned is None:
                return _create(client, config, plan, plan.linear, apply)
            return _update(client, config, plan, plan.linear, *owned, apply)
        case _ as unreachable:
            assert_never(unreachable)
