"""One Linear onboarding issue per team, with rollout PRs attached, plus Slack DMs to team leads."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from .config import Config
from .linear import LinearClient, LinearError, _assignee_id, state_id, state_named
from .plan import Action, ActionKind
from .slack import RolloutPR

ONBOARDING_TITLE = "vulgard onboarding: approve rollout PRs"

ONBOARDING_BODY = """\
Vulgard opened PRs on branch `vulgard/rollout` that add Dependabot and the dependency check workflow.

**Team lead:** review and approve each linked PR (or ask the repo owners to merge).

After these merge, the org ruleset step can make the vulgard check required.
"""


def group_rollout_prs_by_team(config: Config, prs: list[RolloutPR]) -> dict[str, list[RolloutPR]]:
    by_team: dict[str, list[RolloutPR]] = defaultdict(list)
    default = config.linear.default_team
    for pr in prs:
        target = config.linear.target(pr.repo, pr.owners)
        team = target.team if target else default
        if team:
            by_team[team].append(pr)
    return dict(by_team)


def onboarding_description(linked: list[RolloutPR]) -> str:
    lines = [ONBOARDING_BODY, "", "## Rollout PRs", ""]
    for pr in sorted(linked, key=lambda p: p.repo.lower()):
        lines.append(f"- [{pr.repo}]({pr.url})")
    return "\n".join(lines)


def _issue_attachments(client: LinearClient, issue_id: str) -> set[str]:
    issue = client.get_issue(issue_id)
    if issue is None:
        return set()
    nodes = (issue.get("attachments") or {}).get("nodes") or []
    return {n["url"] for n in nodes if n.get("url")}


def _find_onboarding(client: LinearClient, team_key: str) -> dict[str, Any] | None:
    return client.find_issue(team_key, ONBOARDING_TITLE)


def sync_rollout_onboarding(
    client: LinearClient, config: Config, prs: list[RolloutPR], apply: bool
) -> tuple[dict[str, str], list[Action]]:
    """Creates or refreshes one onboarding issue per team and returns team key -> issue URL."""
    actions: list[Action] = []
    tickets: dict[str, str] = {}
    linear = config.linear
    for team, team_prs in sorted(group_rollout_prs_by_team(config, prs).items()):
        linked = [p for p in team_prs if p.url]
        if not linked:
            continue
        if not apply:
            actions.append(
                Action(None, ActionKind.LINEAR_CREATE, f"team {team}: {len(linked)} rollout PR(s)")
            )
            continue
        try:
            team_obj = client.team(team)
            existing = _find_onboarding(client, team)
            if existing is None:
                payload: dict[str, Any] = {
                    "teamId": team_obj["id"],
                    "title": ONBOARDING_TITLE,
                    "description": onboarding_description(linked),
                    "labelIds": [client.label_id(name, team_obj["id"]) for name in linear.labels],
                }
                if linear.state:
                    payload["stateId"] = state_named(team_obj, linear.state)
                assignee = _assignee_id(client, config, [], team)
                if assignee:
                    payload["assigneeId"] = assignee
                created = client.create_issue(payload)
                issue_id = created["id"]
                identifier = created["identifier"]
                url = created["url"]
                actions.append(Action(None, ActionKind.LINEAR_CREATE, identifier))
            else:
                issue_id = existing["id"]
                identifier = existing["identifier"]
                url = existing["url"]
                client.update_issue(issue_id, {"description": onboarding_description(linked)})
            attached = _issue_attachments(client, issue_id)
            added = 0
            for pr in linked:
                if pr.url in attached:
                    continue
                client.attach_url(issue_id, pr.url, f"{pr.repo} rollout PR")
                added += 1
                time.sleep(0.4)
            if added:
                actions.append(
                    Action(None, ActionKind.LINEAR_UPDATE, f"{identifier}: linked {added} PR(s)")
                )
            tickets[team] = url
        except LinearError as e:
            actions.append(Action(None, ActionKind.LINEAR_ERROR, f"team {team}: {e}"))
    return tickets, actions


def collect_open_rollout_prs(gh: Any, config: Config, prs: list[RolloutPR]) -> list[RolloutPR]:
    """Every open rollout PR in selected repos, for onboarding and lead DMs after a rollout run."""
    from .repos import resolve_owners, selected_repos

    own = config.rollout.workflow_repo
    seen = {p.repo: p for p in prs if p.url}
    for repo in selected_repos(gh, config):
        name = repo["name"]
        if name == own:
            continue
        open_pr = gh.find_open_pr(config.org, name, config.rollout.branch)
        if open_pr and name not in seen:
            seen[name] = RolloutPR(
                name, resolve_owners(gh, config, name), open_pr["html_url"]
            )
    return list(seen.values())
