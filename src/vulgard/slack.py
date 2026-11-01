from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Protocol, assert_never

import httpx

from .config import Config, route
from .plan import Action, ActionKind, IssueOp, RepoRun, TopicSpec
from .policy import ClosedSummary, RepoReport, org_totals

API_URL = "https://slack.com/api"
MAX_ROWS = 15
LEADERBOARD_ROWS = 5
MEDALS = ("🥇", "🥈", "🥉")


class SlackError(RuntimeError):
    pass


class SlackClient(Protocol):
    def post(
        self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> None: ...


class Slack:
    """Posts with a bot token (scopes: chat:write, chat:write.public, im:write)."""

    def __init__(self, token: str, base_url: str = API_URL):
        self._http = httpx.Client(
            base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=15.0
        )

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> None:
        payload: dict[str, Any] = {"channel": channel, "text": text, "unfurl_links": False}
        if blocks:
            payload["blocks"] = blocks
        for attempt in range(3):
            resp = self._http.post("/chat.postMessage", json=payload)
            if resp.status_code == 429 and attempt < 2:
                time.sleep(float(resp.headers.get("retry-after", 1)))
                continue
            break
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            raise SlackError(f"chat.postMessage to {channel} failed: {data.get('error')}")


def post_webhook(url: str, text: str, blocks: list[dict[str, Any]] | None = None) -> None:
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    httpx.post(url, json=payload, timeout=15).raise_for_status()


def _post(target: str, detail: str, send: Callable[[], None], apply: bool) -> Action:
    if apply:
        try:
            send()
        except (SlackError, httpx.HTTPError) as e:
            return Action(None, ActionKind.SLACK_ERROR, f"{target}: {e}")
    return Action(None, ActionKind.SLACK, f"{target}: {detail}")


def _repo_link(org: str, repo: str, issue_url: str | None) -> str:
    url = issue_url or f"https://github.com/{org}/{repo}/issues"
    return f"<{url}|{repo}>"


def _owner_mentions(owners: list[str], config: Config) -> str:
    return " ".join(config.slack.mention(o) for o in owners)


def _repo_line(run: RepoRun, config: Config) -> str:
    plan = run.plan
    match plan.op:
        case IssueOp.CREATE:
            parts = ["new tracking issue"]
        case IssueOp.REOPEN:
            parts = ["tracking issue reopened"]
        case IssueOp.UPDATE | IssueOp.CLOSE | IssueOp.NONE:
            parts = []
        case _ as unreachable:
            assert_never(unreachable)
    if plan.digest:
        parts.append(plan.digest)
    owners = _owner_mentions(plan.owners, config)
    line = f"• *{_repo_link(config.org, plan.repo, run.issue_url)}*: {', '.join(parts)}"
    return line + (f" · {owners}" if owners else "")


def _escalation_line(run: RepoRun, config: Config) -> str:
    assert run.plan.escalation is not None
    owners = _owner_mentions(run.plan.owners, config)
    link = _repo_link(config.org, run.repo, run.issue_url)
    detail = run.plan.escalation.slack_detail
    return f"• *{link}*: {detail}" + (f" · owners {owners}" if owners else "")


@dataclass
class _TopicMessages:
    spec: TopicSpec
    channels: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    dms: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    escalations: list[str] = field(default_factory=list)


def notify_slack(
    client: SlackClient, config: Config, runs: list[RepoRun], apply: bool
) -> list[Action]:
    """Per topic: a digest per routed channel, DMs to owners, and the escalation channel."""
    topics: dict[str, _TopicMessages] = {}
    for run in runs:
        plan = run.plan
        if not plan.pinged:
            continue
        msgs = topics.setdefault(plan.spec.topic, _TopicMessages(plan.spec))
        line = _repo_line(run, config)
        channel = route(config.slack.channels, run.repo, plan.owners, config.slack.default_channel)
        if channel:
            msgs.channels[channel].append(line)
        if plan.escalation:
            msgs.escalations.append(_escalation_line(run, config))
        if config.slack.dm_owners:
            for owner in [*plan.owners, *plan.dm]:
                user = config.slack.dm_target(owner)
                if user and line not in msgs.dms[user]:
                    msgs.dms[user].append(line)

    messages: list[tuple[str, str, list[str]]] = []
    for msgs in topics.values():
        spec = msgs.spec
        messages += [(ch, spec.slack_header, lines) for ch, lines in msgs.channels.items()]
        if msgs.escalations and config.slack.escalation_channel:
            leads = "".join(f"{config.slack.mention(m)} " for m in config.escalation.mentions)
            header = leads + spec.escalation_header
            messages.append((config.slack.escalation_channel, header, msgs.escalations))
        messages += [(user, spec.slack_dm_header, lines) for user, lines in msgs.dms.items()]
    return [
        _post(
            target,
            f"{len(lines)} repo(s)",
            partial(client.post, target, header + "\n" + "\n".join(lines)),
            apply,
        )
        for target, header, lines in messages
    ]


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}}


def team_of(report: RepoReport) -> str:
    """The repo's first team owner, else its first owner. Used to group the leaderboard."""
    owners = report.owners
    return next((o for o in owners if "/" in o), owners[0] if owners else "unowned")


def _ranking(title: str, rows: list[str], medals: bool) -> dict[str, Any]:
    lines = [
        f"{MEDALS[i] if medals and i < len(MEDALS) else f'{i + 1}.'} {row}"
        for i, row in enumerate(rows[:LEADERBOARD_ROWS])
    ]
    return _section(f"*{title}*\n" + "\n".join(lines))


def leaderboard_message(
    config: Config, reports: dict[str, RepoReport], closed: ClosedSummary | None
) -> tuple[str, list[dict[str, Any]]]:
    """Weekly org-wide scoreboard for `slack.default_channel`. Names teams without pinging."""
    org = config.org
    ranked = sorted(
        (
            r
            for r in reports.values()
            if r.overdue or r.stale_prs or r.known_exploited or r.ready_prs
        ),
        key=lambda r: -r.risk_score,
    )
    totals = org_totals(reports)
    fixed = closed.fixed if closed is not None else Counter()
    header = (
        f"*🏆 Vulnerability leaderboard for {org}*: {sum(fixed.values())} fixed in the "
        f"last 7 days, {totals.overdue} past deadline, {totals.exploited} actively exploited."
    )
    blocks: list[dict[str, Any]] = [_section(header)]

    fixed_by_team: Counter[str] = Counter()
    for repo, n in fixed.items():
        fixed_by_team[team_of(reports[repo])] += n
    if fixed_by_team:
        rows = [f"{team}: {n}" for team, n in fixed_by_team.most_common()]
        blocks.append(_ranking("Most fixed this week", rows, medals=True))

    overdue_by_team: Counter[str] = Counter()
    exploited_by_team: Counter[str] = Counter()
    for r in reports.values():
        overdue_by_team[team_of(r)] += len(r.overdue)
        exploited_by_team[team_of(r)] += len(r.known_exploited)
    rows = [
        f"{team}: {n} overdue"
        + (f" (🔥 {exploited_by_team[team]} exploited)" if exploited_by_team[team] else "")
        for team, n in (+overdue_by_team).most_common()
    ]
    if rows:
        blocks.append(_ranking("Most overdue", rows, medals=False))

    if totals.ready_prs:
        blocks.append(
            _section(f"*✅ {totals.ready_prs} Dependabot PR(s) pass CI and only need a merge.*")
        )

    if closed is not None:
        if closed.unexplained:
            rows = [
                f"• <{d.html_url}|{d.repo}#{d.number}> {d.severity} `{d.package}` dismissed as "
                f"_{d.reason}_ by @{d.by} with no comment"
                for d in closed.unexplained[:10]
            ]
            title = "⚠️ *High-severity dismissals with no justification:*"
            blocks.append(_section(title + "\n" + "\n".join(rows)))

    rows = [
        f"• <https://github.com/{org}/{r.repo}/security/dependabot|{r.repo}>: "
        f"{len(r.overdue)} overdue, {len(r.stale_prs)} stale PR(s)"
        + (f", ✅ {len(r.ready_prs)} ready" if r.ready_prs else "")
        + (f", 🔥 {len(r.known_exploited)} exploited" if r.known_exploited else "")
        + (f" (owners: {', '.join(r.owners)})" if r.owners else "")
        for r in ranked[:MAX_ROWS]
    ]
    if len(ranked) > MAX_ROWS:
        rows.append(f"…and {len(ranked) - MAX_ROWS} more.")
    if rows:
        blocks.append(_section("*Repos needing attention*\n" + "\n".join(rows)))
    else:
        blocks.append(_section("Nothing overdue. 🎉"))
    text = "\n\n".join(b["text"]["text"] for b in blocks)
    return text, blocks


def send_leaderboard(
    client: SlackClient | None,
    webhook_url: str | None,
    config: Config,
    text: str,
    blocks: list[dict[str, Any]],
    apply: bool,
) -> Action:
    channel = config.slack.default_channel
    if client is not None and channel:
        return _post(channel, "leaderboard", partial(client.post, channel, text, blocks), apply)
    if webhook_url:
        send = partial(post_webhook, webhook_url, text, blocks)
        return _post("webhook", "leaderboard", send, apply)
    return Action(
        None,
        ActionKind.SLACK_SKIP,
        "no leaderboard target: set slack.default_channel (with a bot token) "
        f"or ${config.slack.webhook_env}",
    )
