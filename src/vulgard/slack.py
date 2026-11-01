from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable
from functools import partial
from typing import Any, Protocol

import httpx

from .config import Config, route
from .plan import Action, ActionKind, IssueOp, RepoRun
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
    url = issue_url or f"https://github.com/{org}/{repo}/security/dependabot"
    return f"<{url}|{repo}>"


def _owner_mentions(owners: list[str], config: Config) -> str:
    return " ".join(config.slack.mention(o) for o in owners)


def _repo_line(run: RepoRun, config: Config) -> str:
    plan, r = run.plan, run.plan.report
    parts = ["new tracking issue"] if plan.op == IssueOp.CREATE else []
    if plan.newly_overdue:
        parts.append(f"*{len(plan.newly_overdue)} newly overdue*")
    if r.overdue:
        parts.append(f"{len(r.overdue)} overdue")
    if r.due_soon:
        parts.append(f"{len(r.due_soon)} due soon")
    if r.known_exploited:
        parts.append(f"🔥 {len(r.known_exploited)} actively exploited")
    if r.ready_prs:
        links = ", ".join(f"<{p.html_url}|#{p.number}>" for p in r.ready_prs[:5])
        parts.append(f"*✅ {len(r.ready_prs)} Dependabot PR(s) ready to merge* ({links})")
    if r.stale_prs:
        parts.append(f"{len(r.stale_prs)} stale Dependabot PR(s)")
    owners = _owner_mentions(r.owners, config)
    line = f"• *{_repo_link(config.org, r.repo, run.issue_url)}*: {', '.join(parts)}"
    return line + (f" · {owners}" if owners else "")


def _escalation_line(run: RepoRun, config: Config) -> str:
    escalate = run.plan.escalate
    worst = ", ".join(
        f"{a.severity} `{a.package}` {-a.days_left}d overdue"
        + (" 🔥" if a.known_exploited else "")
        for a in escalate[:3]
    )
    more = f" (+{len(escalate) - 3} more)" if len(escalate) > 3 else ""
    owners = _owner_mentions(run.plan.report.owners, config)
    link = _repo_link(config.org, run.repo, run.issue_url)
    return f"• *{link}*: {worst}{more}" + (f" · owners {owners}" if owners else "")


def notify_slack(
    client: SlackClient, config: Config, runs: list[RepoRun], apply: bool
) -> list[Action]:
    channels: dict[str, list[str]] = defaultdict(list)
    dms: dict[str, list[str]] = defaultdict(list)
    escalations: list[str] = []
    for run in runs:
        if not run.plan.pinged:
            continue
        owners = run.plan.report.owners
        line = _repo_line(run, config)
        channel = route(config.slack.channels, run.repo, owners, config.slack.default_channel)
        if channel:
            channels[channel].append(line)
        if run.plan.escalate:
            escalations.append(_escalation_line(run, config))
        if config.slack.dm_owners:
            for owner in owners:
                user = config.slack.dm_target(owner)
                if user and line not in dms[user]:
                    dms[user].append(line)

    messages: list[tuple[str, str, list[str]]] = [
        (channel, "Vulnerable dependencies need attention in these repos:", lines)
        for channel, lines in channels.items()
    ]
    if escalations and config.slack.escalation_channel:
        leads = "".join(f"{config.slack.mention(m)} " for m in config.escalation.mentions)
        header = f"{leads}🚨 Escalation: these alerts are well past their fix deadline."
        messages.append((config.slack.escalation_channel, header, escalations))
    messages += [
        (user, "Updates on vulnerable dependencies in repos you own:", lines)
        for user, lines in dms.items()
    ]
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
