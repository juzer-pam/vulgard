from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

import httpx

from .config import Config, route
from .events import Action, ActionKind, RepoPlan
from .policy import ClosedSummary, RepoReport

API_URL = "https://slack.com/api"
MAX_ROWS = 15


class SlackError(RuntimeError):
    pass


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


def mention(handle: str, config: Config) -> str:
    slack_id = config.slack.users.get(handle)
    if not slack_id:
        return handle
    if slack_id.startswith("S"):
        return f"<!subteam^{slack_id}>"
    return f"<@{slack_id}>"


def _repo_link(org: str, repo: str, issue_url: str | None) -> str:
    url = issue_url or f"https://github.com/{org}/{repo}/security/dependabot"
    return f"<{url}|{repo}>"


def _repo_line(plan: RepoPlan, config: Config) -> str:
    r = plan.report
    parts = ["new tracking issue"] if plan.opened else []
    if plan.newly_overdue:
        parts.append(f"*{len(plan.newly_overdue)} newly overdue*")
    if r.overdue:
        parts.append(f"{len(r.overdue)} overdue")
    if r.due_soon:
        parts.append(f"{len(r.due_soon)} due soon")
    if r.known_exploited:
        parts.append(f"🔥 {len(r.known_exploited)} actively exploited")
    ready = r.ready_prs(config.ready_pr_days)
    if ready:
        links = ", ".join(f"<{p.html_url}|#{p.number}>" for p in ready[:5])
        parts.append(f"*✅ {len(ready)} Dependabot PR(s) ready to merge* ({links})")
    stale = r.stale_prs(config.stale_pr_days)
    if stale:
        parts.append(f"{len(stale)} stale Dependabot PR(s)")
    owners = " ".join(mention(o, config) for o in r.owners)
    line = f"• *{_repo_link(config.org, r.repo, plan.issue_url)}*: {', '.join(parts)}"
    return line + (f" · {owners}" if owners else "")


def _escalation_line(plan: RepoPlan, config: Config) -> str:
    worst = ", ".join(
        f"{a.severity} `{a.package}` {-a.days_left}d overdue"
        + (" 🔥" if a.known_exploited else "")
        for a in plan.escalate[:3]
    )
    more = f" (+{len(plan.escalate) - 3} more)" if len(plan.escalate) > 3 else ""
    owners = " ".join(mention(o, config) for o in plan.report.owners)
    link = _repo_link(config.org, plan.repo, plan.issue_url)
    return f"• *{link}*: {worst}{more}" + (f" · owners {owners}" if owners else "")


def notify_slack(client: Any, config: Config, plans: list[RepoPlan], apply: bool) -> list[Action]:
    channels: dict[str, list[str]] = defaultdict(list)
    dms: dict[str, list[str]] = defaultdict(list)
    escalations: list[str] = []
    for plan in plans:
        if not plan.pinged:
            continue
        line = _repo_line(plan, config)
        channel = route(
            config.slack.channels, plan.repo, plan.report.owners, config.slack.default_channel
        )
        if channel:
            channels[channel].append(line)
        if plan.escalate:
            escalations.append(_escalation_line(plan, config))
        if config.slack.dm_owners:
            for owner in plan.report.owners:
                user = config.slack.users.get(owner, "")
                if user[:1] in ("U", "W") and line not in dms[user]:
                    dms[user].append(line)

    messages: list[tuple[str, str, list[str]]] = [
        (channel, "Vulnerable dependencies need attention in these repos:", lines)
        for channel, lines in channels.items()
    ]
    if escalations and config.slack.escalation_channel:
        leads = "".join(f"{mention(m, config)} " for m in config.escalation.mentions)
        header = f"{leads}🚨 Escalation: these alerts are well past their fix deadline."
        messages.append((config.slack.escalation_channel, header, escalations))
    messages += [
        (user, "Updates on vulnerable dependencies in repos you own:", lines)
        for user, lines in dms.items()
    ]

    actions = []
    for target, header, lines in messages:
        if apply:
            try:
                client.post(target, header + "\n" + "\n".join(lines))
            except (SlackError, httpx.HTTPError) as e:
                actions.append(Action("(slack)", ActionKind.SLACK_ERROR, f"{target}: {e}"))
                continue
        actions.append(Action("(slack)", ActionKind.SLACK, f"{target}: {len(lines)} repo(s)"))
    return actions


def digest_message(
    config: Config,
    reports: dict[str, RepoReport],
    closed: ClosedSummary | None,
) -> tuple[str, list[dict[str, Any]]]:
    org, stale_days, ready_days = config.org, config.stale_pr_days, config.ready_pr_days
    ranked = sorted(
        (
            r
            for r in reports.values()
            if r.overdue or r.stale_prs(stale_days) or r.known_exploited or r.ready_prs(ready_days)
        ),
        key=lambda r: -r.risk_score,
    )
    overdue = sum(len(r.overdue) for r in reports.values())
    critical = sum(r.severity_counts()["critical"] for r in reports.values())
    exploited = sum(len(r.known_exploited) for r in reports.values())
    ready = sum(len(r.ready_prs(ready_days)) for r in reports.values())
    header = (
        f"*Vulnerability digest for {org}*: {overdue} alert(s) past deadline, "
        f"{critical} critical open, {exploited} actively exploited, "
        f"across {len(ranked)} repo(s)."
    )
    blocks: list[dict[str, Any]] = [_section(header)]
    if ready:
        blocks.append(
            _section(f"*✅ {ready} Dependabot PR(s) pass CI and only need a review and merge.*")
        )

    if closed is not None:
        fixed_total = sum(closed.fixed.values())
        top = ", ".join(f"{repo} {n}" for repo, n in closed.fixed.most_common(5))
        wins = f"*Last 7 days:* ✅ {fixed_total} fixed" + (f" ({top})" if top else "")
        wins += f", {len(closed.dismissed)} dismissed."
        blocks.append(_section(wins))
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
        f"{len(r.overdue)} overdue, {len(r.stale_prs(stale_days))} stale PR(s)"
        + (f", ✅ {len(r.ready_prs(ready_days))} ready" if r.ready_prs(ready_days) else "")
        + (f", 🔥 {len(r.known_exploited)} exploited" if r.known_exploited else "")
        + (f" (owners: {', '.join(r.owners)})" if r.owners else "")
        for r in ranked[:MAX_ROWS]
    ]
    if len(ranked) > MAX_ROWS:
        rows.append(f"…and {len(ranked) - MAX_ROWS} more.")
    blocks.append(_section("\n".join(rows) if rows else "Nothing overdue. 🎉"))
    text = header if not rows else header + "\n" + "\n".join(rows)
    return text, blocks


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}}


def send_digest(
    client: Any,
    webhook_url: str | None,
    config: Config,
    text: str,
    blocks: list[dict[str, Any]],
    apply: bool,
) -> Action | None:
    if client is not None and config.slack.digest_channel:
        target = config.slack.digest_channel
        if apply:
            client.post(target, text, blocks)
    elif webhook_url:
        target = "webhook"
        if apply:
            post_webhook(webhook_url, text, blocks)
    else:
        return None
    return Action("(slack)", ActionKind.SLACK, f"digest to {target}")
