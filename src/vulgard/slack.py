from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Protocol, assert_never

import httpx

from .config import Config, route
from .plan import Action, ActionKind, IssueOp, RepoRun, TopicSpec

API_URL = "https://slack.com/api"
LEADERBOARD_ROWS = 5
MEDALS = ("🥇", "🥈", "🥉")
SECTION_CHARS = 3000

type Block = dict[str, Any]


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

    messages: list[tuple[str, str, str, list[str]]] = []
    for msgs in topics.values():
        spec = msgs.spec
        messages += [
            (ch, spec.slack_title, spec.slack_header, lines) for ch, lines in msgs.channels.items()
        ]
        if msgs.escalations and config.slack.escalation_channel:
            leads = "".join(f"{config.slack.mention(m)} " for m in config.escalation.mentions)
            messages.append(
                (
                    config.slack.escalation_channel,
                    f"🚨 Escalation · {spec.slack_title}",
                    leads + spec.escalation_header,
                    msgs.escalations,
                )
            )
        messages += [
            (user, f"{spec.slack_title} · your repos", spec.slack_dm_header, lines)
            for user, lines in msgs.dms.items()
        ]
    return [
        _post(
            target,
            f"{len(lines)} repo(s)",
            partial(client.post, target, *digest_message(title, intro, lines)),
            apply,
        )
        for target, title, intro, lines in messages
    ]


@dataclass(frozen=True)
class RolloutPR:
    repo: str
    owners: list[str]
    url: str | None  # None in a dry run, before the PR exists


def notify_leads(
    client: SlackClient,
    config: Config,
    prs: list[RolloutPR],
    apply: bool,
    team_tickets: dict[str, str] | None = None,
) -> list[Action]:
    """DMs each team lead about their onboarding ticket and rollout PRs to approve."""
    from .rollout_onboarding import group_rollout_prs_by_team

    tickets = team_tickets or {}
    actions: list[Action] = []
    for team, team_prs in sorted(group_rollout_prs_by_team(config, prs).items()):
        linked = [p for p in team_prs if p.url]
        if not linked:
            continue
        lead = config.linear.leads.get(team)
        user = config.slack.dm_target(lead) if lead else None
        if user is None:
            why = f"no Slack user for {lead}" if lead else "no team lead"
            actions.append(Action(None, ActionKind.SLACK_SKIP, f"team {team}: {why}"))
            continue
        ticket = tickets.get(team)
        intro = (
            f"Your team's vulgard onboarding ticket: <{ticket}|open in Linear>. "
            f"It links {len(linked)} rollout PR(s) that add Dependabot and the vulgard check. "
            "Please review and approve them, or ask repo owners to merge."
            if ticket
            else f"{len(linked)} rollout PR(s) in your team's repos need approval "
            "(Dependabot + vulgard check). Run `vulgard rollout --linear` for a tracking ticket."
        )
        lines = [f"• <{p.url}|{p.repo}>" for p in sorted(linked, key=lambda p: p.repo.lower())]
        message = digest_message("vulgard rollout · approval needed", intro, lines)
        detail = f"team {team}: {len(linked)} PR(s)"
        actions.append(_post(user, detail, partial(client.post, user, *message), apply))
    return actions


def header_block(text: str) -> Block:
    return {"type": "header", "text": {"type": "plain_text", "text": text[:150], "emoji": True}}


def section_block(text: str) -> Block:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:SECTION_CHARS]}}


def fields_block(texts: list[str]) -> Block:
    """Up to 10 mrkdwn cells laid out two per row."""
    return {
        "type": "section",
        "fields": [{"type": "mrkdwn", "text": t[:2000]} for t in texts[:10]],
    }


def context_block(parts: list[str]) -> Block:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": p} for p in parts[:10]]}


DIVIDER: Block = {"type": "divider"}


def chunk_lines(lines: list[str], limit: int = SECTION_CHARS) -> list[str]:
    """Joins lines into as few texts as fit one section each."""
    chunks: list[str] = []
    for line in lines:
        if chunks and len(chunks[-1]) + 1 + len(line) <= limit:
            chunks[-1] += "\n" + line
        else:
            chunks.append(line)
    return chunks


def digest_message(title: str, intro: str, lines: list[str]) -> tuple[str, list[Block]]:
    """A header, the intro (which may carry mentions) and one bullet per repo. The fallback text
    is what notifications show, so it leads with the intro."""
    blocks = [header_block(title), section_block(intro)]
    blocks += [section_block(chunk) for chunk in chunk_lines(lines)]
    return f"{intro} ({len(lines)} repo(s))", blocks


def ranking(title: str, rows: list[str], medals: bool) -> str:
    lines = [
        f"{MEDALS[i] if medals and i < len(MEDALS) else f'{i + 1}.'} {row}"
        for i, row in enumerate(rows[:LEADERBOARD_ROWS])
    ]
    return f"*{title}*\n" + "\n".join(lines)


def leaderboard_message(topics: list[list[Block]]) -> tuple[str, list[Block]]:
    """The weekly org-wide scoreboard for `slack.default_channel`: each topic's blocks, divided.
    The fallback text is just the topic headers, so it never pings anyone."""
    blocks: list[Block] = []
    for topic in (t for t in topics if t):
        blocks += [DIVIDER, *topic] if blocks else topic
    titles = [b["text"]["text"] for b in blocks if b["type"] == "header"]
    return " · ".join(titles), blocks


def send_leaderboard(
    client: SlackClient | None,
    webhook_url: str | None,
    config: Config,
    text: str,
    blocks: list[Block],
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
