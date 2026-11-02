"""Turns a `StaleReport` and the existing tracking issue into a `RepoPlan`: what to write on the
issue, what to say in comments, when to escalate, and what Linear and Slack hear.

Pure, like `vulns.plan_repo`, whose skeleton it shares through the helpers in `plan.py`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .config import SEVERITIES, Config
from .lifecycle import TRIGGER_WHY, Scheduled, notice_marker
from .linear import PRIORITY
from .plan import (
    Escalation,
    IssueOp,
    LinearContent,
    RepoPlan,
    TrackedIssue,
    TrackingState,
    issue_op,
    mention_prefix,
    reminder_clock,
    reminder_due,
    slack_summary,
)
from .stale import Finding, StaleMemory, StaleReport, spec
from .stale_render import finding_block, finding_line, render_body, render_description

CLOSED = "✅ Every deployment here is up to date or baselined, and the repo is active. Closing."
BASELINED_DAYS = 14  # how long "baselined this week" remembers a resolved finding
MAX_GONE_NAMES = 100  # deleted deployments remembered, so commands naming them stay moot


@dataclass(frozen=True)
class Changes:
    """What differs from what the issue already announced."""

    newly: list[Finding]
    newly_overdue: list[Finding]
    escalate: list[Finding]

    @classmethod
    def of(cls, report: StaleReport, memory: StaleMemory) -> Changes:
        findings = report.findings
        return cls(
            newly=[f for f in findings if f.key not in memory.flagged],
            newly_overdue=[f for f in report.overdue if f.key not in memory.overdue],
            escalate=[f for f in findings if f.sla.escalate and f.key not in memory.escalated],
        )


def _baselined(
    memory: StaleMemory, report: StaleReport, now: datetime
) -> tuple[tuple[str, str], ...]:
    """Findings resolved in the last two weeks, for the leaderboard."""
    current = {f.key for f in report.findings}
    today = now.date().isoformat()
    cutoff = (now - timedelta(days=BASELINED_DAYS)).date().isoformat()
    resolved = {(k, today) for k in memory.flagged if k not in current}
    return tuple(sorted({b for b in memory.baselined if b[1] >= cutoff} | resolved))


def _seen(memory: StaleMemory, report: StaleReport) -> tuple[str, ...]:
    """Every deployment name present now, plus the most recent that went away."""
    present = {d.name for d in report.deployments}
    gone = sorted(set(memory.seen) - present)[:MAX_GONE_NAMES]
    return tuple(sorted(present | set(gone)))


def _news_comment(report: StaleReport, changes: Changes, now: datetime, mentions: str) -> str:
    by_key = {f.key: f for f in [*changes.newly, *changes.newly_overdue]}
    news = sorted(by_key.values(), key=lambda f: f.sla.days_left)
    lines = [line for f in news for line in finding_block(f, now)]
    return (
        f"{mentions} {len(news)} item(s) need a baseline. Comment a command to record one:"
        "\n\n" + "\n".join(lines)
    )


def _reminder_comment(report: StaleReport, mentions: str) -> str:
    return (
        f"{mentions} Reminder: {len(report.findings)} item(s) still need a baseline "
        f"({len(report.overdue)} overdue). See the list in the issue description."
    )


def _notice_comment(report: StaleReport, fresh: list[Scheduled]) -> str:
    """Announces automatic ops. The hidden markers are how the next run finds the posting time."""
    persons = sorted({s.deployment.person for s in fresh if s.deployment.person})
    lines = [
        f"- `{s.deployment.name}` ({s.deployment.person}): **{s.verb}** on {s.due:%Y-%m-%d} "
        f"({TRIGGER_WHY[s.trigger]})"
        for s in fresh
    ]
    markers = [notice_marker(s.deployment.key, s.verb) for s in fresh]
    return (
        f"{' '.join([*persons, *report.owners])} vulgard will act on these personal "
        "deployments automatically unless someone comments "
        "`/vulgard keep <name> until YYYY-MM-DD: why` or `/vulgard cancel <name>` first:"
        "\n\n" + "\n".join(lines) + "\n\n" + "\n".join(markers)
    )


def _escalation(config: Config, escalate: list[Finding], now: datetime) -> tuple[str, Escalation]:
    text = (
        f"Escalating: these are more than {config.escalation.after_days_overdue} days past "
        "their baseline deadline."
    )
    comment = (
        f"{mention_prefix(config.escalation.mentions)}{text}\n\n"
        + "\n".join(finding_line(f, now) for f in escalate)
    )
    worst = [f"{f.sla.severity} `{f.name}` {-f.sla.days_left}d overdue" for f in escalate]
    return comment, Escalation(
        detail=f"{len(escalate)} item(s)",
        linear_md=f"{text}\n\n" + "\n".join(finding_line(f, now, relative=False) for f in escalate),
        slack_detail=slack_summary(worst),
    )


def _worst(report: StaleReport) -> str | None:
    present = {f.sla.severity for f in report.findings}
    return next((s for s in SEVERITIES if s in present), None)


def _digest(report: StaleReport, newly: int) -> str:
    parts = [f"*{newly} newly stale*"] if newly else []
    if report.deployment_findings:
        parts.append(f"{len(report.deployment_findings)} deployment(s) need a baseline")
    if report.overdue:
        parts.append(f"{len(report.overdue)} overdue")
    if report.lifecycle.scheduled:
        parts.append(f"{len(report.lifecycle.scheduled)} automatic op(s) scheduled")
    if report.repo_finding is not None:
        days = report.repo_finding.days
        parts.append(f"no commits in {days}d" if days is not None else "no commits")
    return ", ".join(parts)


def _linear_content(
    report: StaleReport, config: Config, newly: list[Finding], fresh: bool, now: datetime
) -> LinearContent:
    worst = _worst(report)
    fields: dict[str, Any] = {
        "title": f"{report.repo}: {config.deployments.title}",
        "description": render_description(report, now),
        "priority": PRIORITY[worst or "low"],
    }
    if report.findings:
        fields["dueDate"] = min(f.sla.deadline for f in report.findings).date().isoformat()
    news = [] if fresh or not newly else ["\n".join(finding_line(f, now, False) for f in newly)]
    return LinearContent(
        fields=fields,
        worst_severity=worst,
        reopened="Reopened by vulgard: deployments in this repo need a baseline again.",
        news=news,
    )


def plan_repo(
    report: StaleReport, config: Config, issue: TrackedIssue | None, now: datetime
) -> RepoPlan[StaleMemory]:
    """Pure. Announce what's new, remind, announce automatic ops, escalate."""
    topic = spec(config)
    prev = TrackingState.from_body(issue.body if issue else None, StaleMemory)
    op = issue_op(issue, report.needs_tracking)
    baselined = _baselined(prev.memory, report, now)
    seen = _seen(prev.memory, report)

    def render(state: TrackingState[StaleMemory]) -> str:
        return render_body(report, config, state, now)

    if op in (IssueOp.CLOSE, IssueOp.NONE):
        memory = StaleMemory(seen=seen, baselined=baselined)
        state = TrackingState(memory, prev.last_reminder, prev.linear)
        closing = [CLOSED] if op == IssueOp.CLOSE else []
        return RepoPlan(topic, report.repo, report.owners, op, state, "baselined", render, closing)

    fresh = op in (IssueOp.CREATE, IssueOp.REOPEN)
    changes = Changes.of(report, prev.memory)
    mentions = " ".join([*report.owners, *report.persons])
    comments: list[str] = []
    detail = None
    if op == IssueOp.REOPEN or (not fresh and (changes.newly or changes.newly_overdue)):
        comments.append(_news_comment(report, changes, now, mentions))
        detail = f"{len(changes.newly)} newly stale, {len(changes.newly_overdue)} newly overdue"
    elif not fresh and report.findings and reminder_due(prev, now, config.reminder_interval_days):
        comments.append(_reminder_comment(report, mentions))
        detail = "periodic reminder"
    announce = [s for s in report.lifecycle.scheduled if s.fresh]
    if announce:
        comments.append(_notice_comment(report, announce))
        detail = detail or f"{len(announce)} automatic op(s) announced"
    escalation = None
    if changes.escalate:
        text, escalation = _escalation(config, changes.escalate, now)
        comments.append(text)

    keys = {f.key for f in report.findings}
    escalated = set(prev.memory.escalated) & keys | {f.key for f in changes.escalate}
    memory = StaleMemory(
        seen=seen,
        flagged=tuple(sorted(keys)),
        overdue=tuple(sorted(f.key for f in report.overdue)),
        escalated=tuple(sorted(escalated)),
        baselined=baselined,
    )
    state = TrackingState(memory, reminder_clock(prev, now, bool(comments) or fresh), prev.linear)
    pinged = fresh or changes.newly or changes.newly_overdue or changes.escalate or detail
    return RepoPlan(
        topic,
        report.repo,
        report.owners,
        op,
        state,
        f"{len(report.findings)} item(s)",
        render,
        comments,
        comment_detail=detail,
        linear=_linear_content(report, config, changes.newly, fresh, now),
        escalation=escalation,
        digest=_digest(report, len(changes.newly)) if pinged else None,
        dm=tuple(report.persons),
    )
