"""Turns an `InspectorRepo` and its existing tracking issue into a `RepoPlan`: what the GitHub
issue says, what Linear and Slack hear, and when to escalate.

A public repo never gets a GitHub issue, because Inspector data names what runs in AWS. Its plan
is tracked in Linear only.

Pure, like `vulns.plan_repo`, whose skeleton it shares through the helpers in `plan.py`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .config import Config
from .inspector import FixStatus
from .inspector_render import render_body, repo_description, tracked_line
from .inspector_sla import CLOSED, SPEC, TITLE, InspectorMemory, InspectorRepo, TrackedItem
from .linear import PRIORITY
from .plan import (
    Escalation,
    IssueOp,
    LinearContent,
    RepoPlan,
    TrackingState,
    issue_op,
    mention_prefix,
    reminder_clock,
    reminder_due,
    slack_summary,
)


@dataclass(frozen=True)
class Changes:
    """What differs from what the GitHub issue already announced. Empty without one."""

    newly: list[TrackedItem]
    newly_overdue: list[TrackedItem]
    escalate: list[TrackedItem]

    @classmethod
    def of(cls, repo: InspectorRepo, memory: InspectorMemory, escalating: bool) -> Changes:
        if not repo.github:
            return cls([], [], [])
        listed = {key for key, _ in memory.listed}
        return cls(
            newly=[i for i in repo.items if i.key not in listed],
            newly_overdue=[i for i in repo.overdue if i.key not in memory.overdue],
            escalate=[
                i
                for i in repo.items
                if escalating and i.escalate and i.key not in memory.escalated
            ],
        )

    @property
    def news(self) -> list[TrackedItem]:
        by_key = {i.key: i for i in [*self.newly, *self.newly_overdue]}
        return sorted(by_key.values(), key=lambda i: i.days_left)


def _digest(repo: InspectorRepo, newly: int) -> str:
    statuses = repo.statuses
    parts = [f"{len(repo.items)} item(s)"]
    if newly:
        parts.append(f"*{newly} new*")
    if repo.overdue:
        parts.append(f"{len(repo.overdue)} overdue")
    if repo.due_soon:
        parts.append(f"{len(repo.due_soon)} due soon")
    for status in (FixStatus.NEEDS_FIX, FixStatus.NEEDS_DEPLOY):
        if statuses[status]:
            parts.append(f"{statuses[status]} {status}")
    return ", ".join(parts)


def _linear_content(repo: InspectorRepo, news: list[str], parent_id: str | None) -> LinearContent:
    worst = repo.worst_severity
    urgent = any(i.item.severity == "critical" for i in repo.overdue)
    fields: dict[str, Any] = {
        "title": f"{repo.repo}: {TITLE}",
        "description": repo_description(repo),
        "priority": 1 if urgent else PRIORITY[worst or "low"],
        "dueDate": min(i.deadline for i in repo.items).isoformat(),
    }
    if parent_id:
        fields["parentId"] = parent_id
    return LinearContent(
        fields=fields,
        worst_severity=worst,
        reopened="Reopened by vulgard: Amazon Inspector finds vulnerable packages from this repo "
        "running in AWS again.",
        news=news,
    )


def plan_repo(
    repo: InspectorRepo,
    config: Config,
    prev: TrackingState[InspectorMemory],
    open_issue: bool | None,
    now: datetime,
    parent_id: str | None = None,
) -> RepoPlan[InspectorMemory]:
    """Pure. `prev` and `open_issue` come from the GitHub issue, or for a repo without one from
    its Linear issue, whose state holds just the Linear ref. Linear-only repos are pinged only
    when their Linear issue opens, since nothing remembers what they were told."""
    op = issue_op(open_issue, bool(repo.items))

    def render(state: TrackingState[InspectorMemory]) -> str:
        return render_body(repo, config, state, now)

    if op in (IssueOp.CLOSE, IssueOp.NONE):
        state = TrackingState(InspectorMemory(), prev.last_reminder, prev.linear)
        closing = [CLOSED] if op == IssueOp.CLOSE else []
        summary = "no items"
        return RepoPlan(
            SPEC, repo.repo, repo.owners, op, state, summary, render, closing, github=repo.github
        )

    fresh = op in (IssueOp.CREATE, IssueOp.REOPEN)
    changes = Changes.of(repo, prev.memory, config.escalation.due(now))
    mentions = mention_prefix(repo.owners)
    comments: list[str] = []
    detail = None
    reminder = False
    if repo.github and op == IssueOp.REOPEN:
        comments.append(
            f"{mentions}Reopened: Amazon Inspector finds {len(repo.items)} vulnerable "
            "package(s) from this repo running in AWS again. See the list in the issue "
            "description."
        )
    elif not fresh and changes.news:
        lines = [tracked_line(i) for i in changes.news]
        intro = f"{mentions}{len(lines)} item(s) are new or newly overdue:"
        comments.append(intro + "\n\n" + "\n".join(lines))
        detail = f"{len(changes.newly)} new, {len(changes.newly_overdue)} newly overdue"
    elif (
        repo.github
        and not fresh
        and repo.overdue
        and reminder_due(prev, now, config.reminder_interval_days)
    ):
        comments.append(
            f"{mentions}Reminder: {len(repo.overdue)} item(s) are past their fix deadline. "
            "See the list in the issue description."
        )
        reminder = True
        detail = "periodic reminder"
    escalation = None
    if changes.escalate:
        text = (
            f"Escalating: these are more than {config.escalation.after_days_overdue} days past "
            "their fix deadline."
        )
        comments.append(
            f"{mention_prefix(config.escalation.mentions)}{text}\n\n"
            + "\n".join(tracked_line(i) for i in changes.escalate)
        )
        worst = [
            f"{i.item.severity} `{i.item.package}` {-i.days_left}d overdue"
            for i in changes.escalate
        ]
        escalation = Escalation(
            detail=f"{len(changes.escalate)} item(s)",
            linear_md=f"{text}\n\n"
            + "\n".join(tracked_line(i, relative=False) for i in changes.escalate),
            slack_detail=slack_summary(worst),
        )

    keys = {i.key for i in repo.items}
    escalated = set(prev.memory.escalated) & keys | {i.key for i in changes.escalate}
    memory = InspectorMemory(
        listed=tuple(sorted((i.key, i.listed.isoformat()) for i in repo.items)),
        overdue=tuple(sorted(i.key for i in repo.overdue)),
        escalated=tuple(sorted(escalated)),
    )
    state = TrackingState(memory, reminder_clock(prev, now, bool(comments) or fresh), prev.linear)
    news: list[str] = []
    if not fresh and changes.news:
        news = ["\n".join(tracked_line(i, relative=False) for i in changes.news)]
    pinged = fresh or changes.news or changes.escalate or reminder
    return RepoPlan(
        SPEC,
        repo.repo,
        repo.owners,
        op,
        state,
        f"{len(repo.items)} item(s)",
        render,
        comments,
        comment_detail=detail,
        linear=_linear_content(repo, news, parent_id),
        escalation=escalation,
        digest=_digest(repo, 0 if fresh else len(changes.newly)) if pinged else None,
        github=repo.github,
    )
