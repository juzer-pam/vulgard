from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, assert_never

import httpx

from .config import Config
from .linear import LinearClient, LinearError, sync_linear
from .plan import Action, ActionKind, IssueOp, RepoPlan, RepoRun, TrackingState
from .policy import RepoReport, now_utc
from .render import escalation_md, newly_overdue_md, newly_ready_md, render_issue_body


def _reminder(report: RepoReport, config: Config) -> str | None:
    parts = []
    if report.overdue:
        parts.append(f"**{len(report.overdue)} overdue alert(s)**")
    if report.ready_prs:
        parts.append(f"**{len(report.ready_prs)} Dependabot PR(s) ready to merge**")
    if report.stale_prs:
        parts.append(
            f"**{len(report.stale_prs)} Dependabot PR(s) open for {config.stale_pr_days}+ days**"
        )
    if not parts:
        return None
    return (
        f"{' '.join(report.owners)} Reminder: this repo still has {' and '.join(parts)}. "
        "See the list in the issue description."
    )


def plan_repo(
    report: RepoReport, config: Config, issue: dict[str, Any] | None, now: datetime
) -> RepoPlan:
    prev = TrackingState.from_body(issue["body"] if issue else None)
    if not report.needs_tracking:
        if issue is None:
            return RepoPlan(report, IssueOp.NONE, prev)
        resolved = "✅ All Dependabot alerts are resolved. Thanks! Closing this issue."
        return RepoPlan(report, IssueOp.CLOSE, prev, [resolved])

    newly_overdue = [a for a in report.overdue if a.number not in prev.overdue]
    newly_ready = [p for p in report.ready_prs if p.number not in prev.ready_prs]
    escalate = [
        a for a in report.escalation_due(config.escalation) if a.number not in prev.escalated
    ]
    reminder_due = prev.last_reminder is None or (
        (now - prev.last_reminder).days >= config.reminder_interval_days
    )

    comments: list[str] = []
    reminder = False
    if issue and (newly_overdue or newly_ready):
        sections = [newly_overdue_md(newly_overdue)] if newly_overdue else []
        if newly_ready:
            sections.append(newly_ready_md(newly_ready))
        comments.append(f"{' '.join(report.owners)} " + "\n\n".join(sections))
    elif issue and reminder_due and (text := _reminder(report, config)):
        comments.append(text)
        reminder = True
    if escalate:
        leads = "".join(f"{m} " for m in config.escalation.mentions)
        comments.append(leads + escalation_md(escalate, config.escalation))

    open_numbers = {a.number for a in report.alerts}
    state = TrackingState(
        overdue=tuple(sorted(a.number for a in report.overdue)),
        escalated=tuple(
            sorted(set(prev.escalated) & open_numbers | {a.number for a in escalate})
        ),
        ready_prs=tuple(sorted(p.number for p in report.ready_prs)),
        last_reminder=now if comments or issue is None else prev.last_reminder,
        linear=prev.linear,
    )
    return RepoPlan(
        report,
        IssueOp.CREATE if issue is None else IssueOp.UPDATE,
        state,
        comments,
        newly_overdue=newly_overdue,
        newly_ready=newly_ready,
        escalate=escalate,
        reminder=reminder,
    )


def _individual_owners(owners: list[str]) -> list[str]:
    return [o.lstrip("@") for o in owners if "/" not in o]


def _write_issue(
    gh: Any, config: Config, plan: RepoPlan, issue: dict[str, Any] | None, now: datetime
) -> dict[str, Any] | None:
    org, repo = config.org, plan.repo
    match plan.op:
        case IssueOp.NONE:
            return issue
        case IssueOp.CLOSE:
            assert issue is not None
            for c in plan.comments:
                gh.comment_issue(org, repo, issue["number"], c)
            gh.update_issue(org, repo, issue["number"], state="closed")
            return issue
        case IssueOp.CREATE:
            gh.ensure_label(org, repo, config.issue.label)
            issue = gh.create_issue(
                org,
                repo,
                config.issue.title,
                render_issue_body(plan.report, config, plan.state, now),
                [config.issue.label],
                _individual_owners(plan.report.owners),
            )
        case IssueOp.UPDATE:
            assert issue is not None
            body = render_issue_body(plan.report, config, plan.state, now)
            if body != issue.get("body"):
                gh.update_issue(org, repo, issue["number"], body=body)
        case _ as unreachable:
            assert_never(unreachable)
    for c in plan.comments:
        gh.comment_issue(org, repo, issue["number"], c)
    return issue


def _run_repo(
    gh: Any,
    linear: LinearClient | None,
    config: Config,
    report: RepoReport,
    apply: bool,
    now: datetime,
) -> RepoRun:
    issue = gh.find_open_issue(config.org, report.repo, config.issue.label)
    plan = plan_repo(report, config, issue, now)
    run = RepoRun(plan, issue.get("html_url") if issue else None, plan.actions())
    created_in_linear = False
    if linear is not None:
        try:
            result = sync_linear(linear, config, plan, apply)
        except (LinearError, httpx.HTTPError) as e:
            run.actions.append(Action(plan.repo, ActionKind.LINEAR_ERROR, str(e)))
        else:
            run.actions += result.actions
            plan.state = replace(plan.state, linear=result.ref)
            created_in_linear = result.created
    if not apply:
        return run
    issue = _write_issue(gh, config, plan, issue, now)
    if issue:
        run.issue_url = issue.get("html_url")
    if linear is not None and created_in_linear and plan.state.linear and run.issue_url:
        try:
            linear.attach_url(plan.state.linear.id, run.issue_url, f"{plan.repo} tracking issue")
        except (LinearError, httpx.HTTPError) as e:
            run.actions.append(Action(plan.repo, ActionKind.LINEAR_ERROR, str(e)))
    return run


def nag(
    gh: Any,
    config: Config,
    reports: dict[str, RepoReport],
    apply: bool,
    now: datetime | None = None,
    linear: LinearClient | None = None,
) -> list[RepoRun]:
    now = now or now_utc()
    return [
        _run_repo(gh, linear, config, report, apply, now)
        for _, report in sorted(reports.items())
    ]
