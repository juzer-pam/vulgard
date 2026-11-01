from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

import httpx

from .config import SEVERITIES, Config
from .events import Action, ActionKind, RepoPlan
from .linear import LinearError, sync_linear
from .policy import Alert, ClosedSummary, RepoReport, SlaStatus, now_utc, parse_time

STATE_RE = re.compile(r"<!-- vulgard-state (\{.*?\}) -->", re.S)


def read_state(body: str | None) -> dict[str, Any]:
    if not body:
        return {}
    match = STATE_RE.search(body)
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def render_issue_body(
    report: RepoReport, config: Config, state: dict[str, Any], now: datetime
) -> str:
    counts = report.severity_counts()
    lines = [
        f"This repository has **{len(report.alerts)} open Dependabot alert(s)**: "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
        + ".",
        "",
        "Fix deadlines (days from when the alert opened): "
        + ", ".join(f"{s} **{config.sla_days[s]}d**" for s in SEVERITIES)
        + (
            f", and **{config.kev.sla_days}d** for anything on CISA's known-exploited list"
            if config.kev.enabled
            else ""
        )
        + ".",
    ]
    if report.owners:
        lines += ["", f"Owners: {' '.join(report.owners)}"]
    linear = state.get("linear")
    if linear:
        lines += ["", f"Tracked in Linear: [{linear['identifier']}]({linear['url']})"]

    for title, alerts in (
        ("🚨 Overdue", report.overdue),
        ("⏳ Due soon", report.due_soon),
        ("Within SLA", report.by_status(SlaStatus.OK)),
    ):
        if alerts:
            lines += ["", f"### {title} ({len(alerts)})", *[a.markdown_line() for a in alerts]]

    ready = report.ready_prs(config.ready_pr_days)
    if ready:
        lines += [
            "",
            f"### ✅ Ready to merge ({len(ready)})",
            "These pass CI and have no conflicts. They only need a review and a merge.",
            *[p.markdown_line(config.stale_pr_days) for p in ready],
        ]
    waiting = [p for p in report.dependabot_prs if p not in ready]
    if waiting:
        lines += [
            "",
            f"### Other open Dependabot PRs ({len(waiting)})",
            *[p.markdown_line(config.stale_pr_days) for p in waiting],
        ]
    if report.dependabot_prs:
        lines += [
            "",
            "Merging these is usually the fastest way to clear the list above. "
            "If one can't be merged, comment on it with the reason, or dismiss the alert "
            "with a justification so it stops showing up here.",
        ]

    if report.accepted:
        lines += [
            "",
            f"### Accepted risk ({len(report.accepted)})",
            *[a.accepted_line() for a in report.accepted],
            "",
            "These come back automatically when their exception in `vulgard.yml` expires.",
        ]

    lines += [
        "",
        "---",
        f"_Updated by vulgard on {now:%Y-%m-%d %H:%M} UTC. This issue closes itself once "
        "every alert is resolved. Please don't edit it by hand; changes are overwritten._",
        f"<!-- vulgard-state {json.dumps(state, sort_keys=True)} -->",
    ]
    return "\n".join(lines)


def _escalation_targets(report: RepoReport, config: Config) -> list[Alert]:
    esc = config.escalation
    if not esc.mentions and not config.slack.escalation_channel:
        return []
    return [
        a
        for a in report.overdue
        if a.known_exploited
        or (a.severity in esc.severities and -a.days_left >= esc.after_days_overdue)
    ]


def plan_repo(
    report: RepoReport,
    config: Config,
    issue: dict[str, Any] | None,
    now: datetime,
) -> RepoPlan:
    """Decide what to do for a repo. `body` is None if the issue is closed or left alone."""
    prev = read_state(issue["body"] if issue else None)
    stale = report.stale_prs(config.stale_pr_days)

    if report.is_clean and not stale:
        if issue:
            return RepoPlan(
                report,
                [Action(report.repo, ActionKind.CLOSE, "all alerts resolved")],
                None,
                ["✅ All Dependabot alerts are resolved. Thanks! Closing this issue."],
                state=prev,
                closing=True,
            )
        noop = Action(report.repo, ActionKind.NOOP, "clean")
        return RepoPlan(report, [noop], None, [], state=prev)

    overdue_ids = sorted(a.number for a in report.overdue)
    newly_overdue = [a for a in report.overdue if a.number not in set(prev.get("overdue", []))]
    last_reminder = parse_time(prev["last_reminder"]) if prev.get("last_reminder") else None
    reminder_due = last_reminder is None or (
        (now - last_reminder).days >= config.reminder_interval_days
    )
    escalate = [
        a
        for a in _escalation_targets(report, config)
        if a.number not in set(prev.get("escalated", []))
    ]

    ready = report.ready_prs(config.ready_pr_days)
    newly_ready = [p for p in ready if p.number not in set(prev.get("ready_prs", []))]

    comments: list[str] = []
    actions: list[Action] = []
    mentions = " ".join(report.owners)
    reminder = False

    if issue and (newly_overdue or newly_ready):
        sections = []
        if newly_overdue:
            sections.append(
                f"{len(newly_overdue)} alert(s) just went past their fix deadline:\n\n"
                + "\n".join(a.markdown_line() for a in newly_overdue)
            )
        if newly_ready:
            sections.append(
                f"{len(newly_ready)} Dependabot PR(s) pass CI and are only waiting on a review "
                "and merge:\n\n"
                + "\n".join(p.markdown_line(config.stale_pr_days) for p in newly_ready)
            )
        comments.append(f"{mentions} " + "\n\n".join(sections))
        detail = f"{len(newly_overdue)} newly overdue, {len(newly_ready)} newly ready PR(s)"
        actions.append(Action(report.repo, ActionKind.COMMENT, detail))
    elif issue and reminder_due and (report.overdue or stale or ready):
        parts = []
        if report.overdue:
            parts.append(f"**{len(report.overdue)} overdue alert(s)**")
        if ready:
            parts.append(f"**{len(ready)} Dependabot PR(s) ready to merge**")
        if stale:
            parts.append(f"**{len(stale)} Dependabot PR(s) open for {config.stale_pr_days}+ days**")
        comments.append(
            f"{mentions} Reminder: this repo still has {' and '.join(parts)}. "
            "See the list in the issue description."
        )
        actions.append(Action(report.repo, ActionKind.COMMENT, "periodic reminder"))
        reminder = True

    if escalate:
        leads = "".join(f"{m} " for m in config.escalation.mentions)
        comments.append(
            f"{leads}Escalating: these alerts are well past their deadline "
            "or are being actively exploited.\n\n"
            + "\n".join(a.markdown_line() for a in escalate)
        )
        actions.append(Action(report.repo, ActionKind.ESCALATE, f"{len(escalate)} alert(s)"))

    reminded = bool(comments) or issue is None
    state: dict[str, Any] = {
        "overdue": overdue_ids,
        "escalated": sorted(
            set(prev.get("escalated", [])) & {a.number for a in report.alerts}
            | {a.number for a in escalate}
        ),
        "last_reminder": now.isoformat() if reminded else prev.get("last_reminder"),
        "ready_prs": sorted(p.number for p in ready),
    }
    if prev.get("linear"):
        state["linear"] = prev["linear"]
    body = render_issue_body(report, config, state, now)
    if issue is None:
        actions.insert(0, Action(report.repo, ActionKind.CREATE, f"{len(report.alerts)} alert(s)"))
    elif body != issue.get("body"):
        actions.insert(0, Action(report.repo, ActionKind.UPDATE, f"{len(report.alerts)} alert(s)"))
    return RepoPlan(
        report,
        actions,
        body,
        comments,
        state=state,
        newly_overdue=newly_overdue,
        newly_ready=newly_ready,
        escalate=escalate,
        reminder=reminder,
        opened=issue is None,
    )


def _individual_owners(owners: list[str]) -> list[str]:
    return [o.lstrip("@") for o in owners if "/" not in o]


def _write_issue(
    gh: Any, config: Config, plan: RepoPlan, issue: dict[str, Any] | None
) -> dict[str, Any] | None:
    org, repo = config.org, plan.repo
    if plan.closing and issue:
        for c in plan.comments:
            gh.comment_issue(org, repo, issue["number"], c)
        gh.update_issue(org, repo, issue["number"], state="closed")
        return issue
    if plan.body is None:
        return issue
    if issue is None:
        gh.ensure_label(org, repo, config.issue.label)
        issue = gh.create_issue(
            org,
            repo,
            config.issue.title,
            plan.body,
            [config.issue.label],
            _individual_owners(plan.report.owners),
        )
    elif plan.body != issue.get("body"):
        gh.update_issue(org, repo, issue["number"], body=plan.body)
    for c in plan.comments:
        gh.comment_issue(org, repo, issue["number"], c)
    return issue


def _sync_linear(linear: Any, config: Config, plan: RepoPlan, now: datetime, apply: bool) -> bool:
    """Returns True if the Linear ref changed and the issue body was re-rendered."""
    try:
        actions, ref = sync_linear(linear, config, plan, apply)
    except (LinearError, httpx.HTTPError) as e:
        plan.actions.append(Action(plan.repo, ActionKind.LINEAR_ERROR, str(e)))
        return False
    plan.actions.extend(actions)
    if plan.closing or ref == plan.state.get("linear"):
        return False
    plan.state["linear"] = ref
    plan.body = render_issue_body(plan.report, config, plan.state, now)
    return True


def nag(
    gh: Any,
    config: Config,
    reports: dict[str, RepoReport],
    apply: bool,
    now: datetime | None = None,
    linear: Any = None,
) -> list[RepoPlan]:
    now = now or now_utc()
    plans: list[RepoPlan] = []
    for repo, report in sorted(reports.items()):
        issue = gh.find_open_issue(config.org, repo, config.issue.label)
        plan = plan_repo(report, config, issue, now)
        plans.append(plan)
        if issue:
            plan.issue_url = issue.get("html_url")
        active = plan.body is not None or plan.closing

        # Existing issue: sync Linear first so its link lands in the same body update.
        if linear is not None and active and issue is not None:
            _sync_linear(linear, config, plan, now, apply)
        had_issue = issue is not None
        if apply:
            issue = _write_issue(gh, config, plan, issue)
            if issue:
                plan.issue_url = issue.get("html_url")
        # New issue: Linear needs the GitHub URL, so it syncs after creation.
        if linear is not None and active and not had_issue:
            changed = _sync_linear(linear, config, plan, now, apply)
            if changed and apply and issue:
                gh.update_issue(config.org, repo, issue["number"], body=plan.body)
    return plans


def render_org_summary(
    config: Config,
    reports: dict[str, RepoReport],
    closed: ClosedSummary | None = None,
) -> str:
    org, stale_days, ready_days = config.org, config.stale_pr_days, config.ready_pr_days
    ready = sum(len(r.ready_prs(ready_days)) for r in reports.values())
    ranked = sorted(
        (r for r in reports.values() if r.alerts or r.stale_prs(stale_days)),
        key=lambda r: -r.risk_score,
    )
    totals = dict.fromkeys(SEVERITIES, 0)
    for r in reports.values():
        for s, n in r.severity_counts().items():
            totals[s] += n
    overdue = sum(len(r.overdue) for r in reports.values())
    exploited = sum(len(r.known_exploited) for r in reports.values())
    lines = [
        f"## Vulnerability report for `{org}`",
        "",
        f"**{sum(totals.values())} open alerts** across {len(ranked)} of {len(reports)} repos "
        f"({', '.join(f'{totals[s]} {s}' for s in SEVERITIES)}). **{overdue} past deadline**, "
        f"**{exploited} actively exploited**. **{ready} Dependabot PR(s) ready to merge.**",
    ]
    if closed is not None:
        lines += [
            "",
            f"Last 7 days: **{sum(closed.fixed.values())} fixed**, "
            f"{len(closed.dismissed)} dismissed "
            f"({len(closed.unexplained)} high-severity with no justification).",
        ]
    if not ranked:
        lines += ["", "No open alerts. 🎉"]
        return "\n".join(lines)
    lines += [
        "",
        "| Repo | Critical | High | Medium | Low | Overdue | Exploited | Ready PRs | Stale PRs |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in ranked:
        c = r.severity_counts()
        lines.append(
            f"| {r.repo} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} "
            f"| {len(r.overdue)} | {len(r.known_exploited)} | {len(r.ready_prs(ready_days))} "
            f"| {len(r.stale_prs(stale_days))} |"
        )
    return "\n".join(lines)
