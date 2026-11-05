"""The vulnerabilities topic: Dependabot alerts past their SLA, tracked through the engine."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Self

from .config import SEVERITIES, Config, team_of_owners
from .linear import PRIORITY, LinearClient
from .nag import load_issues, track
from .plan import (
    Escalation,
    IssueOp,
    LinearContent,
    RepoPlan,
    RepoRun,
    Topic,
    TopicSpec,
    TrackedIssue,
    TrackingState,
    issue_op,
    mention_prefix,
    reminder_clock,
    reminder_due,
    slack_summary,
)
from .policy import (
    ClosedSummary,
    RepoReport,
    SlaStatus,
    evaluate,
    now_utc,
    org_totals,
)
from .render import (
    alert_sections,
    escalation_md,
    newly_overdue_md,
    newly_ready_md,
    pr_sections,
    render_issue_body,
    severity_summary,
)
from .repos import resolve_owners
from .slack import (
    DIVIDER,
    LEADERBOARD_ROWS,
    Block,
    context_block,
    fields_block,
    header_block,
    ranking,
    section_block,
)

RESOLVED = "✅ All Dependabot alerts are resolved. Thanks! Closing this issue."


@dataclass(frozen=True)
class VulnMemory:
    overdue: tuple[int, ...] = ()
    escalated: tuple[int, ...] = ()
    ready_prs: tuple[int, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Self:
        return cls(
            overdue=tuple(raw.get("overdue", ())),
            escalated=tuple(raw.get("escalated", ())),
            ready_prs=tuple(raw.get("ready_prs", ())),
        )


type VulnState = TrackingState[VulnMemory]


def spec(config: Config) -> TopicSpec:
    return TopicSpec(
        topic=Topic.VULNS,
        label=config.issue.label,
        title=config.issue.title,
        slack_title="Vulnerable dependencies",
        slack_header="Vulnerable dependencies need attention in these repos:",
        slack_dm_header="Updates on vulnerable dependencies in repos you own:",
        escalation_header="These Dependabot alerts are well past their fix deadline:",
        linear_closed="✅ All Dependabot alerts are resolved. Closing.",
        memory_type=VulnMemory,
    )


def collect(
    gh: Any, config: Config, repos: list[dict[str, Any]], kev: frozenset[str] = frozenset()
) -> dict[str, RepoReport]:
    """Open alerts and Dependabot PRs for each of the repos, with owners where there is work."""
    reports = evaluate(
        config,
        gh.list_open_alerts(config.org),
        gh.list_dependabot_prs(config.org),
        [r["name"] for r in repos],
        kev=kev,
    )
    for report in reports.values():
        if report.alerts or report.dependabot_prs:
            report.owners = resolve_owners(gh, config, report.repo)
    return reports


def critical_repos(reports: dict[str, RepoReport]) -> frozenset[str]:
    """Repos with an open critical alert. Their personal deployments become eligible for
    automatic redeploys and deletes."""
    return frozenset(repo for repo, r in reports.items() if r.severity_counts()["critical"])


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


def render_description(report: RepoReport) -> str:
    n = len(report.alerts)
    lines = [
        f"**{report.repo}** has {n} open vulnerable dependenc{'y' if n == 1 else 'ies'}: "
        f"{severity_summary(report.severity_counts())}.",
        *alert_sections(report, relative=False),
        *pr_sections(report, relative=False),
        "",
        "---",
        "_Synced by vulgard from GitHub. The description, priority, and due date are "
        "overwritten on each run, and the issue closes itself once every alert is resolved._",
    ]
    return "\n".join(lines)


def worst_severity(report: RepoReport) -> str | None:
    counts = report.severity_counts()
    return next((s for s in SEVERITIES if counts[s]), None)


def issue_fields(report: RepoReport, config: Config) -> dict[str, Any]:
    worst = worst_severity(report) or "low"
    urgent = any(
        a.known_exploited or (a.severity == "critical" and a.status == SlaStatus.OVERDUE)
        for a in report.alerts
    )
    fields: dict[str, Any] = {
        "title": f"{report.repo}: {config.issue.title}",
        "description": render_description(report),
        "priority": 1 if urgent else PRIORITY[worst],
    }
    deadlines = [a.deadline for a in report.alerts if a.deadline]
    if deadlines:
        fields["dueDate"] = min(deadlines).date().isoformat()
    return fields


def _digest(report: RepoReport, newly_overdue: int) -> str:
    parts = [f"*{newly_overdue} newly overdue*"] if newly_overdue else []
    if report.overdue:
        parts.append(f"{len(report.overdue)} overdue")
    if report.due_soon:
        parts.append(f"{len(report.due_soon)} due soon")
    if report.known_exploited:
        parts.append(f"🔥 {len(report.known_exploited)} actively exploited")
    if report.ready_prs:
        links = ", ".join(f"<{p.html_url}|#{p.number}>" for p in report.ready_prs[:5])
        parts.append(f"*✅ {len(report.ready_prs)} Dependabot PR(s) ready to merge* ({links})")
    if report.stale_prs:
        parts.append(f"{len(report.stale_prs)} stale Dependabot PR(s)")
    return ", ".join(parts)


def plan_repo(
    report: RepoReport, config: Config, issue: TrackedIssue | None, now: datetime
) -> RepoPlan[VulnMemory]:
    topic = spec(config)
    prev = TrackingState.from_body(issue.body if issue else None, VulnMemory)
    op = issue_op(None if issue is None else issue.open, report.needs_tracking)

    def render(state: VulnState) -> str:
        return render_issue_body(report, config, state, now)

    if op in (IssueOp.CLOSE, IssueOp.NONE):
        closing = [RESOLVED] if op == IssueOp.CLOSE else []
        return RepoPlan(
            topic, report.repo, report.owners, op, prev, "all alerts resolved", render, closing
        )

    fresh = op in (IssueOp.CREATE, IssueOp.REOPEN)
    newly_overdue = [a for a in report.overdue if a.number not in prev.memory.overdue]
    newly_ready = [p for p in report.ready_prs if p.number not in prev.memory.ready_prs]
    due = report.escalation_due(config.escalation) if config.escalation.due(now) else []
    escalate = [a for a in due if a.number not in prev.memory.escalated]
    comments: list[str] = []
    detail = None
    reminder = False
    if op == IssueOp.REOPEN:
        comments.append(
            f"{' '.join(report.owners)} Reopened: this repo has {len(report.alerts)} open "
            "Dependabot alert(s) again. See the list in the issue description."
        )
    elif not fresh and (newly_overdue or newly_ready):
        sections = [newly_overdue_md(newly_overdue)] if newly_overdue else []
        if newly_ready:
            sections.append(newly_ready_md(newly_ready))
        comments.append(f"{' '.join(report.owners)} " + "\n\n".join(sections))
        detail = f"{len(newly_overdue)} newly overdue, {len(newly_ready)} newly ready PR(s)"
    elif (
        not fresh
        and reminder_due(prev, now, config.reminder_interval_days)
        and (text := _reminder(report, config))
    ):
        comments.append(text)
        reminder = True
        detail = "periodic reminder"
    escalation = None
    if escalate:
        leads = mention_prefix(config.escalation.mentions)
        comments.append(leads + escalation_md(escalate, config.escalation))
        worst = [
            f"{a.severity} `{a.package}` {-a.days_left}d overdue"
            + (" 🔥" if a.known_exploited else "")
            for a in escalate
        ]
        escalation = Escalation(
            detail=f"{len(escalate)} alert(s)",
            linear_md=escalation_md(escalate, config.escalation, relative=False),
            slack_detail=slack_summary(worst),
        )

    open_numbers = {a.number for a in report.alerts}
    state = TrackingState(
        VulnMemory(
            overdue=tuple(sorted(a.number for a in report.overdue)),
            escalated=tuple(
                sorted(set(prev.memory.escalated) & open_numbers | {a.number for a in escalate})
            ),
            ready_prs=tuple(sorted(p.number for p in report.ready_prs)),
        ),
        last_reminder=reminder_clock(prev, now, bool(comments) or fresh),
        linear=prev.linear,
    )
    news = [newly_overdue_md(newly_overdue, relative=False)] if newly_overdue else []
    if newly_ready:
        news.append(newly_ready_md(newly_ready, relative=False))
    linear = LinearContent(
        fields=issue_fields(report, config),
        worst_severity=worst_severity(report),
        reopened=(
            f"Reopened by vulgard: {len(report.alerts)} alert(s) are still open in GitHub. "
            "This issue closes itself once they're fixed. To accept a risk instead, dismiss the "
            "alert in GitHub with a reason or add an exception with an expiry date to vulgard.yml."
        ),
        news=news,
    )
    pinged = fresh or newly_overdue or newly_ready or escalate or reminder
    return RepoPlan(
        topic,
        report.repo,
        report.owners,
        op,
        state,
        f"{len(report.alerts)} alert(s)",
        render,
        comments,
        comment_detail=detail,
        linear=linear,
        escalation=escalation,
        digest=_digest(report, len(newly_overdue)) if pinged else None,
    )


def nag(
    gh: Any,
    config: Config,
    reports: dict[str, RepoReport],
    apply: bool,
    now: datetime | None = None,
    linear: LinearClient | None = None,
) -> list[RepoRun]:
    now = now or now_utc()
    issues = load_issues(gh, config, spec(config), sorted(reports))
    plans = [plan_repo(reports[repo], config, issues[repo], now) for repo in sorted(reports)]
    return track(gh, linear, config, plans, issues, apply)


def leaderboard_blocks(
    config: Config, reports: dict[str, RepoReport], closed: ClosedSummary | None
) -> list[Block]:
    """The weekly org-wide scoreboard: totals, team rankings and only the riskiest few repos.
    Names teams without pinging."""
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
    blocks = [
        header_block(f"🏆 Vulnerability leaderboard · {org}"),
        fields_block(
            [
                f"*Fixed (last 7 days)*\n{sum(fixed.values())}",
                f"*Past deadline*\n{totals.overdue}",
                f"*Actively exploited*\n{totals.exploited}",
                f"*PRs ready to merge*\n{totals.ready_prs}",
            ]
        ),
    ]

    fixed_by_team: Counter[str] = Counter()
    for repo, n in fixed.items():
        fixed_by_team[team_of_owners(reports[repo].owners)] += n
    overdue_by_team: Counter[str] = Counter()
    exploited_by_team: Counter[str] = Counter()
    for r in reports.values():
        team = team_of_owners(r.owners)
        overdue_by_team[team] += len(r.overdue)
        exploited_by_team[team] += len(r.known_exploited)
    rankings: list[str] = []
    if fixed_by_team:
        rows = [f"{team}: {n}" for team, n in fixed_by_team.most_common()]
        rankings.append(ranking("Most fixed this week", rows, medals=True))
    if len(+overdue_by_team) > 1:
        rows = [
            f"{team}: {n}"
            + (f" (🔥 {exploited_by_team[team]})" if exploited_by_team[team] else "")
            for team, n in (+overdue_by_team).most_common()
        ]
        rankings.append(ranking("Most overdue", rows, medals=False))
    if rankings:
        blocks.append(fields_block(rankings))

    if closed is not None and closed.unexplained:
        rows = [
            f"• <{d.html_url}|{d.repo}#{d.number}> {d.severity} `{d.package}` dismissed as "
            f"_{d.reason}_ by @{d.by} with no comment"
            for d in closed.unexplained[:10]
        ]
        title = "⚠️ *High-severity dismissals with no justification*"
        blocks.append(section_block(title + "\n" + "\n".join(rows)))

    if not ranked:
        blocks.append(section_block("Nothing overdue. 🎉"))
        return blocks
    shown = ranked[:LEADERBOARD_ROWS]
    owners = {tuple(r.owners) for r in shown}
    shared = owners.pop() if len(owners) == 1 else ()
    rows = []
    for r in shown:
        parts = [f"{len(r.overdue)} overdue"] if r.overdue else []
        if r.stale_prs:
            parts.append(f"{len(r.stale_prs)} stale PR{'s' if len(r.stale_prs) != 1 else ''}")
        if r.ready_prs:
            parts.append(f"✅ {len(r.ready_prs)} ready")
        if r.known_exploited:
            parts.append(f"🔥 {len(r.known_exploited)} exploited")
        if r.owners and not shared:
            parts.append(", ".join(r.owners))
        link = f"<https://github.com/{org}/{r.repo}/security/dependabot|{r.repo}>"
        rows.append(f"• *{link}* — {' · '.join(parts)}")
    blocks += [DIVIDER, section_block("*Highest-risk repos*\n" + "\n".join(rows))]
    hidden = len(ranked) - len(shown)
    notes = [f"+{hidden} more repos need attention"] if hidden else []
    if shared:
        notes.append(f"Owners: {', '.join(shared)}")
    alerts_url = f"https://github.com/orgs/{org}/security/alerts/dependabot"
    notes.append(f"<{alerts_url}|All Dependabot alerts>")
    blocks.append(context_block(notes))
    return blocks

