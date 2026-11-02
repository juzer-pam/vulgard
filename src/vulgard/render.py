from __future__ import annotations

from datetime import datetime

from .config import SEVERITIES, Config, EscalationConfig
from .plan import TrackingState
from .policy import Alert, ClosedSummary, DependabotPR, RepoReport, SlaStatus, org_totals

SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}


def format_table(header: list[str], rows: list[list[str]]) -> str:
    """Left-aligned columns with a dashed rule under the header."""
    table = [header, *rows]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(header))]
    lines = []
    for i, row in enumerate(table):
        lines.append("  ".join(str(cell).ljust(w) for cell, w in zip(row, widths, strict=True)))
        if i == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def severity_summary(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])


def alert_line(a: Alert, relative: bool = True) -> str:
    if relative:
        due = f"{-a.days_left}d overdue" if a.days_left < 0 else f"due in {a.days_left}d"
    else:
        due = f"due {a.deadline:%Y-%m-%d}" if a.deadline else "no deadline"
    fix = f"upgrade to `{a.patched_version}`" if a.patched_version else "no patched version yet"
    pr = f" · fix ready in [#{a.fix_pr.number}]({a.fix_pr.html_url})" if a.fix_pr else ""
    kev = " · 🔥 **actively exploited (CISA KEV)**" if a.known_exploited else ""
    return (
        f"- {SEVERITY_ICON[a.severity]} **{a.severity}** [`{a.package}`]({a.html_url}) "
        f"({a.ecosystem}, `{a.manifest_path}`): {a.summary} [{a.ident}]{kev} · **{due}** · "
        f"{fix}{pr}"
    )


def accepted_line(a: Alert) -> str:
    assert a.exception is not None
    return (
        f"- {SEVERITY_ICON[a.severity]} {a.severity} [`{a.package}`]({a.html_url}) [{a.ident}], "
        f"accepted until **{a.exception.expires.isoformat()}**: {a.exception.reason}"
    )


def _pr_status(p: DependabotPR) -> str:
    if p.mergeable == "CONFLICTING":
        return "⚠️ merge conflicts"
    if p.ci_passing:
        return "✅ CI passing"
    if p.ci_state in ("FAILURE", "ERROR"):
        return "❌ CI failing"
    if p.ci_state in ("PENDING", "EXPECTED"):
        return "⏳ CI running"
    return "no CI checks"


def pr_line(p: DependabotPR, relative: bool = True) -> str:
    age = f"open {p.age_days}d" if relative else f"opened {p.created_at:%Y-%m-%d}"
    fixes = ""
    if p.fixes:
        fixes = " · fixes " + ", ".join(f"{a.severity} `{a.package}`" for a in p.fixes)
    stale = " · ⚠️ stale" if p.stale else ""
    status = _pr_status(p)
    return f"- [#{p.number}]({p.html_url}) {p.title}, {age} · {status}{fixes}{stale}"


def alert_sections(report: RepoReport, relative: bool = True) -> list[str]:
    lines: list[str] = []
    for title, alerts in (
        ("🚨 Overdue", report.overdue),
        ("⏳ Due soon", report.due_soon),
        ("Within SLA", report.by_status(SlaStatus.OK)),
    ):
        if alerts:
            lines += ["", f"### {title} ({len(alerts)})"]
            lines += [alert_line(a, relative) for a in alerts]
    return lines


def pr_sections(report: RepoReport, relative: bool = True) -> list[str]:
    lines: list[str] = []
    ready = report.ready_prs
    if ready:
        lines += [
            "",
            f"### ✅ Ready to merge ({len(ready)})",
            "These pass CI and have no conflicts. They only need a review and a merge.",
            *[pr_line(p, relative) for p in ready],
        ]
    waiting = [p for p in report.dependabot_prs if not p.ready]
    if waiting:
        lines += [
            "",
            f"### Other open Dependabot PRs ({len(waiting)})",
            *[pr_line(p, relative) for p in waiting],
        ]
    return lines


def newly_overdue_md(alerts: list[Alert], relative: bool = True) -> str:
    return f"{len(alerts)} alert(s) just went past their fix deadline:\n\n" + "\n".join(
        alert_line(a, relative) for a in alerts
    )


def newly_ready_md(prs: list[DependabotPR], relative: bool = True) -> str:
    return (
        f"{len(prs)} Dependabot PR(s) pass CI and are only waiting on a review and merge:\n\n"
        + "\n".join(pr_line(p, relative) for p in prs)
    )


def escalation_md(alerts: list[Alert], esc: EscalationConfig, relative: bool = True) -> str:
    lines = "\n".join(alert_line(a, relative) for a in alerts)
    return (
        f"Escalating: these alerts are more than {esc.after_days_overdue} days past their "
        f"deadline or are actively exploited.\n\n{lines}"
    )


def render_issue_body(
    report: RepoReport, config: Config, state: TrackingState, now: datetime
) -> str:
    deadlines = ", ".join(f"{s} **{config.sla_days[s]}d**" for s in SEVERITIES)
    if config.kev.enabled:
        deadlines += f", and **{config.kev.sla_days}d** for anything on CISA's known-exploited list"
    lines = [
        f"This repository has **{len(report.alerts)} open Dependabot alert(s)**: "
        f"{severity_summary(report.severity_counts())}.",
        "",
        f"Fix deadlines (days from when the alert opened): {deadlines}.",
    ]
    if report.owners:
        lines += ["", f"Owners: {' '.join(report.owners)}"]
    if state.linear:
        lines += ["", f"Tracked in Linear: [{state.linear.identifier}]({state.linear.url})"]
    lines += alert_sections(report)
    lines += pr_sections(report)
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
            *[accepted_line(a) for a in report.accepted],
            "",
            "These come back automatically when their exception in `vulgard.yml` expires.",
        ]
    lines += [
        "",
        "---",
        f"_Updated by vulgard on {now:%Y-%m-%d %H:%M} UTC. This issue closes itself once "
        "every alert is resolved. Please don't edit it by hand; changes are overwritten._",
        state.to_comment(),
    ]
    return "\n".join(lines)


def render_org_summary(
    config: Config, reports: dict[str, RepoReport], closed: ClosedSummary | None = None
) -> str:
    ranked = sorted((r for r in reports.values() if r.needs_tracking), key=lambda r: -r.risk_score)
    totals = org_totals(reports)
    lines = [
        f"## Vulnerability report for `{config.org}`",
        "",
        f"**{totals.alerts} open alerts** across {len(ranked)} of {len(reports)} repos "
        f"({', '.join(f'{totals.severities[s]} {s}' for s in SEVERITIES)}). "
        f"**{totals.overdue} past deadline**, **{totals.exploited} actively exploited**. "
        f"**{totals.ready_prs} Dependabot PR(s) ready to merge.**",
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
            f"| {len(r.overdue)} | {len(r.known_exploited)} | {len(r.ready_prs)} "
            f"| {len(r.stale_prs)} |"
        )
    return "\n".join(lines)
