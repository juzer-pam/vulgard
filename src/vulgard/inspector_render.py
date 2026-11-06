"""Everything the inspector topic says: the `report --topic inspector` table and JSON, and for
`nag` the issue body, the Linear descriptions, comment lines and the step summary."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, assert_never

from .config import SEVERITIES, Config, InspectorConfig, severities_at_least
from .inspector import (
    Attributed,
    Finding,
    FindingAttribution,
    FixItem,
    FixStatus,
    InspectorReport,
    Reason,
    Unattributed,
    Via,
)
from .inspector_sla import InspectorMemory, InspectorRepo, TrackedItem
from .plan import TrackingState
from .policy import SlaStatus
from .render import SEVERITY_ICON, format_table

MAX_ITEMS = 40  # per issue, so a busy repo's issue stays under GitHub's body limit
MAX_LISTED = 5  # resources and vulnerability ids shown per item


def _severity_counts(items: list[FixItem]) -> list[int]:
    by_severity = Counter(item.severity for item in items)
    return [by_severity[severity] for severity in SEVERITIES]


def _row(label: str, items: list[FixItem]) -> list[str]:
    resources = {finding.resource.id for item in items for finding in item.findings}
    return [
        label,
        *(str(count) for count in _severity_counts(items)),
        str(len(items)),
        str(sum(item.exploit_available for item in items)),
        str(len(resources)),
    ]


def _worst_first(entry: tuple[str, list[FixItem]]) -> tuple[list[int], str]:
    repo, items = entry
    return [-count for count in _severity_counts(items)], repo


def _status_row(label: str, items: list[FixItem]) -> list[str]:
    by_status = Counter(item.status for item in items)
    return [label, *(str(by_status[status]) for status in FixStatus)]


def report_text(report: InspectorReport, cfg: InspectorConfig) -> str:
    """One row per repo, worst first, then one per reason findings couldn't be attributed.
    Severity, items and exploitable count fix items; resources counts distinct resources. A
    second table, in the same row order, counts items by status."""
    sections = [*report.by_repo.values(), *report.unattributed.values()]
    item_count = sum(len(items) for items in sections)
    if not item_count:
        return f"No Inspector findings at {cfg.min_severity} or above."
    ordered = sorted(report.by_repo.items(), key=_worst_first)
    ordered += [
        (f"unattributed: {reason}", items) for reason, items in report.unattributed.items()
    ]
    rows = [_row(label, items) for label, items in ordered]
    status_rows = [_status_row(label, items) for label, items in ordered]
    attributed = ", ".join(f"{report.via[kind]} by {kind}" for kind in Via)
    header = ["repo", *SEVERITIES, "items", "exploitable", "resources"]
    return "\n".join(
        [
            f"{len(report.attributions)} finding(s) in {item_count} fix item(s) at "
            f"{cfg.min_severity} or above; attributed: {attributed}.",
            format_table(header, rows),
            "",
            "Fix status: items by what they need.",
            format_table(["repo", *FixStatus], status_rows),
        ]
    )


def _attribution_json(attribution: FindingAttribution) -> dict[str, Any]:
    match attribution:
        case Attributed(via=via, deployment=deployment, runner=runner):
            return {
                "via": via,
                "deployment": deployment,
                "runner": runner and {"name": runner.name},
            }
        case Unattributed():
            return {}
        case _ as unreachable:
            assert_never(unreachable)


def _finding_json(finding: Finding, attribution: FindingAttribution) -> dict[str, Any]:
    resource = finding.resource
    return {
        "arn": finding.arn,
        "title": finding.title,
        "installed_version": finding.installed_version,
        "package_manager": finding.package_manager,
        "first_observed": finding.first_observed.isoformat(),
        "resource": {
            "type": resource.type,
            "id": resource.id,
            "name": resource.name,
            "region": resource.region,
            "tags": dict(resource.tags),
        },
        **_attribution_json(attribution),
    }


def _item_json(item: FixItem, report: InspectorReport) -> dict[str, Any]:
    pr = item.pr
    return {
        "package": item.package,
        "ecosystem": item.ecosystem,
        "severity": item.severity,
        "fixed_in": item.fixed_in,
        "status": item.status,
        "main_versions": sorted(item.main_versions),
        "pr": pr and {"number": pr.number, "url": pr.html_url, "target": item.pr_target},
        "vulnerability_ids": item.vulnerability_ids,
        "exploit_available": item.exploit_available,
        "resources": item.resources,
        "findings": [
            _finding_json(finding, report.attributions[finding.arn]) for finding in item.findings
        ],
    }


def report_json(report: InspectorReport) -> dict[str, Any]:
    return {
        "via": {kind.value: report.via[kind] for kind in Via},
        "status": {status.value: report.status[status] for status in FixStatus},
        "repos": {
            repo: [_item_json(item, report) for item in items]
            for repo, items in report.by_repo.items()
        },
        "unattributed": {
            reason.value: [_item_json(item, report) for item in items]
            for reason, items in report.unattributed.items()
        },
    }


# --- nag: issues, Linear and the step summary


def _first(names: list[str], code: bool = True) -> str:
    shown = ", ".join(f"`{name}`" if code else name for name in names[:MAX_LISTED])
    more = len(names) - MAX_LISTED
    return shown + (f" and {more} more" if more > 0 else "")


def status_label(status: FixStatus) -> str:
    """What items with `status` need, in a word or two, for counts and table columns."""
    match status:
        case FixStatus.NEEDS_DEPLOY:
            return "redeploy"
        case FixStatus.NEEDS_PR_MERGE:
            return "merge PR"
        case FixStatus.NEEDS_FIX:
            return "upgrade"
        case FixStatus.NEEDS_OS_UPDATE:
            return "base image"
        case FixStatus.UNKNOWN:
            return "check"
        case _ as unreachable:
            assert_never(unreachable)


def _status_heading(status: FixStatus) -> str:
    match status:
        case FixStatus.NEEDS_DEPLOY:
            return "Redeploy: already fixed on the default branch"
        case FixStatus.NEEDS_PR_MERGE:
            return "Merge the fix PR, then redeploy"
        case FixStatus.NEEDS_FIX:
            return "Upgrade on the default branch"
        case FixStatus.NEEDS_OS_UPDATE:
            return "Use a newer base image or runtime"
        case FixStatus.UNKNOWN:
            return "Needs a person to look"
        case _ as unreachable:
            assert_never(unreachable)


def severity_icons(severities: Counter[str]) -> str:
    """Severity counts as icons, worst first, such as "🟥 1 critical · 🟧 12 high"."""
    return " · ".join(
        f"{SEVERITY_ICON[severity]} {severities[severity]} {severity}"
        for severity in SEVERITIES
        if severities[severity]
    )


def _version_change(item: FixItem) -> str:
    if not item.fixed_in:
        return "no fix yet"
    fixed = f"→ `{item.fixed_in}`"
    return f"{_first(sorted(item.main_versions))} {fixed}" if item.main_versions else fixed


def item_line(
    item: FixItem, due: str | None = None, step: bool = True, resources: bool = False
) -> str:
    """One fix item on one line: severity, package, version change and, when tracked, its due
    date. `step` adds what the item needs, for lists that aren't under its status heading."""
    fire = " 🔥" if item.exploit_available else ""
    parts = [f"- {SEVERITY_ICON[item.severity]} `{item.package}` {_version_change(item)}{fire}"]
    if item.status is FixStatus.NEEDS_PR_MERGE:
        assert item.pr is not None
        parts.append(f"merge [#{item.pr.number}]({item.pr.html_url})")
    elif step:
        parts.append(status_label(item.status))
    if resources:
        parts.append(f"on {_first(item.resources)}")
    if due:
        parts.append(due)
    return " · ".join(parts)


def _detail_line(item: FixItem) -> str:
    ids = _first(item.vulnerability_ids, code=False)
    return f"- `{item.package}`: {ids} · on {_first(item.resources)}"


def _collapsed(title: str, lines: list[str], linear: bool) -> list[str]:
    """A section that starts closed: Linear's `+++` toggle, or GitHub's `<details>`."""
    if linear:
        return ["", f"+++ {title}", "", *lines, "", "+++"]
    return ["", f"<details><summary>{title}</summary>", "", *lines, "", "</details>"]


def _due(tracked: TrackedItem, relative: bool) -> str:
    if not relative:
        return f"due {tracked.deadline:%b} {tracked.deadline.day}"
    if tracked.status is SlaStatus.OVERDUE:
        return f"**{-tracked.days_left}d overdue**"
    return f"due in {tracked.days_left}d"


def tracked_line(tracked: TrackedItem, relative: bool = True) -> str:
    return item_line(tracked.item, _due(tracked, relative))


def _by_status[T](
    entries: list[T], status_of: Callable[[T], FixStatus]
) -> list[tuple[FixStatus, list[T]]]:
    """Entries grouped by status, in `FixStatus` order, skipping empty groups."""
    groups = [(status, [e for e in entries if status_of(e) is status]) for status in FixStatus]
    return [(status, group) for status, group in groups if group]


def _summary(items: list[FixItem], what: str) -> str:
    """The bold lead line: how many packages, by severity, and the 🔥 legend when it's used."""
    severities = severity_icons(Counter(i.severity for i in items))
    line = f"**{len(items)} vulnerable package(s) {what}** · {severities}"
    return line + (" · 🔥 = known exploit" if any(i.exploit_available for i in items) else "")


def _item_lines(repo: InspectorRepo, relative: bool, linear: bool) -> list[str]:
    shown = repo.items[:MAX_ITEMS]
    lines: list[str] = []
    for status, group in _by_status(shown, lambda t: t.item.status):
        lines += ["", f"**{_status_heading(status)} ({len(group)})**"]
        lines += [item_line(t.item, _due(t, relative), step=False) for t in group]
    if len(repo.items) > MAX_ITEMS:
        more = len(repo.items) - MAX_ITEMS
        lines += [
            "",
            f"…and {more} more. `vulgard report --topic inspector --repo {repo.repo}` lists "
            "them all.",
        ]
    details = [_detail_line(t.item) for t in shown]
    return lines + _collapsed("CVEs and where they run", details, linear)


def render_body(
    repo: InspectorRepo, config: Config, state: TrackingState[InspectorMemory], now: datetime
) -> str:
    severities = severities_at_least(config.inspector.min_severity)
    days = ", ".join(f"{config.sla_days[s]}d for {s}" for s in severities)
    about = [f"Found by Amazon Inspector. Due {days} after first listed."]
    if repo.owners:
        about.append(f"Owners: {' '.join(repo.owners)}.")
    if state.linear:
        about.append(f"Linear: [{state.linear.identifier}]({state.linear.url}).")
    lines = [_summary([t.item for t in repo.items], "running in AWS"), "", " ".join(about)]
    lines += _item_lines(repo, relative=True, linear=False)
    lines += [
        "",
        f"_Updated by vulgard {now:%Y-%m-%d %H:%M} UTC. Closes itself once Inspector stops "
        "finding these. Edits are overwritten._",
        state.to_comment(),
    ]
    return "\n".join(lines)


def repo_description(repo: InspectorRepo) -> str:
    return "\n".join(
        [
            _summary([t.item for t in repo.items], "running in AWS"),
            *_item_lines(repo, relative=False, linear=True),
            "",
            "_Synced by vulgard from Amazon Inspector. Edits are overwritten._",
        ]
    )


def _status_cells(repo: InspectorRepo) -> list[str]:
    statuses = repo.statuses
    return [str(len(repo.items)), str(len(repo.overdue)), *(str(statuses[s]) for s in FixStatus)]


def parent_description(repos: list[InspectorRepo]) -> str:
    """A team's parent issue: one row per repo with items, most overdue first."""
    ranked = sorted(repos, key=lambda r: (-len(r.overdue), -len(r.items), r.repo))
    header = ["Repo", "Packages", "Overdue", *(status_label(s).capitalize() for s in FixStatus)]
    total = InspectorRepo("Total", [i for r in repos for i in r.items], github=False)
    rows = [[r.repo, *_status_cells(r)] for r in ranked]
    rows.append(["**Total**", *_status_cells(total)])
    return "\n".join(
        [
            "Vulnerable packages Amazon Inspector found running in AWS, by repo. Each repo's "
            "sub-issue lists its packages.",
            "",
            "| " + " | ".join(header) + " |",
            "|" + "---|" * len(header),
            *("| " + " | ".join(row) + " |" for row in rows),
            "",
            "_Synced by vulgard. Closes itself once no repo has packages left._",
        ]
    )


def _reason_heading(reason: Reason) -> str:
    match reason:
        case Reason.SHARED_ASSET_REPOSITORY:
            return "Image in the shared asset repository"
        case Reason.RUNNERS_IN_SEVERAL_REPOS:
            return "Image run by several repos"
        case Reason.NO_DEPLOYMENT_TAGS:
            return "No repo or deployment tags"
        case Reason.DEPLOYMENT_NOT_FOUND:
            return "Deployment not found"
        case Reason.DEPLOYMENT_UNATTRIBUTED:
            return "Deployment with no repo"
        case _ as unreachable:
            assert_never(unreachable)


def _why_unattributed(reason: Reason) -> str:
    match reason:
        case Reason.SHARED_ASSET_REPOSITORY:
            return (
                "The image is in a repository every app in the account shares, and no ECS task "
                "definition that runs it names a repo."
            )
        case Reason.RUNNERS_IN_SEVERAL_REPOS:
            return (
                "The image is in a repository every app shares, and the ECS task definitions "
                "that run it belong to different repos. Check which repo should own the fix."
            )
        case Reason.NO_DEPLOYMENT_TAGS:
            return (
                "The resource has no repo tag and no deployment tags. Tag it, or the stack that "
                "creates it, `vulgard:repo=<repo>`."
            )
        case Reason.DEPLOYMENT_NOT_FOUND:
            return (
                "The resource's tags name a deployment vulgard's scan didn't find, for example a "
                "nested stack or one in a region outside `deployments.aws.regions`."
            )
        case Reason.DEPLOYMENT_UNATTRIBUTED:
            return (
                "vulgard found the deployment but no repo for it. Tag the stack `github:repo` "
                "when it deploys."
            )
        case _ as unreachable:
            assert_never(unreachable)


def unattributed_description(unattributed: Mapping[Reason, list[FixItem]]) -> str:
    every = [item for items in unattributed.values() for item in items]
    lines = [
        _summary(every, "with no repo"),
        "",
        "vulgard can't tell which repo deployed these, so no team tracks them. They move to "
        "their repo's issue once attributed.",
    ]
    shown: list[FixItem] = []
    for reason, items in unattributed.items():
        lines += ["", f"### {_reason_heading(reason)} ({len(items)})", _why_unattributed(reason)]
        for status, group in _by_status(items[:MAX_ITEMS], lambda item: item.status):
            lines += ["", f"**{_status_heading(status)} ({len(group)})**"]
            lines += [item_line(item, step=False, resources=True) for item in group]
        if len(items) > MAX_ITEMS:
            lines += ["", f"…and {len(items) - MAX_ITEMS} more."]
        shown += items[:MAX_ITEMS]
    lines += _collapsed("CVEs", [_detail_line(item) for item in shown], linear=True)
    lines += ["", "_Synced by vulgard from Amazon Inspector. Edits are overwritten._"]
    return "\n".join(lines)


def render_summary(
    repos: list[InspectorRepo], unattributed: Mapping[Reason, list[FixItem]], cfg: InspectorConfig
) -> str:
    """Markdown for the workflow step summary: counts per repo, no resource names."""
    title = "## Vulnerable packages running in AWS"
    ranked = sorted(
        (r for r in repos if r.items), key=lambda r: (-len(r.overdue), -len(r.items), r.repo)
    )
    if not ranked and not unattributed:
        return f"{title}\n\nAmazon Inspector finds nothing at {cfg.min_severity} or above."
    header = ["Repo", "Tracked in", "Items", "Overdue", *FixStatus]
    rows = [
        [r.repo, "GitHub, Linear" if r.github else "Linear", *_status_cells(r)] for r in ranked
    ]
    for reason, items in unattributed.items():
        statuses = Counter(item.status for item in items)
        cells = [str(len(items)), "-", *(str(statuses[s]) for s in FixStatus)]
        rows.append([f"unattributed: {reason}", "Linear", *cells])
    return "\n".join(
        [
            title,
            "",
            "| " + " | ".join(header) + " |",
            "|" + "---|" * len(header),
            *("| " + " | ".join(row) + " |" for row in rows),
        ]
    )
