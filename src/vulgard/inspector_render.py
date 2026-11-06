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
from .render import SEVERITY_ICON, format_table, severity_summary

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


def _first(names: list[str]) -> str:
    shown = ", ".join(f"`{name}`" for name in names[:MAX_LISTED])
    more = len(names) - MAX_LISTED
    return shown + (f" and {more} more" if more > 0 else "")


def _next_step(item: FixItem) -> str:
    match item.status:
        case FixStatus.NEEDS_DEPLOY:
            return "redeploy"
        case FixStatus.NEEDS_PR_MERGE:
            assert item.pr is not None
            return f"merge [#{item.pr.number}]({item.pr.html_url}), then redeploy"
        case FixStatus.NEEDS_FIX:
            return "upgrade the package on the default branch"
        case FixStatus.NEEDS_OS_UPDATE:
            return "use a newer base image or runtime"
        case FixStatus.UNKNOWN:
            return "needs a person to look"
        case _ as unreachable:
            assert_never(unreachable)


def status_heading(status: FixStatus) -> str:
    match status:
        case FixStatus.NEEDS_DEPLOY:
            return "Fixed on the default branch: redeploy"
        case FixStatus.NEEDS_PR_MERGE:
            return "Fix PR open: merge it, then redeploy"
        case FixStatus.NEEDS_FIX:
            return "Upgrade the package on the default branch"
        case FixStatus.NEEDS_OS_UPDATE:
            return "Operating system packages: use a newer base image or runtime"
        case FixStatus.UNKNOWN:
            return "vulgard can't tell what these need, so a person has to look"
        case _ as unreachable:
            assert_never(unreachable)


def status_count(status: FixStatus, count: int) -> str:
    """A count of items with `status`, for Slack digests."""
    match status:
        case FixStatus.NEEDS_DEPLOY:
            return f"{count} to redeploy"
        case FixStatus.NEEDS_PR_MERGE:
            return f"{count} with a fix PR to merge"
        case FixStatus.NEEDS_FIX:
            return f"{count} to upgrade"
        case FixStatus.NEEDS_OS_UPDATE:
            return f"{count} needing a newer base image"
        case FixStatus.UNKNOWN:
            return f"{count} for a person to check"
        case _ as unreachable:
            assert_never(unreachable)


def item_line(item: FixItem, due: str | None = None, step: bool = True) -> str:
    """One fix item as a bullet: what it is, the fix and, when tracked, its due date, with its
    vulnerability ids and where it runs on a nested bullet. `step` adds what the item needs
    next, for lists that aren't already under its status heading."""
    ecosystem = item.ecosystem or item.findings[0].package_manager
    parts = [f"- {SEVERITY_ICON[item.severity]} **{item.severity}** `{item.package}` ({ecosystem})"]
    if item.main_versions:
        parts.append(f"default branch has {_first(sorted(item.main_versions))}")
    parts.append(f"fixed in `{item.fixed_in}`" if item.fixed_in else "no fixed version known")
    if item.exploit_available:
        parts.append("🔥 exploit available")
    if step:
        parts.append(_next_step(item))
    elif item.status is FixStatus.NEEDS_PR_MERGE:
        assert item.pr is not None
        parts.append(f"merge [#{item.pr.number}]({item.pr.html_url})")
    if due:
        parts.append(due)
    details = [", ".join(item.vulnerability_ids[:MAX_LISTED]), f"on {_first(item.resources)}"]
    return " · ".join(parts) + "\n  - " + " · ".join(details)


def _due(tracked: TrackedItem, relative: bool) -> str:
    if not relative:
        return f"due {tracked.deadline:%Y-%m-%d}"
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


def _item_lines(repo: InspectorRepo, relative: bool) -> list[str]:
    shown = repo.items[:MAX_ITEMS]
    lines: list[str] = []
    for status, group in _by_status(shown, lambda t: t.item.status):
        lines += ["", f"### {status_heading(status)} ({len(group)})", ""]
        lines += [item_line(t.item, _due(t, relative), step=False) for t in group]
    if len(repo.items) > MAX_ITEMS:
        more = len(repo.items) - MAX_ITEMS
        lines += [
            "",
            f"…and {more} more. `vulgard report --topic inspector --repo {repo.repo}` lists "
            "them all.",
        ]
    return lines


def _counts(repo: InspectorRepo) -> str:
    return severity_summary(Counter(i.item.severity for i in repo.items))


def render_body(
    repo: InspectorRepo, config: Config, state: TrackingState[InspectorMemory], now: datetime
) -> str:
    severities = severities_at_least(config.inspector.min_severity)
    days = ", ".join(f"{config.sla_days[s]} for {s}" for s in severities)
    lines = [
        "Amazon Inspector found vulnerable packages in what this repo runs in AWS. Each item is "
        "one package: one upgrade and a redeploy fix every finding listed under it. An item is "
        f"due a number of days after vulgard first listed it here: {days}.",
    ]
    if repo.owners:
        lines += ["", f"Owners: {' '.join(repo.owners)}"]
    if state.linear:
        lines += ["", f"Tracked in Linear: [{state.linear.identifier}]({state.linear.url})"]
    lines += _item_lines(repo, relative=True)
    lines += [
        "",
        "---",
        f"_Updated by vulgard on {now:%Y-%m-%d %H:%M} UTC. This issue closes itself once "
        "Inspector no longer finds these packages. Please don't edit it by hand; changes are "
        "overwritten._",
        state.to_comment(),
    ]
    return "\n".join(lines)


def repo_description(repo: InspectorRepo) -> str:
    return "\n".join(
        [
            f"**{repo.repo}** has {len(repo.items)} vulnerable package(s) running in AWS: "
            f"{_counts(repo)}.",
            *_item_lines(repo, relative=False),
            "",
            "---",
            "_Synced by vulgard from Amazon Inspector. The description, priority and due date are "
            "overwritten on each run, and the issue closes itself once Inspector no longer finds "
            "these packages._",
        ]
    )


def _status_cells(repo: InspectorRepo) -> list[str]:
    statuses = repo.statuses
    return [str(len(repo.items)), str(len(repo.overdue)), *(str(statuses[s]) for s in FixStatus)]


def parent_description(repos: list[InspectorRepo]) -> str:
    """A team's parent issue: one row per repo with items, most overdue first."""
    ranked = sorted(repos, key=lambda r: (-len(r.overdue), -len(r.items), r.repo))
    header = ["Repo", "Items", "Overdue", *FixStatus]
    total = InspectorRepo("Total", [i for r in repos for i in r.items], github=False)
    rows = [[r.repo, *_status_cells(r)] for r in ranked]
    rows.append(["**Total**", *_status_cells(total)])
    return "\n".join(
        [
            "Vulnerable packages that Amazon Inspector found running in AWS, in this team's "
            "repos. Each repo has a sub-issue with its fix items and their due dates.",
            "",
            "| " + " | ".join(header) + " |",
            "|" + "---|" * len(header),
            *("| " + " | ".join(row) + " |" for row in rows),
            "",
            "---",
            "_Synced by vulgard. This issue closes itself once none of the team's repos have "
            "items._",
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
    lines = [
        "Amazon Inspector found these vulnerable packages running in AWS, but vulgard can't tell "
        "which repo deployed them, so no team is tracking them. Once a resource can be "
        "attributed, its items move to their repo's issue.",
    ]
    for reason, items in unattributed.items():
        heading = f"### {_reason_heading(reason)} ({len(items)})"
        lines += ["", heading, "", _why_unattributed(reason)]
        for status, group in _by_status(items[:MAX_ITEMS], lambda item: item.status):
            lines += ["", f"**{status_heading(status)} ({len(group)})**", ""]
            lines += [item_line(item, step=False) for item in group]
        if len(items) > MAX_ITEMS:
            lines += ["", f"…and {len(items) - MAX_ITEMS} more."]
    lines += [
        "",
        "---",
        "_Synced by vulgard from Amazon Inspector. This issue closes itself once every finding "
        "has a repo or is gone._",
    ]
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
