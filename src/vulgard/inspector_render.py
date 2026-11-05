"""Everything the inspector topic says: the `report --topic inspector` table and JSON, and for
`nag` the issue body, the Linear descriptions, comment lines and the step summary."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
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
        case Attributed(via=via, deployment=deployment):
            return {"via": via, "deployment": deployment}
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
            return "fixed on the default branch, so redeploy"
        case FixStatus.NEEDS_PR_MERGE:
            assert item.pr is not None
            return f"merge [#{item.pr.number}]({item.pr.html_url}), then redeploy"
        case FixStatus.NEEDS_FIX:
            return "upgrade the package on the default branch"
        case FixStatus.NEEDS_OS_UPDATE:
            return "an operating system package: use a newer base image or runtime"
        case FixStatus.UNKNOWN:
            return "vulgard can't tell what it needs, so a person has to look"
        case _ as unreachable:
            assert_never(unreachable)


def item_line(item: FixItem, due: str | None = None) -> str:
    """One fix item: what it is, what it needs next, where it runs and, when tracked, its due
    date."""
    ecosystem = item.ecosystem or item.findings[0].package_manager
    parts = [
        f"- {SEVERITY_ICON[item.severity]} **{item.severity}** `{item.package}` ({ecosystem}): "
        f"**{item.status}**, {_next_step(item)}"
    ]
    if item.main_versions:
        parts.append(f"default branch has {_first(sorted(item.main_versions))}")
    parts.append(f"fixed in `{item.fixed_in}`" if item.fixed_in else "no fixed version known")
    if item.exploit_available:
        parts.append("🔥 exploit available")
    parts.append(", ".join(item.vulnerability_ids[:MAX_LISTED]))
    parts.append(f"on {_first(item.resources)}")
    if due:
        parts.append(due)
    return " · ".join(parts)


def _due(tracked: TrackedItem, relative: bool) -> str:
    if not relative:
        return f"due {tracked.deadline:%Y-%m-%d}"
    if tracked.status is SlaStatus.OVERDUE:
        return f"**{-tracked.days_left}d overdue**"
    return f"due in {tracked.days_left}d"


def tracked_line(tracked: TrackedItem, relative: bool = True) -> str:
    return item_line(tracked.item, _due(tracked, relative))


def _item_lines(repo: InspectorRepo, relative: bool) -> list[str]:
    lines = ["", f"### Fix items ({len(repo.items)})"]
    lines += [tracked_line(i, relative) for i in repo.items[:MAX_ITEMS]]
    if len(repo.items) > MAX_ITEMS:
        more = len(repo.items) - MAX_ITEMS
        lines.append(
            f"- …and {more} more. `vulgard report --topic inspector --repo {repo.repo}` lists "
            "them all."
        )
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


def _why_unattributed(reason: Reason) -> str:
    match reason:
        case Reason.SHARED_ASSET_REPOSITORY:
            return (
                "The image is in a repository every app in the account shares, so its name "
                "can't say whose it is."
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
        lines += ["", f"### {reason} ({len(items)})", _why_unattributed(reason), ""]
        lines += [item_line(item) for item in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            lines.append(f"- …and {len(items) - MAX_ITEMS} more.")
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
