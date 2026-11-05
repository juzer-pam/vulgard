"""Everything the inspector topic prints: the `report --topic inspector` table and JSON."""

from __future__ import annotations

from collections import Counter
from typing import Any, assert_never

from .config import SEVERITIES, InspectorConfig
from .inspector import (
    Attributed,
    Finding,
    FindingAttribution,
    FixItem,
    FixStatus,
    InspectorReport,
    Unattributed,
    Via,
)
from .render import format_table


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
                "runner": runner and {"kind": runner.kind, "name": runner.name},
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
