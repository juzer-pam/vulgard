"""Everything the inspector topic prints: the `report --topic inspector` table and JSON."""

from __future__ import annotations

from collections import Counter
from typing import Any, assert_never

from .config import SEVERITIES, InspectorConfig
from .inspector import (
    Attributed,
    Finding,
    FindingAttribution,
    FindingGroup,
    InspectorReport,
    Unattributed,
    Via,
)
from .render import format_table


def _severity_counts(groups: list[FindingGroup]) -> list[int]:
    by_severity = Counter(group.severity for group in groups)
    return [by_severity[severity] for severity in SEVERITIES]


def _row(label: str, groups: list[FindingGroup]) -> list[str]:
    resources = {finding.resource.id for group in groups for finding in group.findings}
    return [
        label,
        *(str(count) for count in _severity_counts(groups)),
        str(sum(group.exploit_available for group in groups)),
        str(sum(group.fix_available for group in groups)),
        str(len(resources)),
    ]


def _worst_first(item: tuple[str, list[FindingGroup]]) -> tuple[list[int], str]:
    repo, groups = item
    return [-count for count in _severity_counts(groups)], repo


def report_text(report: InspectorReport, cfg: InspectorConfig) -> str:
    """One row per repo, worst first, then one per reason findings couldn't be attributed.
    Severity, exploitable and fixable count groups; resources counts distinct resources."""
    sections = [*report.by_repo.values(), *report.unattributed.values()]
    group_count = sum(len(groups) for groups in sections)
    if not group_count:
        return f"No Inspector findings at {cfg.min_severity} or above."
    rows = [_row(repo, groups) for repo, groups in sorted(report.by_repo.items(), key=_worst_first)]
    for reason, groups in report.unattributed.items():
        rows.append(_row(f"unattributed: {reason}", groups))
    attributed = ", ".join(f"{report.via[kind]} by {kind}" for kind in Via)
    header = ["repo", *SEVERITIES, "exploitable", "fixable", "resources"]
    return "\n".join(
        [
            f"{len(report.attributions)} finding(s) in {group_count} group(s) at "
            f"{cfg.min_severity} or above; attributed: {attributed}.",
            format_table(header, rows),
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


def _group_json(group: FindingGroup, report: InspectorReport) -> dict[str, Any]:
    return {
        "vulnerability_id": group.vulnerability_id,
        "package": group.package,
        "severity": group.severity,
        "exploit_available": group.exploit_available,
        "fix_available": group.fix_available,
        "fixed_in": group.fixed_in,
        "resources": group.resources,
        "findings": [
            _finding_json(finding, report.attributions[finding.arn]) for finding in group.findings
        ],
    }


def report_json(report: InspectorReport) -> dict[str, Any]:
    return {
        "via": {kind.value: report.via[kind] for kind in Via},
        "repos": {
            repo: [_group_json(group, report) for group in groups]
            for repo, groups in report.by_repo.items()
        },
        "unattributed": {
            reason.value: [_group_json(group, report) for group in groups]
            for reason, groups in report.unattributed.items()
        },
    }
