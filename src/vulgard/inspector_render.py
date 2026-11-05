"""Everything the inspector topic prints: the `report --topic inspector` table and JSON."""

from __future__ import annotations

from collections import Counter
from typing import Any, assert_never

from .config import SEVERITIES, InspectorConfig
from .inspector import (
    Attributed,
    Coverage,
    CoverageMatch,
    Finding,
    FindingAttribution,
    FindingGroup,
    InspectorReport,
    Unattributed,
    Via,
)
from .render import format_table

LINEAR_SKIPPED = (
    "Linear issues were not checked: they need inspector.linear_labels and a Linear API key."
)


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


def _coverage_row(label: str, groups: list[FindingGroup]) -> list[str]:
    by_status = Counter(group.coverage.status for group in groups)
    return [label, *(str(by_status[status]) for status in Coverage)]


def report_text(report: InspectorReport, cfg: InspectorConfig, linear_checked: bool) -> str:
    """One row per repo, worst first, then one per reason findings couldn't be attributed.
    Severity, exploitable and fixable count groups; resources counts distinct resources. A second
    table, in the same row order, counts groups by coverage status."""
    sections = [*report.by_repo.values(), *report.unattributed.values()]
    group_count = sum(len(groups) for groups in sections)
    if not group_count:
        return f"No Inspector findings at {cfg.min_severity} or above."
    ordered = sorted(report.by_repo.items(), key=_worst_first)
    ordered += [
        (f"unattributed: {reason}", groups) for reason, groups in report.unattributed.items()
    ]
    rows = [_row(label, groups) for label, groups in ordered]
    coverage_rows = [_coverage_row(label, groups) for label, groups in ordered]
    attributed = ", ".join(f"{report.via[kind]} by {kind}" for kind in Via)
    header = ["repo", *SEVERITIES, "exploitable", "fixable", "resources"]
    return "\n".join(
        [
            f"{len(report.attributions)} finding(s) in {group_count} group(s) at "
            f"{cfg.min_severity} or above; attributed: {attributed}.",
            format_table(header, rows),
            "",
            "Coverage: groups by what already tracks them.",
            *([] if linear_checked else [LINEAR_SKIPPED]),
            format_table(["repo", *Coverage], coverage_rows),
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


def _coverage_json(match: CoverageMatch) -> dict[str, Any]:
    alert, pr = match.alert, match.pr
    return {
        "coverage": match.status,
        "alert": alert
        and {
            "number": alert.number,
            "state": "fixed" if match.status is Coverage.FIXED_NOT_DEPLOYED else "open",
            "url": alert.html_url,
        },
        "pr": pr and {"number": pr.number, "url": pr.html_url},
        "linear_issues": [
            {"identifier": issue.identifier, "url": issue.url} for issue in match.linear_issues
        ],
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
        **_coverage_json(group.coverage),
        "findings": [
            _finding_json(finding, report.attributions[finding.arn]) for finding in group.findings
        ],
    }


def report_json(report: InspectorReport) -> dict[str, Any]:
    return {
        "via": {kind.value: report.via[kind] for kind in Via},
        "coverage": {status.value: report.coverage[status] for status in Coverage},
        "repos": {
            repo: [_group_json(group, report) for group in groups]
            for repo, groups in report.by_repo.items()
        },
        "unattributed": {
            reason.value: [_group_json(group, report) for group in groups]
            for reason, groups in report.unattributed.items()
        },
    }
