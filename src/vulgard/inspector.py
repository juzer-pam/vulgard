"""The inspector topic's model and policy: Amazon Inspector package vulnerabilities, each
attributed to the repo that deployed the vulnerable resource.

Inspector names a resource (a Lambda function, an ECR image, an EC2 instance), never a repo. The
repo is the first of these that answers:

    1. a repo tag on the resource
    2. the estate deployment the resource belongs to (see `estate.py`), found through its
       CloudFormation stack, SST app and stage, or Amplify app and branch tags

Findings of one vulnerability in one package, across resources, are reported as one group. Each
group is then checked against what already tracks it (see `cover`).

This module is pure. The parser is `aws.sight_finding`, the live source is `aws.AwsInspector`,
and the printed tables and JSON are in `inspector_render.py`.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Protocol, assert_never

from .config import SEVERITIES, InspectorConfig, severities_at_least
from .estate import (
    REPO_TAGS,
    AmplifyBranch,
    CfnStack,
    Deployment,
    NativeRef,
    SstStage,
    VercelProject,
    repo_name,
)
from .linear import LinearIssue
from .policy import Alert, DependabotPR, RepoReport

STACK_NAME_TAG = "aws:cloudformation:stack-name"
SERVERLESS_REPOSITORY_RE = re.compile(r"^serverless-(.+)$")
SHARED_ASSET_REPOSITORIES = ("sst-asset", "cdk-*-container-assets-*")  # one per account, all apps
OS_PACKAGE_MANAGER = "OS"


class ResourceType(StrEnum):
    LAMBDA = "lambda"
    ECR_IMAGE = "ecr_image"
    EC2 = "ec2"


@dataclass(frozen=True)
class InspectorResource:
    type: ResourceType
    id: str
    name: str  # function name, ECR repository name or EC2 instance id
    region: str
    tags: Mapping[str, str]  # ECR images have none


@dataclass(frozen=True)
class Finding:
    """A package vulnerability. Inspector may list several vulnerable packages on one finding;
    only the first is kept."""

    arn: str
    vulnerability_id: str
    severity: str  # one of config.SEVERITIES
    package: str
    package_manager: str
    installed_version: str
    fixed_in: str | None
    fix_available: bool
    exploit_available: bool
    first_observed: datetime
    title: str
    resource: InspectorResource


class InspectorSource(Protocol):
    """Parses Inspector's ListFindings into findings; nothing raw escapes."""

    def findings(self) -> list[Finding]: ...


# --- attribution


class Via(StrEnum):
    TAG = "tag"
    DEPLOYMENT = "deployment"


class Reason(StrEnum):
    SHARED_ASSET_REPOSITORY = "shared_asset_repository"
    NO_DEPLOYMENT_TAGS = "no_deployment_tags"
    DEPLOYMENT_NOT_FOUND = "deployment_not_found"
    DEPLOYMENT_UNATTRIBUTED = "deployment_unattributed"


@dataclass(frozen=True)
class Attributed:
    repo: str
    via: Via
    deployment: str | None = None

    def __post_init__(self) -> None:
        assert (self.deployment is not None) == (self.via is Via.DEPLOYMENT)


@dataclass(frozen=True)
class Unattributed:
    reason: Reason


type FindingAttribution = Attributed | Unattributed

type DeploymentKey = tuple[str, ...]


def deployment_key(native: NativeRef) -> DeploymentKey | None:
    """The identity Inspector's resource tags can name a deployment by."""
    match native:
        case CfnStack(region=region, name=name):
            return ("cfn", region, name)
        case SstStage(region=region, app=app, stage=stage):
            return ("sst", region, app, stage)
        case AmplifyBranch(region=region, app_id=app_id, branch=branch):
            return ("amplify", region, app_id, branch)
        case VercelProject():
            return None
        case _ as unreachable:
            assert_never(unreachable)


def index_deployments(deployments: Iterable[Deployment]) -> dict[DeploymentKey, Deployment]:
    table: dict[DeploymentKey, Deployment] = {}
    for deployment in deployments:
        key = deployment_key(deployment.sighting.native)
        if key is not None:
            table.setdefault(key, deployment)
    return table


def candidate_keys(resource: InspectorResource) -> list[DeploymentKey]:
    """The deployments a resource says it belongs to, in order of trust."""
    tags, region = resource.tags, resource.region
    keys: list[DeploymentKey] = []
    if stack := tags.get(STACK_NAME_TAG):
        keys.append(("cfn", region, stack))
    if (app := tags.get("sst:app")) and (stage := tags.get("sst:stage")):
        keys.append(("sst", region, app, stage))
    if (app_id := tags.get("amplify:app-id")) and (branch := tags.get("amplify:branch-name")):
        keys.append(("amplify", region, app_id, branch))
    if resource.type is ResourceType.ECR_IMAGE:
        # ECR images carry no tags. Serverless names its repository `serverless-<service>-<stage>`
        # and the stack `<service>-<stage>`.
        if serverless := SERVERLESS_REPOSITORY_RE.match(resource.name):
            keys.append(("cfn", region, serverless[1]))
    return keys


def _matches(resource: InspectorResource, pattern: str) -> bool:
    names = (resource.name, resource.tags.get(STACK_NAME_TAG, ""))
    return any(fnmatch.fnmatch(name, pattern) for name in names)


def _is_shared_asset_repository(resource: InspectorResource) -> bool:
    return resource.type is ResourceType.ECR_IMAGE and any(
        fnmatch.fnmatch(resource.name, pattern) for pattern in SHARED_ASSET_REPOSITORIES
    )


def attribute(
    finding: Finding,
    deployments_by_key: Mapping[DeploymentKey, Deployment],
) -> FindingAttribution:
    """The first rule that answers wins. A deployment found through the resource's tags is final
    even when it has no repo."""
    resource = finding.resource
    for tag in REPO_TAGS:
        if resource.tags.get(tag):
            return Attributed(repo_name(resource.tags[tag]), Via.TAG)
    keys = candidate_keys(resource)
    deployment = next((deployments_by_key[key] for key in keys if key in deployments_by_key), None)
    if deployment is not None:
        if deployment.repo:
            return Attributed(deployment.repo, Via.DEPLOYMENT, deployment.name)
        return Unattributed(Reason.DEPLOYMENT_UNATTRIBUTED)
    if _is_shared_asset_repository(resource):
        return Unattributed(Reason.SHARED_ASSET_REPOSITORY)
    return Unattributed(Reason.DEPLOYMENT_NOT_FOUND if keys else Reason.NO_DEPLOYMENT_TAGS)


# --- coverage


class Coverage(StrEnum):
    DEPENDABOT_ALERT = "dependabot_alert"
    DEPENDABOT_PR = "dependabot_pr"
    FIXED_NOT_DEPLOYED = "fixed_not_deployed"
    LINEAR_ISSUE = "linear_issue"
    UNTRACKED_OS_PACKAGE = "untracked_os_package"
    UNTRACKED = "untracked"


@dataclass(frozen=True)
class Tracking:
    """What vulgard found for one repo."""

    open_alerts: tuple[Alert, ...]
    fixed_alerts: tuple[Alert, ...]
    prs: tuple[DependabotPR, ...]
    linear_issues: tuple[LinearIssue, ...]  # open, labelled, and naming the repo in the title


NO_TRACKING = Tracking((), (), (), ())


@dataclass(frozen=True)
class CoverageMatch:
    status: Coverage
    alert: Alert | None = None  # DEPENDABOT_ALERT and FIXED_NOT_DEPLOYED only
    pr: DependabotPR | None = None  # DEPENDABOT_PR, or the DEPENDABOT_ALERT's fix PR
    linear_issues: tuple[LinearIssue, ...] = ()  # LINEAR_ISSUE only

    def __post_init__(self) -> None:
        assert (self.alert is not None) == (
            self.status in (Coverage.DEPENDABOT_ALERT, Coverage.FIXED_NOT_DEPLOYED)
        )
        assert self.pr is not None or self.status is not Coverage.DEPENDABOT_PR
        assert self.pr is None or self.status in (Coverage.DEPENDABOT_PR, Coverage.DEPENDABOT_ALERT)
        assert bool(self.linear_issues) == (self.status is Coverage.LINEAR_ISSUE)


def names_repo(title: str, repo: str) -> bool:
    """Whether `title` names `repo` as a whole word. Repo names contain hyphens and dots, so
    `payments` is not named by a title that says `payments-api`."""
    return re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(repo)}(?![A-Za-z0-9_.-])", title) is not None


def build_tracking(
    reports: Mapping[str, RepoReport],
    fixed_alerts: Iterable[Alert],
    issues: Iterable[LinearIssue],
) -> dict[str, Tracking]:
    """Pure. `reports` are from `vulns.collect`, with Dependabot PRs already linked to alerts."""
    fixed: defaultdict[str, list[Alert]] = defaultdict(list)
    for alert in fixed_alerts:
        fixed[alert.repo].append(alert)
    return {
        repo: Tracking(
            open_alerts=tuple(report.alerts),
            fixed_alerts=tuple(fixed[repo]),
            prs=tuple(report.dependabot_prs),
            linear_issues=tuple(issue for issue in issues if names_repo(issue.title, repo)),
        )
        for repo, report in reports.items()
    }


def _names_vulnerability(alert: Alert, vulnerability_id: str) -> bool:
    return vulnerability_id.lower() in {(alert.cve_id or "").lower(), alert.ghsa_id.lower()}


def cover(group: FindingGroup, tracking: Tracking) -> CoverageMatch:
    """The first thing that already tracks the group, in the order of `Coverage`."""
    for alert in tracking.open_alerts:
        if _names_vulnerability(alert, group.vulnerability_id):
            return CoverageMatch(Coverage.DEPENDABOT_ALERT, alert=alert, pr=alert.fix_pr)
    package = group.package.lower()
    pr = next((pr for pr in tracking.prs if package in pr.packages), None)
    if pr is not None:
        return CoverageMatch(Coverage.DEPENDABOT_PR, pr=pr)
    for alert in tracking.fixed_alerts:
        if _names_vulnerability(alert, group.vulnerability_id):
            return CoverageMatch(Coverage.FIXED_NOT_DEPLOYED, alert=alert)
    if tracking.linear_issues:
        return CoverageMatch(Coverage.LINEAR_ISSUE, linear_issues=tracking.linear_issues)
    if any(finding.package_manager == OS_PACKAGE_MANAGER for finding in group.findings):
        return CoverageMatch(Coverage.UNTRACKED_OS_PACKAGE)
    return CoverageMatch(Coverage.UNTRACKED)


# --- grouping and the report


@dataclass(frozen=True)
class FindingGroup:
    """One vulnerability in one package, across every resource that has it. `severity` is the
    highest of its findings, `exploit_available` is true if any finding has an exploit, and
    `fixed_in` is the first version a finding names. `coverage` starts as untracked and is set
    by `cover` once the group exists."""

    vulnerability_id: str
    package: str
    severity: str
    exploit_available: bool
    fixed_in: str | None
    findings: tuple[Finding, ...]
    coverage: CoverageMatch = CoverageMatch(Coverage.UNTRACKED)

    @property
    def resources(self) -> list[str]:
        return sorted({finding.resource.name for finding in self.findings})

    @property
    def fix_available(self) -> bool:
        return any(finding.fix_available for finding in self.findings)


def _group(findings: list[Finding], tracking: Tracking) -> FindingGroup:
    group = FindingGroup(
        vulnerability_id=findings[0].vulnerability_id,
        package=findings[0].package,
        severity=min((finding.severity for finding in findings), key=SEVERITIES.index),
        exploit_available=any(finding.exploit_available for finding in findings),
        fixed_in=next((finding.fixed_in for finding in findings if finding.fixed_in), None),
        findings=tuple(findings),
    )
    return replace(group, coverage=cover(group, tracking))


def group_findings(findings: Iterable[Finding], tracking: Tracking) -> list[FindingGroup]:
    """Most severe first, then the widest."""
    buckets: defaultdict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        buckets[(finding.vulnerability_id, finding.package)].append(finding)
    return sorted(
        (_group(bucket, tracking) for bucket in buckets.values()),
        key=lambda group: (
            SEVERITIES.index(group.severity),
            -len(group.resources),
            group.vulnerability_id,
            group.package,
        ),
    )


@dataclass(frozen=True)
class InspectorReport:
    by_repo: dict[str, list[FindingGroup]]
    unattributed: dict[Reason, list[FindingGroup]]
    attributions: dict[str, FindingAttribution]  # finding ARN -> how it was attributed

    @property
    def coverage(self) -> Counter[Coverage]:
        groups = [*self.by_repo.values(), *self.unattributed.values()]
        return Counter(group.coverage.status for repo_groups in groups for group in repo_groups)

    @property
    def via(self) -> Counter[Via]:
        return Counter(
            attribution.via
            for attribution in self.attributions.values()
            if isinstance(attribution, Attributed)
        )


def build_report(
    findings: Iterable[Finding],
    deployments: Iterable[Deployment],
    cfg: InspectorConfig,
    only: set[str] | None,
    tracking: Mapping[str, Tracking],
) -> InspectorReport:
    """Pure. Drops findings below `min_severity` and `ignore` matches, attributes the rest, and
    groups them. `only` (from --repo) keeps just those repos and the unattributed buckets go,
    as in `stale.survey(scoped=True)`. `tracking` is by repo; unattributed groups and repos missing
    from it are checked against nothing."""
    table = index_deployments(deployments)
    wanted = severities_at_least(cfg.min_severity)
    attributed = [
        (finding, attribute(finding, table))
        for finding in findings
        if finding.severity in wanted
        and not any(_matches(finding.resource, pattern) for pattern in cfg.ignore)
    ]
    if only is not None:
        attributed = [
            (finding, attribution)
            for finding, attribution in attributed
            if isinstance(attribution, Attributed) and attribution.repo in only
        ]
    in_repo: defaultdict[str, list[Finding]] = defaultdict(list)
    without_repo: defaultdict[Reason, list[Finding]] = defaultdict(list)
    for finding, attribution in attributed:
        match attribution:
            case Attributed(repo=repo):
                in_repo[repo].append(finding)
            case Unattributed(reason=reason):
                without_repo[reason].append(finding)
            case _ as unreachable:
                assert_never(unreachable)
    return InspectorReport(
        by_repo={
            repo: group_findings(in_repo[repo], tracking.get(repo, NO_TRACKING))
            for repo in sorted(in_repo)
        },
        unattributed={
            reason: group_findings(without_repo[reason], NO_TRACKING)
            for reason in Reason
            if reason in without_repo
        },
        attributions={finding.arn: attribution for finding, attribution in attributed},
    )
