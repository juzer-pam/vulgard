"""The inspector topic's model and policy: Amazon Inspector package vulnerabilities, each
attributed to the repo that deployed the vulnerable resource.

Inspector names a resource (a Lambda function, an ECR image, an EC2 instance), never a repo. The
repo is the first of these that answers:

    1. `inspector.attribution`, an admin override matched against the resource and stack names
    2. a repo tag on the resource
    3. the estate deployment the resource belongs to (see `estate.py`), found through its
       CloudFormation stack, SST app and stage, or Amplify app and branch tags

Findings of one vulnerability in one package, across resources, are reported as one group.

This module is pure. The parser is `aws.sight_finding`, the live source is `aws.AwsInspector`,
and the printed tables and JSON are in `inspector_render.py`.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
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

STACK_NAME_TAG = "aws:cloudformation:stack-name"
SERVERLESS_REPOSITORY_RE = re.compile(r"^serverless-(.+)$")
SHARED_ASSET_REPOSITORIES = ("sst-asset", "cdk-*-container-assets-*")  # one per account, all apps


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
    CONFIG = "config"
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
    cfg: InspectorConfig,
) -> FindingAttribution:
    """The first rule that answers wins. A deployment found through the resource's tags is final
    even when it has no repo."""
    resource = finding.resource
    for pattern, repo in cfg.attribution.items():
        if _matches(resource, pattern):
            return Attributed(repo, Via.CONFIG)
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


# --- grouping and the report


@dataclass(frozen=True)
class FindingGroup:
    """One vulnerability in one package, across every resource that has it. `severity` is the
    highest of its findings, `exploit_available` is true if any finding has an exploit, and
    `fixed_in` is the first version a finding names."""

    vulnerability_id: str
    package: str
    severity: str
    exploit_available: bool
    fixed_in: str | None
    findings: tuple[Finding, ...]

    @property
    def resources(self) -> list[str]:
        return sorted({finding.resource.name for finding in self.findings})

    @property
    def fix_available(self) -> bool:
        return any(finding.fix_available for finding in self.findings)


def _group(findings: list[Finding]) -> FindingGroup:
    return FindingGroup(
        vulnerability_id=findings[0].vulnerability_id,
        package=findings[0].package,
        severity=min((finding.severity for finding in findings), key=SEVERITIES.index),
        exploit_available=any(finding.exploit_available for finding in findings),
        fixed_in=next((finding.fixed_in for finding in findings if finding.fixed_in), None),
        findings=tuple(findings),
    )


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    """Most severe first, then the widest."""
    buckets: defaultdict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        buckets[(finding.vulnerability_id, finding.package)].append(finding)
    return sorted(
        (_group(bucket) for bucket in buckets.values()),
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
) -> InspectorReport:
    """Pure. Drops findings below `min_severity` and `ignore` matches, attributes the rest, and
    groups them. `only` (from --repo) keeps just those repos and the unattributed buckets go,
    as in `stale.survey(scoped=True)`."""
    table = index_deployments(deployments)
    wanted = severities_at_least(cfg.min_severity)
    attributed = [
        (finding, attribute(finding, table, cfg))
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
        by_repo={repo: group_findings(in_repo[repo]) for repo in sorted(in_repo)},
        unattributed={
            reason: group_findings(without_repo[reason])
            for reason in Reason
            if reason in without_repo
        },
        attributions={finding.arn: attribution for finding, attribution in attributed},
    )
