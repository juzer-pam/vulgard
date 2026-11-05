"""The inspector topic's model and policy: Amazon Inspector package vulnerabilities, each
attributed to the repo that deployed the vulnerable resource.

Inspector names a resource (a Lambda function, an ECR image, an EC2 instance), never a repo. The
repo is the first of these that answers:

    1. a repo tag on the resource
    2. the estate deployment the resource belongs to (see `estate.py`), found through its
       CloudFormation stack, SST app and stage, or Amplify app and branch tags
    3. for an image in a shared asset repository only, the Lambda function or ECS task definition
       that runs it, attributed by rules 1 and 2 applied to the runner's own tags

All the findings of one package in one repo, across vulnerabilities and resources, are one fix
item, because a single upgrade fixes them all. Each fix item gets a status that says what it needs
next (see `FixStatus`).

This module is pure. The parser is `aws.sight_finding`, the live source is `aws.AwsInspector`,
and the printed tables and JSON are in `inspector_render.py`.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, assert_never

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
from .policy import DependabotPR

STACK_NAME_TAG = "aws:cloudformation:stack-name"
SERVERLESS_REPOSITORY_RE = re.compile(r"^serverless-(.+)$")
SHARED_ASSET_REPOSITORIES = ("sst-asset", "cdk-*-container-assets-*")  # one per account, all apps
OS_PACKAGE_MANAGER = "OS"
# Inspector's package manager -> the SBOM purl type GitHub's dependency graph uses for it.
SBOM_ECOSYSTEMS = {"NODE": "npm", "JAVA": "maven", "PYTHON": "pypi", "GO": "golang"}
VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")
ECR_IMAGE_RE = re.compile(
    r"^\d+\.dkr\.ecr(?:-fips)?\.(?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?"
    r"/(?P<repository>[^@:]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>sha256:[0-9a-f]+))?$"
)


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
    image_digest: str | None = None  # ECR images only
    image_tags: tuple[str, ...] = ()  # ECR images only


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


# --- what runs an image


class RunnerKind(StrEnum):
    LAMBDA = "lambda"
    ECS_TASK_DEFINITION = "ecs_task_definition"


@dataclass(frozen=True)
class ImageRef:
    """A container image as a Lambda function or ECS task definition names it. A Lambda function
    names its image by digest. A task definition names it by digest or by tag, and a tag is how
    CDK and SST reference the images they push."""

    region: str
    repository: str
    digest: str | None
    tag: str | None

    def __post_init__(self) -> None:
        assert (self.digest is None) != (self.tag is None)

    @property
    def reference(self) -> str:
        return self.digest or self.tag or ""


def parse_image(uri: str) -> ImageRef | None:
    """`<account>.dkr.ecr.<region>.amazonaws.com/<repository>[:tag][@sha256:...]`. None for an
    image outside ECR. When both are given the digest wins, because it is what runs."""
    found = ECR_IMAGE_RE.match(uri)
    if found is None:
        return None
    digest = found["digest"]
    tag = None if digest else found["tag"] or "latest"
    return ImageRef(found["region"], found["repository"], digest, tag)


@dataclass(frozen=True)
class ImageRunner:
    """A Lambda function or ECS task definition running one container image. A task definition
    with several containers is one runner per image."""

    kind: RunnerKind
    name: str  # function name or task definition family
    region: str
    image: ImageRef
    tags: Mapping[str, str]


type ImageKey = tuple[str, str, str]  # (region, repository, digest or tag)
type RunnerIndex = Mapping[ImageKey, Sequence[ImageRunner]]


def index_runners(runners: Iterable[ImageRunner]) -> dict[ImageKey, list[ImageRunner]]:
    table: defaultdict[ImageKey, list[ImageRunner]] = defaultdict(list)
    for runner in runners:
        image = runner.image
        table[(image.region, image.repository, image.reference)].append(runner)
    return dict(table)


def _running(resource: InspectorResource, runners: RunnerIndex) -> list[ImageRunner]:
    """The runners of an ECR image, matched by its digest or by any of its tags, in name order."""
    references = [*resource.image_tags, *([resource.image_digest] if resource.image_digest else [])]
    found = [
        runner
        for reference in references
        for runner in runners.get((resource.region, resource.name, reference), ())
    ]
    return sorted(found, key=lambda runner: (runner.kind, runner.name))


class InspectorSource(Protocol):
    """Parses Inspector's ListFindings into findings; nothing raw escapes."""

    def findings(self) -> list[Finding]: ...

    def runners(self) -> list[ImageRunner]:
        """The Lambda functions and ECS task definitions that run container images."""
        ...


# --- attribution


class Via(StrEnum):
    TAG = "tag"
    DEPLOYMENT = "deployment"


class Reason(StrEnum):
    SHARED_ASSET_REPOSITORY = "shared_asset_repository"
    RUNNERS_IN_SEVERAL_REPOS = "runners_in_several_repos"
    NO_DEPLOYMENT_TAGS = "no_deployment_tags"
    DEPLOYMENT_NOT_FOUND = "deployment_not_found"
    DEPLOYMENT_UNATTRIBUTED = "deployment_unattributed"


@dataclass(frozen=True)
class Attributed:
    """`via` and `deployment` say how the repo was found, for the resource or, when `runner` is
    set, for the runner that runs the resource's image."""

    repo: str
    via: Via
    deployment: str | None = None
    runner: ImageRunner | None = None

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


def tag_keys(tags: Mapping[str, str], region: str) -> list[DeploymentKey]:
    """The deployments a resource's tags say it belongs to, in order of trust."""
    keys: list[DeploymentKey] = []
    if stack := tags.get(STACK_NAME_TAG):
        keys.append(("cfn", region, stack))
    if (app := tags.get("sst:app")) and (stage := tags.get("sst:stage")):
        keys.append(("sst", region, app, stage))
    if (app_id := tags.get("amplify:app-id")) and (branch := tags.get("amplify:branch-name")):
        keys.append(("amplify", region, app_id, branch))
    return keys


def candidate_keys(resource: InspectorResource) -> list[DeploymentKey]:
    """The deployments a resource says it belongs to, in order of trust."""
    keys = tag_keys(resource.tags, resource.region)
    if resource.type is ResourceType.ECR_IMAGE:
        # ECR images carry no tags. Serverless names its repository `serverless-<service>-<stage>`
        # and the stack `<service>-<stage>`.
        if serverless := SERVERLESS_REPOSITORY_RE.match(resource.name):
            keys.append(("cfn", resource.region, serverless[1]))
    return keys


def _matches(resource: InspectorResource, pattern: str) -> bool:
    names = (resource.name, resource.tags.get(STACK_NAME_TAG, ""))
    return any(fnmatch.fnmatch(name, pattern) for name in names)


def is_shared_asset_image(resource: InspectorResource) -> bool:
    return resource.type is ResourceType.ECR_IMAGE and any(
        fnmatch.fnmatch(resource.name, pattern) for pattern in SHARED_ASSET_REPOSITORIES
    )


def _by_tags(
    tags: Mapping[str, str],
    keys: Sequence[DeploymentKey],
    deployments_by_key: Mapping[DeploymentKey, Deployment],
) -> FindingAttribution:
    """Rules 1 and 2. A deployment found through the tags is final even when it has no repo."""
    for tag in REPO_TAGS:
        if tags.get(tag):
            return Attributed(repo_name(tags[tag]), Via.TAG)
    deployment = next((deployments_by_key[key] for key in keys if key in deployments_by_key), None)
    if deployment is not None:
        if deployment.repo:
            return Attributed(deployment.repo, Via.DEPLOYMENT, deployment.name)
        return Unattributed(Reason.DEPLOYMENT_UNATTRIBUTED)
    return Unattributed(Reason.DEPLOYMENT_NOT_FOUND if keys else Reason.NO_DEPLOYMENT_TAGS)


def _through_runners(
    resource: InspectorResource,
    deployments_by_key: Mapping[DeploymentKey, Deployment],
    runners: RunnerIndex,
) -> FindingAttribution:
    """Rule 3. Runners that name no repo are ignored. Runners that name different repos leave the
    image unattributed, because it is shared and picking one repo would send the fix to the wrong
    team. When they agree, the first runner by kind and name is the one reported."""
    resolved: list[Attributed] = []
    for runner in _running(resource, runners):
        answer = _by_tags(runner.tags, tag_keys(runner.tags, runner.region), deployments_by_key)
        if isinstance(answer, Attributed):
            resolved.append(replace(answer, runner=runner))
    if not resolved:
        return Unattributed(Reason.SHARED_ASSET_REPOSITORY)
    if len({attribution.repo for attribution in resolved}) > 1:
        return Unattributed(Reason.RUNNERS_IN_SEVERAL_REPOS)
    return resolved[0]


def attribute(
    finding: Finding,
    deployments_by_key: Mapping[DeploymentKey, Deployment],
    runners: RunnerIndex,
) -> FindingAttribution:
    """The first rule that answers wins."""
    resource = finding.resource
    answer = _by_tags(resource.tags, candidate_keys(resource), deployments_by_key)
    if is_shared_asset_image(resource) and answer in (
        Unattributed(Reason.NO_DEPLOYMENT_TAGS),
        Unattributed(Reason.DEPLOYMENT_NOT_FOUND),
    ):
        return _through_runners(resource, deployments_by_key, runners)
    return answer


# --- the dependency graph


@dataclass(frozen=True)
class BranchDependencies:
    """Every package version on a repo's default branch, from GitHub's dependency graph,
    keyed by (purl type, normalized name)."""

    versions: Mapping[tuple[str, str], frozenset[str]]

    @property
    def ecosystems(self) -> frozenset[str]:
        return frozenset(ecosystem for ecosystem, _ in self.versions)


def _package_key(ecosystem: str, name: str) -> tuple[str, str]:
    name = name.lower()
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return ecosystem, name


def branch_dependencies(sbom: Mapping[str, Any]) -> BranchDependencies:
    """Parses `GET /repos/{org}/{repo}/dependency-graph/sbom`. Packages without a purl, such as
    the repo itself, are skipped."""
    versions: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for package in sbom.get("sbom", {}).get("packages", []):
        purl = next(
            (
                ref["referenceLocator"]
                for ref in package.get("externalRefs", [])
                if ref.get("referenceType") == "purl"
            ),
            None,
        )
        if not purl or not purl.startswith("pkg:") or not package.get("versionInfo"):
            continue
        ecosystem = purl[len("pkg:") :].split("/", 1)[0]
        versions[_package_key(ecosystem, package["name"])].add(package["versionInfo"])
    return BranchDependencies({key: frozenset(found) for key, found in versions.items()})


def _version(text: str) -> tuple[int, ...] | None:
    """`2`, `2.0` and `2.0.0` compare equal, so trailing zero parts are dropped."""
    found = VERSION_RE.match(text.strip())
    if not found:
        return None
    parts = [int(part) for part in found.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


# --- fix items


class FixStatus(StrEnum):
    """What a fix item needs next. The first that holds is the item's status."""

    NEEDS_DEPLOY = "needs_deploy"
    NEEDS_PR_MERGE = "needs_pr_merge"
    NEEDS_FIX = "needs_fix"
    NEEDS_OS_UPDATE = "needs_os_update"
    UNKNOWN = "unknown"


def _normalized(ecosystem: str | None, name: str) -> str:
    return _package_key(ecosystem or "", name)[1]


def _pr_updates(pr: DependabotPR, ecosystem: str | None) -> dict[str, str | None]:
    return {_normalized(ecosystem, name): target for name, target in pr.updates.items()}


@dataclass(frozen=True)
class FixItem:
    """Every finding for one package in one repo. `severity` is the worst of its findings and
    `fixed_in` the highest version any of them needs, None when a finding names none or a version
    can't be parsed. `main_versions` are the versions the default branch has, empty when the
    package is gone or the branch doesn't declare the package's ecosystem."""

    package: str
    ecosystem: str | None
    severity: str
    fixed_in: str | None
    findings: tuple[Finding, ...]
    status: FixStatus
    main_versions: frozenset[str]
    pr: DependabotPR | None

    def __post_init__(self) -> None:
        assert (self.pr is not None) == (self.status is FixStatus.NEEDS_PR_MERGE)

    @property
    def vulnerability_ids(self) -> list[str]:
        return sorted({finding.vulnerability_id for finding in self.findings})

    @property
    def resources(self) -> list[str]:
        return sorted({finding.resource.name for finding in self.findings})

    @property
    def exploit_available(self) -> bool:
        return any(finding.exploit_available for finding in self.findings)

    @property
    def pr_target(self) -> str | None:
        """The version the PR moves the package to, None when it removes it or there is no PR."""
        if self.pr is None:
            return None
        return _pr_updates(self.pr, self.ecosystem)[_normalized(self.ecosystem, self.package)]


def _required_version(findings: Sequence[Finding]) -> str | None:
    fixed = [finding.fixed_in for finding in findings if finding.fixed_in]
    if len(fixed) < len(findings):
        return None
    parsed = {version: _version(version) for version in fixed}
    if None in parsed.values():
        return None
    return max(parsed, key=lambda version: parsed[version] or ())


def _all_at_least(versions: Iterable[str], required: tuple[int, ...] | None) -> bool | None:
    """Whether every version is at or past `required`, None when that can't be told."""
    parsed = [_version(version) for version in versions]
    if required is None or None in parsed:
        return None
    return all(version >= required for version in parsed if version is not None)


def _fixes(target: str | None, required: tuple[int, ...] | None) -> bool | None:
    """Whether moving to `target` fixes the item, None when that can't be told."""
    if target is None:
        return True
    if required is None:
        return False
    version = _version(target)
    return None if version is None else version >= required


def _decide(
    findings: Sequence[Finding],
    required: tuple[int, ...] | None,
    prs: Sequence[DependabotPR],
    branch: BranchDependencies | None,
) -> tuple[FixStatus, frozenset[str], DependabotPR | None]:
    first = findings[0]
    ecosystem = SBOM_ECOSYSTEMS.get(first.package_manager)
    if first.package_manager == OS_PACKAGE_MANAGER:
        return FixStatus.NEEDS_OS_UPDATE, frozenset(), None
    present: frozenset[str] = frozenset()
    on_branch: bool | None = None
    if ecosystem is not None and branch is not None and ecosystem in branch.ecosystems:
        present = branch.versions.get(_package_key(ecosystem, first.package), frozenset())
        on_branch = _all_at_least(present, required)
        if not present or on_branch:
            return FixStatus.NEEDS_DEPLOY, present, None
    name = _normalized(ecosystem, first.package)
    covers: list[tuple[DependabotPR, bool | None]] = []
    for pr in sorted(prs, key=lambda pr: pr.number):
        updates = _pr_updates(pr, ecosystem)
        if name in updates:
            covers.append((pr, _fixes(updates[name], required)))
    fixing = next((pr for pr, fixes in covers if fixes), None)
    if fixing is not None:
        return FixStatus.NEEDS_PR_MERGE, present, fixing
    undecided = any(fixes is None for _, fixes in covers)
    if present and on_branch is False and not undecided:
        return FixStatus.NEEDS_FIX, present, None
    return FixStatus.UNKNOWN, present, None


def _fix_item(
    findings: Sequence[Finding], prs: Sequence[DependabotPR], branch: BranchDependencies | None
) -> FixItem:
    fixed_in = _required_version(findings)
    status, main_versions, pr = _decide(
        findings, _version(fixed_in) if fixed_in else None, prs, branch
    )
    return FixItem(
        package=findings[0].package,
        ecosystem=SBOM_ECOSYSTEMS.get(findings[0].package_manager),
        severity=min((finding.severity for finding in findings), key=SEVERITIES.index),
        fixed_in=fixed_in,
        findings=tuple(findings),
        status=status,
        main_versions=main_versions,
        pr=pr,
    )


def fix_items(
    findings: Iterable[Finding], prs: Sequence[DependabotPR], branch: BranchDependencies | None
) -> list[FixItem]:
    """One item per package, worst severity first, then with an exploit, then on the most
    resources. Findings of an OS package or an ecosystem the SBOM has no type for are keyed by
    their package manager, so an OS `openssl` and an npm `openssl` stay apart."""
    buckets: defaultdict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        ecosystem = SBOM_ECOSYSTEMS.get(finding.package_manager, finding.package_manager)
        buckets[_package_key(ecosystem, finding.package)].append(finding)
    return sorted(
        (_fix_item(bucket, prs, branch) for bucket in buckets.values()),
        key=lambda item: (
            SEVERITIES.index(item.severity),
            not item.exploit_available,
            -len(item.resources),
            item.package,
            item.ecosystem or "",
        ),
    )


@dataclass(frozen=True)
class InspectorReport:
    by_repo: dict[str, list[FixItem]]
    unattributed: dict[Reason, list[FixItem]]
    attributions: dict[str, FindingAttribution]  # finding ARN -> how it was attributed

    @property
    def status(self) -> Counter[FixStatus]:
        sections = [*self.by_repo.values(), *self.unattributed.values()]
        return Counter(item.status for items in sections for item in items)

    @property
    def via(self) -> Counter[Via]:
        return Counter(
            attribution.via
            for attribution in self.attributions.values()
            if isinstance(attribution, Attributed)
        )


def _attribute_wanted(
    findings: Iterable[Finding],
    deployments: Iterable[Deployment],
    runners: Iterable[ImageRunner],
    cfg: InspectorConfig,
) -> list[tuple[Finding, FindingAttribution]]:
    table = index_deployments(deployments)
    running = index_runners(runners)
    wanted = severities_at_least(cfg.min_severity)
    return [
        (finding, attribute(finding, table, running))
        for finding in findings
        if finding.severity in wanted
        and not any(_matches(finding.resource, pattern) for pattern in cfg.ignore)
    ]


def attributed_repos(
    findings: Iterable[Finding],
    deployments: Iterable[Deployment],
    cfg: InspectorConfig,
    runners: Iterable[ImageRunner] = (),
) -> set[str]:
    """The repos `build_report` will list, so their dependency graphs can be read first."""
    return {
        attribution.repo
        for _, attribution in _attribute_wanted(findings, deployments, runners, cfg)
        if isinstance(attribution, Attributed)
    }


def build_report(
    findings: Iterable[Finding],
    deployments: Iterable[Deployment],
    cfg: InspectorConfig,
    only: set[str] | None,
    prs: Mapping[str, Sequence[DependabotPR]],
    branches: Mapping[str, BranchDependencies],
    runners: Iterable[ImageRunner] = (),
) -> InspectorReport:
    """Pure. Drops findings below `min_severity` and `ignore` matches, attributes the rest, and
    turns them into fix items. `only` (from --repo) keeps just those repos and the unattributed
    buckets go, as in `stale.survey(scoped=True)`. `prs` are each repo's open Dependabot PRs and
    `branches` its default branch's dependencies. A repo missing from `branches` has no
    dependency graph, and unattributed findings have neither. `runners` attribute images in
    shared asset repositories."""
    attributed = _attribute_wanted(findings, deployments, runners, cfg)
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
            repo: fix_items(in_repo[repo], prs.get(repo, ()), branches.get(repo))
            for repo in sorted(in_repo)
        },
        unattributed={
            reason: fix_items(without_repo[reason], (), None)
            for reason in Reason
            if reason in without_repo
        },
        attributions={finding.arn: attribution for finding, attribution in attributed},
    )
