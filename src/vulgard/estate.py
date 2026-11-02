"""The deployment estate: what's deployed, from which repo, for whom, and how risky it is to touch.

Two phases, so I/O and policy never mix:
  1. Scanners (`aws.py`, `vercel.py`) turn cloud APIs into `Sighting`s.
  2. `classify` (pure) turns a sighting into a `Deployment`: repo, tier and person.

A `Deployment` is the unit people baseline and vulgard redeploys or deletes: a Serverless
service-stage, an SST app-stage, a CDK top-level stack, an Amplify Hosting branch, an Amplify
Gen2 sandbox, or a Vercel project.
"""

from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Protocol, assert_never

from .config import DeploymentsConfig, Tier


class OpFailed(RuntimeError):
    """A redeploy or delete that couldn't be started, or whose state couldn't be read."""


class RunState(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class Found:
    """An op that already exists, found by its request id, and how far it got."""

    url: str
    state: RunState = RunState.RUNNING
    why: str = ""  # what the control plane says went wrong, when FAILED


class ScanError(RuntimeError):
    """A scanner couldn't read its control plane. A partial estate must never make deployments
    look deleted, so the whole topic stops."""


class Framework(StrEnum):
    SERVERLESS = "serverless"  # v3 via OSLS; v4 is discovered the same way
    SST = "sst"  # v3/v4: Pulumi state in the bootstrap bucket, not CloudFormation
    CDK = "cdk"
    AMPLIFY = "amplify"  # Hosting branches and Gen2 sandboxes
    VERCEL = "vercel"


class Attribution(StrEnum):
    CONFIG = "config"  # deployments.attribution glob: an admin override, so it wins
    TAG = "tag"  # a repo tag on the stack
    PLATFORM = "platform"  # Amplify app repository, Vercel project git link
    MANIFEST = "manifest"  # serverless `service:` / SST app name on a default branch
    NONE = "none"  # tracked in deployments.unattributed_repo


# --- native handles: one per control plane, each knowing how it is named and keyed


@dataclass(frozen=True)
class CfnStack:
    account: str
    region: str
    name: str
    stack_id: str
    deployment_bucket: str | None = None  # Serverless `ServerlessDeploymentBucketName` output

    @property
    def key(self) -> str:
        return f"cfn:{self.account}/{self.region}/{self.name}"

    @property
    def label(self) -> str:
        return self.name

    @property
    def glob_name(self) -> str:
        return self.name

    @property
    def tag(self) -> str:
        return self.region


@dataclass(frozen=True)
class SstStage:
    account: str
    region: str
    state_bucket: str  # from SSM /sst/bootstrap
    app: str
    stage: str  # state object app/<app>/<stage>.json

    @property
    def key(self) -> str:
        return f"sst:{self.account}/{self.region}/{self.app}/{self.stage}"

    @property
    def label(self) -> str:
        return f"{self.app}/{self.stage}"

    @property
    def glob_name(self) -> str:
        return f"{self.app}-{self.stage}"

    @property
    def tag(self) -> str:
        return self.region


@dataclass(frozen=True)
class AmplifyBranch:
    account: str
    region: str
    app_id: str
    branch: str
    app_name: str = ""

    @property
    def key(self) -> str:
        return f"amplify:{self.account}/{self.region}/{self.app_id}/{self.branch}"

    @property
    def label(self) -> str:
        return f"{self.app_name or self.app_id}/{self.branch}"

    @property
    def glob_name(self) -> str:
        return f"{self.app_id}-{self.branch}"

    @property
    def tag(self) -> str:
        return self.app_id


@dataclass(frozen=True)
class VercelProject:
    team_id: str
    project_id: str
    name: str = ""

    @property
    def key(self) -> str:
        return f"vercel:{self.team_id}/{self.project_id}"

    @property
    def label(self) -> str:
        return self.name or self.project_id

    @property
    def glob_name(self) -> str:
        return self.project_id

    @property
    def tag(self) -> str:
        return self.project_id


type NativeRef = CfnStack | SstStage | AmplifyBranch | VercelProject


@dataclass(frozen=True)
class Sighting:
    """Raw scanner output. Who owns it and what tier it is are decided in `classify`."""

    framework: Framework
    native: NativeRef
    app: str  # serverless service, SST app, CDK stack, Amplify app name, Vercel project
    stage: str | None  # None for CDK stacks without a stage tag and for Vercel projects
    last_deployed: datetime
    tags: Mapping[str, str] = field(default_factory=dict)
    repo_hint: str | None = None  # "org/repo" or a git URL, from the platform itself
    person_hint: str | None = None  # Amplify sandbox <user>
    protected: bool = False  # termination protection, Amplify production branch, Vercel domain
    in_progress: bool = False  # a deploy or delete is running right now


class Scanner(Protocol):
    """One per control plane. Parses wire data into sightings; nothing raw escapes."""

    def scan(self) -> list[Sighting]: ...


@dataclass(frozen=True)
class Deployment:
    """A classified sighting. Invariants: person is set iff tier is PERSONAL, and a protected
    sighting is PRODUCTION."""

    sighting: Sighting
    repo: str | None
    attributed_by: Attribution
    tier: Tier
    person: str | None  # GitHub handle with "@"
    suffix: str = ""  # set by `discover` when two deployments would share a name

    def __post_init__(self) -> None:
        assert (self.person is not None) == (self.tier is Tier.PERSONAL)
        assert not self.sighting.protected or self.tier is Tier.PRODUCTION

    @property
    def key(self) -> str:
        """Stable identity across runs, and the seed of request ids."""
        return self.sighting.native.key

    @property
    def name(self) -> str:
        """What people type in `/vulgard` commands. Unique across the estate."""
        return self.sighting.native.label + self.suffix

    @property
    def delete_refusal(self) -> str | None:
        """Why vulgard won't delete this even when asked. Transient reasons, such as a deploy
        running right now, are checked at execution time instead."""
        if self.tier is Tier.PRODUCTION or self.sighting.protected:
            return "vulgard never deletes production or protected deployments"
        return None

    @property
    def framework(self) -> Framework:
        return self.sighting.framework

    @property
    def last_deployed(self) -> datetime:
        return self.sighting.last_deployed


# --- repo index: framework identity on default branches -> repo

MARKERS: dict[Framework, re.Pattern[str]] = {
    Framework.SERVERLESS: re.compile(r"(^|/)serverless\.(ya?ml|ts|js|json)$"),
    Framework.SST: re.compile(r"(^|/)sst\.config\.(ts|js|mjs)$"),
    Framework.CDK: re.compile(r"(^|/)cdk\.json$"),
    Framework.AMPLIFY: re.compile(r"(^|/)(amplify\.ya?ml|amplify/backend\.ts)$"),
    Framework.VERCEL: re.compile(r"(^|/)vercel\.(json|ts)$"),
}
SERVICE_RE = re.compile(r"^service:\s*['\"]?([\w-]+)['\"]?\s*$", re.M)
SERVICE_NAME_RE = re.compile(r"^service:\s*\n\s+name:\s*['\"]?([\w-]+)['\"]?\s*$", re.M)
SST_APP_RE = re.compile(r"app\s*\([^)]*\)\s*\{.*?name:\s*['\"]([\w-]+)['\"]", re.S)
IDENTITY_FILES = (Framework.SERVERLESS, Framework.SST)


@dataclass(frozen=True)
class RepoIndex:
    """Ambiguous identities (the same serverless service in two repos, e.g. a template) map to
    None, so they fall through to the next attribution rule instead of guessing."""

    repos: frozenset[str]
    by_identity: Mapping[tuple[Framework, str], str | None]
    frameworks: Mapping[str, frozenset[Framework]]


EMPTY_INDEX = RepoIndex(frozenset(), {}, {})


def manifest_identity(framework: Framework, text: str) -> str | None:
    match framework:
        case Framework.SERVERLESS:
            m = SERVICE_RE.search(text) or SERVICE_NAME_RE.search(text)
        case Framework.SST:
            m = SST_APP_RE.search(text)
        case Framework.CDK | Framework.AMPLIFY | Framework.VERCEL:
            return None
        case _ as unreachable:
            assert_never(unreachable)
    return m.group(1) if m else None


# --- classification

REPO_TAGS = ("vulgard:repo", "github:repo", "repository", "Repository", "repo", "Repo")
STAGE_TAGS = ("STAGE", "Stage", "stage", "sst:stage", "environment", "Environment", "env")
TOKEN_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def repo_name(value: str) -> str:
    """'org/repo', 'https://github.com/org/repo.git' or 'repo' -> 'repo'."""
    return value.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]


def _tokens(*values: str | None) -> set[str]:
    out: set[str] = set()
    for v in values:
        if v:
            out |= {t.lower() for t in TOKEN_RE.findall(v)}
    return out


def _attribute(
    s: Sighting, index: RepoIndex, cfg: DeploymentsConfig
) -> tuple[str | None, Attribution]:
    names = [s.app, s.native.glob_name]
    for pattern, repo in cfg.attribution.items():
        if any(fnmatch.fnmatch(n, pattern) for n in names):
            return repo, Attribution.CONFIG
    for tag in REPO_TAGS:
        if s.tags.get(tag):
            return repo_name(s.tags[tag]), Attribution.TAG
    if s.repo_hint:
        return repo_name(s.repo_hint), Attribution.PLATFORM
    owner = index.by_identity.get((s.framework, s.app))
    if owner:
        return owner, Attribution.MANIFEST
    return None, Attribution.NONE


def stage_of(s: Sighting) -> str | None:
    return s.stage or next((s.tags[t] for t in STAGE_TAGS if s.tags.get(t)), None)


def _tier(s: Sighting, cfg: DeploymentsConfig) -> tuple[Tier, str | None]:
    """First hit wins. A production stage anywhere in the name or tags makes it PRODUCTION, so
    a CDK stack named `PamKnowledgeProduction` is never treated as deletable."""
    stage = stage_of(s)
    production = {p.lower() for p in cfg.production_stages}
    if s.protected or _tokens(stage, s.app, s.native.glob_name, *s.tags.values()) & production:
        return Tier.PRODUCTION, None
    if stage and stage.lower() in {p.lower() for p in cfg.shared_stages}:
        return Tier.SHARED, None
    for candidate in (s.person_hint, stage):
        if candidate and candidate in cfg.people:
            return Tier.PERSONAL, cfg.people[candidate]
    return Tier.SHARED, None


def classify(s: Sighting, index: RepoIndex, cfg: DeploymentsConfig) -> Deployment | None:
    """Pure. None for deployments.ignore matches."""
    if any(fnmatch.fnmatch(n, p) for p in cfg.ignore for n in (s.app, s.native.glob_name)):
        return None
    repo, how = _attribute(s, index, cfg)
    tier, person = _tier(s, cfg)
    return Deployment(s, repo, how, tier, person)


def unique_names(found: list[Deployment]) -> list[Deployment]:
    """Commands address a deployment by name, so no two may share one. Same-named deployments
    (a stack in two regions, two Amplify apps with one name) get the native handle's tag, and
    an index when even that collides."""
    by_name: dict[str, list[Deployment]] = defaultdict(list)
    for d in found:
        by_name[d.name].append(d)
    renamed: dict[str, Deployment] = {}
    for group in by_name.values():
        if len(group) == 1:
            continue
        group.sort(key=lambda d: d.key)
        tags = [d.sighting.native.tag for d in group]
        for i, d in enumerate(group):
            tag = d.sighting.native.tag
            suffix = f"@{tag}" if tags.count(tag) == 1 else f"@{tag}#{i + 1}"
            renamed[d.key] = replace(d, suffix=suffix)
    return [renamed.get(d.key, d) for d in found]


def discover(
    scanners: Iterable[Scanner], index: RepoIndex, cfg: DeploymentsConfig
) -> list[Deployment]:
    """Scan every control plane and classify. Scanner errors propagate: a partial estate must
    never make deployments look deleted."""
    found = [d for sc in scanners for s in sc.scan() if (d := classify(s, index, cfg))]
    return unique_names(sorted(found, key=lambda d: (d.repo or "", d.key)))
