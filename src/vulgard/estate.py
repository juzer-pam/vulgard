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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, assert_never

from .config import Config, DeploymentsConfig
from .policy import parse_time


class Framework(StrEnum):
    SERVERLESS = "serverless"  # v3 via OSLS; v4 is discovered the same way
    SST = "sst"  # v3/v4: Pulumi state in the bootstrap bucket, not CloudFormation
    CDK = "cdk"
    AMPLIFY = "amplify"  # Hosting branches and Gen2 sandboxes
    VERCEL = "vercel"


class Tier(StrEnum):
    """How much vulgard may do, by blast radius."""

    PRODUCTION = "production"  # notify only; vulgard never deletes it, even when asked
    SHARED = "shared"  # notify; redeploy or delete only on a human request
    PERSONAL = "personal"  # notify; automatic redeploy or delete when the repo opts in


class Attribution(StrEnum):
    CONFIG = "config"  # deployments.attribution glob: an admin override, so it wins
    TAG = "tag"  # a repo tag on the stack
    PLATFORM = "platform"  # Amplify app repository, Vercel project git link
    MANIFEST = "manifest"  # serverless `service:` / SST app name on a default branch
    NONE = "none"  # tracked in deployments.unattributed_repo


# --- native handles: how to operate on a deployment, one per control plane


@dataclass(frozen=True)
class CfnStack:
    account: str
    region: str
    name: str
    stack_id: str
    deployment_bucket: str | None = None  # Serverless `ServerlessDeploymentBucketName` output


@dataclass(frozen=True)
class SstStage:
    account: str
    region: str
    state_bucket: str  # from SSM /sst/bootstrap
    app: str
    stage: str  # state object app/<app>/<stage>.json


@dataclass(frozen=True)
class AmplifyBranch:
    account: str
    region: str
    app_id: str
    branch: str


@dataclass(frozen=True)
class VercelProject:
    team_id: str
    project_id: str


type NativeRef = CfnStack | SstStage | AmplifyBranch | VercelProject


def native_key(native: NativeRef) -> str:
    """Stable identity across runs: the memory key and the seed of request ids."""
    match native:
        case CfnStack(account=a, region=r, name=n):
            return f"cfn:{a}/{r}/{n}"
        case SstStage(account=a, region=r, app=app, stage=s):
            return f"sst:{a}/{r}/{app}/{s}"
        case AmplifyBranch(account=a, region=r, app_id=app, branch=b):
            return f"amplify:{a}/{r}/{app}/{b}"
        case VercelProject(team_id=t, project_id=p):
            return f"vercel:{t}/{p}"
        case _ as unreachable:
            assert_never(unreachable)


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

    def __post_init__(self) -> None:
        assert (self.person is not None) == (self.tier is Tier.PERSONAL)
        assert not self.sighting.protected or self.tier is Tier.PRODUCTION

    @property
    def key(self) -> str:
        return native_key(self.sighting.native)

    @property
    def name(self) -> str:
        """What people type in `/vulgard` commands. Unique within a repo."""
        s = self.sighting
        match s.native:
            case CfnStack(name=n):
                return n
            case SstStage(app=app, stage=stage):
                return f"{app}/{stage}"
            case AmplifyBranch(branch=b):
                return f"{s.app}/{b}"
            case VercelProject():
                return s.app
            case _ as unreachable:
                assert_never(unreachable)

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


def build_index(gh: Any, config: Config, repos: list[dict[str, Any]]) -> RepoIndex:
    """One tree listing per repo, plus the serverless and SST manifests it finds."""
    found: dict[tuple[Framework, str], set[str]] = {}
    frameworks: dict[str, frozenset[Framework]] = {}
    for r in repos:
        name = r["name"]
        paths = [
            p
            for p in gh.list_tree_paths(config.org, name, r.get("default_branch") or "main")
            if "node_modules/" not in p
        ]
        marked = {fw: [p for p in paths if rx.search(p)] for fw, rx in MARKERS.items()}
        frameworks[name] = frozenset(fw for fw, hits in marked.items() if hits)
        for fw in IDENTITY_FILES:
            for path in marked[fw][:5]:
                text = gh.get_file(config.org, name, path)
                ident = manifest_identity(fw, text) if text else None
                if ident:
                    found.setdefault((fw, ident), set()).add(name)
    by_identity = {k: (next(iter(v)) if len(v) == 1 else None) for k, v in found.items()}
    return RepoIndex(frozenset(r["name"] for r in repos), by_identity, frameworks)


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
    names = [s.app, native_name(s.native)]
    for pattern, repo in cfg.attribution.items():
        if any(fnmatch.fnmatch(n, pattern) for n in names):
            return repo, Attribution.CONFIG
    for tag in REPO_TAGS:
        if s.tags.get(tag):
            return repo_name(s.tags[tag]), Attribution.TAG
    if s.repo_hint:
        return repo_name(s.repo_hint), Attribution.PLATFORM
    repo = index.by_identity.get((s.framework, s.app))
    if repo:
        return repo, Attribution.MANIFEST
    return None, Attribution.NONE


def native_name(native: NativeRef) -> str:
    match native:
        case CfnStack(name=n):
            return n
        case SstStage(app=app, stage=stage):
            return f"{app}-{stage}"
        case AmplifyBranch(app_id=app, branch=b):
            return f"{app}-{b}"
        case VercelProject(project_id=p):
            return p
        case _ as unreachable:
            assert_never(unreachable)


def stage_of(s: Sighting) -> str | None:
    return s.stage or next((s.tags[t] for t in STAGE_TAGS if s.tags.get(t)), None)


def _tier(s: Sighting, cfg: DeploymentsConfig) -> tuple[Tier, str | None]:
    """First hit wins. A production stage anywhere in the name or tags makes it PRODUCTION, so
    a CDK stack named `PamKnowledgeProduction` is never treated as deletable."""
    stage = stage_of(s)
    production = {p.lower() for p in cfg.production_stages}
    if s.protected or _tokens(stage, s.app, native_name(s.native), *s.tags.values()) & production:
        return Tier.PRODUCTION, None
    if stage and stage.lower() in {p.lower() for p in cfg.shared_stages}:
        return Tier.SHARED, None
    for candidate in (s.person_hint, stage):
        if candidate and candidate in cfg.people:
            return Tier.PERSONAL, cfg.people[candidate]
    return Tier.SHARED, None


def classify(s: Sighting, index: RepoIndex, cfg: DeploymentsConfig) -> Deployment | None:
    """Pure. None for deployments.ignore matches."""
    if any(fnmatch.fnmatch(n, p) for p in cfg.ignore for n in (s.app, native_name(s.native))):
        return None
    repo, how = _attribute(s, index, cfg)
    tier, person = _tier(s, cfg)
    return Deployment(s, repo, how, tier, person)


def discover(
    scanners: Iterable[Scanner], index: RepoIndex, cfg: DeploymentsConfig
) -> list[Deployment]:
    """Scan every control plane and classify. Scanner errors propagate: a partial estate must
    never make deployments look deleted."""
    found = [d for sc in scanners for s in sc.scan() if (d := classify(s, index, cfg))]
    return sorted(found, key=lambda d: (d.repo or "", d.key))


# --- repo activity


@dataclass(frozen=True)
class RepoActivity:
    repo: str
    last_commit: datetime | None  # None: no commits seen
    created_at: datetime | None = None  # anchors the inactivity clock when there are no commits


def _is_bot(commit: dict[str, Any]) -> bool:
    author = commit.get("author") or {}
    name = ((commit.get("commit") or {}).get("author") or {}).get("name", "")
    return author.get("type") == "Bot" or "[bot]" in author.get("login", "") or "[bot]" in name


def last_human_commit(commits: list[dict[str, Any]]) -> datetime | None:
    """Latest commit not made by a bot. If every listed commit is a bot's, the human one is
    older than all of them, so the oldest listed date is a safe upper bound."""
    dates = [
        (parse_time(c["commit"]["committer"]["date"]), _is_bot(c))
        for c in commits
        if (c.get("commit") or {}).get("committer")
    ]
    human = [d for d, bot in dates if not bot]
    if human:
        return max(human)
    return min((d for d, _ in dates), default=None)


def repo_activity(gh: Any, config: Config, repos: list[dict[str, Any]]) -> list[RepoActivity]:
    return [
        RepoActivity(
            r["name"],
            last_human_commit(
                gh.list_commits(config.org, r["name"], r.get("default_branch") or "main")
            ),
            parse_time(r["created_at"]) if r.get("created_at") else None,
        )
        for r in repos
    ]
