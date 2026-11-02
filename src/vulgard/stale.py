"""The stale topic's model and policy: deployments not deployed in 30 days and repos with no
commits in 90.

Staleness is one more SLA, so escalation, Linear priority and severity labels, and the
leaderboard work the same way they do for alerts:

    flagged_at = last_deployed + stale_days      (or last_commit + repo_inactive_days)
    deadline   = flagged_at + baseline_days      (time to redeploy, delete, or keep)
    status     = ok / due-soon / overdue
    severity   = deployments.severity[tier]      (repos: deployments.repo_severity)

Every clock comes from cloud and GitHub timestamps and vulgard never stores one, so editing a
tracking issue can't reset it.

This module is pure apart from `survey`. Rendering is in `stale_render.py`, the issue plan in
`stale_plan.py`, and the run itself in `topics.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Self

from .baseline import Active, Decisions, Issued, Keep, Rejection, Request, pending_requests
from .config import SEVERITIES, Config
from .estate import Deployment, Scanner, discover
from .lifecycle import Finished, Lifecycle, Notice, confirmed, reconcile
from .plan import Topic, TopicSpec
from .policy import SlaStatus
from .repos import RepoActivity, build_index, repo_activity

REPO_KEY = "repo"


@dataclass(frozen=True)
class Sla:
    severity: str
    flagged_at: datetime
    deadline: datetime
    status: SlaStatus
    escalate: bool
    days_left: int  # negative when overdue


@dataclass(frozen=True)
class DeploymentFinding:
    deployment: Deployment
    sla: Sla

    @property
    def key(self) -> str:
        return self.deployment.key

    @property
    def name(self) -> str:
        return self.deployment.name


@dataclass(frozen=True)
class RepoFinding:
    last_commit: datetime | None
    days: int | None  # None: no commits at all
    sla: Sla

    @property
    def key(self) -> str:
        return REPO_KEY

    @property
    def name(self) -> str:
        return "repo"


type Finding = DeploymentFinding | RepoFinding


@dataclass(frozen=True)
class StaleReport:
    """Everything the planner renders for one repo. Built once by `evaluate`; the owners are
    attached afterwards because looking them up costs an API call."""

    repo: str
    deployments: list[Deployment]  # attributed here, for the inventory
    notes: dict[str, str]  # key -> why it landed in this repo
    decisions: Decisions
    deployment_findings: list[DeploymentFinding]  # needing a baseline
    kept: list[tuple[DeploymentFinding, Issued[Keep]]]
    repo_finding: RepoFinding | None
    requests: list[tuple[Issued[Request], Deployment]]  # still pending
    lifecycle: Lifecycle
    owners: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        """Most urgent first."""
        found: list[Finding] = [*self.deployment_findings]
        if self.repo_finding is not None:
            found.append(self.repo_finding)
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(found, key=lambda f: (f.sla.days_left, rank[f.sla.severity]))

    @property
    def overdue(self) -> list[Finding]:
        return [f for f in self.findings if f.sla.status is SlaStatus.OVERDUE]

    @property
    def active(self) -> Issued[Active] | None:
        return self.decisions.active

    @property
    def rejected(self) -> tuple[Rejection, ...]:
        return self.decisions.rejected

    @property
    def needs_tracking(self) -> bool:
        life = self.lifecycle
        return bool(self.findings or self.requests or life.scheduled or life.ops)

    @property
    def persons(self) -> list[str]:
        """People whose personal deployments are listed, other than the owners."""
        found = {
            f.deployment.person
            for f in self.deployment_findings
            if f.deployment.person and f.deployment.person not in self.owners
        }
        return sorted(found)


@dataclass(frozen=True)
class StaleMemory:
    """Hints only. Losing them may repeat an announcement and never causes an op."""

    seen: tuple[str, ...] = ()  # deployment names, so commands for deleted ones are moot
    flagged: tuple[str, ...] = ()  # finding keys already announced
    overdue: tuple[str, ...] = ()
    escalated: tuple[str, ...] = ()
    baselined: tuple[tuple[str, str], ...] = ()  # (key, ISO date) resolved recently

    def to_json(self) -> dict[str, Any]:
        return {
            "seen": list(self.seen),
            "flagged": list(self.flagged),
            "overdue": list(self.overdue),
            "escalated": list(self.escalated),
            "baselined": [list(b) for b in self.baselined],
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Self:
        return cls(
            seen=tuple(raw.get("seen", ())),
            flagged=tuple(raw.get("flagged", ())),
            overdue=tuple(raw.get("overdue", ())),
            escalated=tuple(raw.get("escalated", ())),
            baselined=tuple((k, d) for k, d in raw.get("baselined", ())),
        )


def spec(config: Config) -> TopicSpec:
    cfg = config.deployments
    return TopicSpec(
        topic=Topic.STALE,
        label=cfg.label,
        title=cfg.title,
        slack_header="Stale deployments need a baseline in these repos:",
        slack_dm_header="Stale deployments need a baseline in repos you own:",
        escalation_header="🚨 Escalation: these deployments are well past their baseline deadline.",
        linear_closed="✅ Every deployment is up to date or baselined. Closing.",
        memory_type=StaleMemory,
        reads_commands=True,
        linear=cfg.linear,
    )


def _sla(config: Config, severity: str, since: datetime, days: int, now: datetime) -> Sla:
    flagged = since + timedelta(days=days)
    deadline = flagged + timedelta(days=config.deployments.baseline_days)
    left = (deadline - now).days
    if now > deadline:
        status = SlaStatus.OVERDUE
    elif left <= config.due_soon_days:
        status = SlaStatus.DUE_SOON
    else:
        status = SlaStatus.OK
    esc = config.escalation
    escalate = (
        status is SlaStatus.OVERDUE
        and severity in esc.severities
        and -left >= esc.after_days_overdue
    )
    return Sla(severity, flagged, deadline, status, escalate, left)


def _deployment_finding(config: Config, d: Deployment, now: datetime) -> DeploymentFinding | None:
    cfg = config.deployments
    if (now - d.last_deployed).days < cfg.stale_days:
        return None
    sla = _sla(config, cfg.severity[d.tier], d.last_deployed, cfg.stale_days, now)
    return DeploymentFinding(d, sla)


def _repo_finding(config: Config, a: RepoActivity | None, now: datetime) -> RepoFinding | None:
    if a is None:
        return None
    cfg = config.deployments
    limit = cfg.repo_inactive_days
    idle = (now - a.last_commit).days if a.last_commit else None
    if idle is not None and idle < limit:
        return None
    since = a.last_commit or a.created_at or now - timedelta(days=limit)
    return RepoFinding(a.last_commit, idle, _sla(config, cfg.repo_severity, since, limit, now))


def _why_unattributed(d: Deployment) -> str:
    if d.repo:
        return f"attributed to `{d.repo}`, which vulgard doesn't track"
    return "no repo found: tag the stack with `vulgard:repo` or add it to `deployments.attribution`"


def _no_decisions(repo: str, found: list[Deployment]) -> Decisions:
    return Decisions()


def _no_notices(repo: str) -> list[Notice]:
    return []


def _nothing_finished(repo: str) -> list[Finished]:
    return []


def evaluate(
    config: Config,
    deployments: list[Deployment],
    activity: list[RepoActivity],
    tracked: set[str],
    now: datetime,
    decide: Callable[[str, list[Deployment]], Decisions] = _no_decisions,
    notices_of: Callable[[str], list[Notice]] = _no_notices,
    vulnerable: frozenset[str] = frozenset(),
    finished_of: Callable[[str], list[Finished]] = _nothing_finished,
) -> dict[str, StaleReport]:
    """Pure given `decide` (repo, its deployments -> baselines), `notices_of` (repo -> the
    notices vulgard posted) and `finished_of` (repo -> the ops vulgard reported as ended).
    Groups deployments by repo and builds each repo's report.

    Deployments without a repo, or attributed to a repo vulgard doesn't track (archived or
    excluded), land in `deployments.unattributed_repo` with a note saying why. `vulnerable` repos
    have open critical alerts, which makes their personal deployments eligible for automatic ops.
    """
    cfg = config.deployments
    home = cfg.unattributed_repo or ""
    placed: dict[str, list[Deployment]] = {}
    notes: dict[str, dict[str, str]] = {}
    for d in deployments:
        if d.repo in tracked:
            placed.setdefault(d.repo or "", []).append(d)
        else:
            placed.setdefault(home, []).append(d)
            notes.setdefault(home, {})[d.key] = _why_unattributed(d)
    for a in activity:
        if a.repo in tracked:
            placed.setdefault(a.repo, [])
    by_repo = {a.repo: a for a in activity}

    reports: dict[str, StaleReport] = {}
    for repo, sighted in placed.items():
        if not repo:
            continue
        finished = finished_of(repo)
        found = confirmed(sighted, finished)
        decisions = decide(repo, found)
        findings: list[DeploymentFinding] = []
        kept: list[tuple[DeploymentFinding, Issued[Keep]]] = []
        for d in found:
            finding = _deployment_finding(config, d, now)
            if finding is None:
                continue
            keep = decisions.keeps.get(d.key)
            if keep:
                kept.append((finding, keep))
            else:
                findings.append(finding)
        repo_finding = None if decisions.active else _repo_finding(config, by_repo.get(repo), now)
        reports[repo] = StaleReport(
            repo=repo,
            deployments=found,
            notes=notes.get(repo, {}),
            decisions=decisions,
            deployment_findings=findings,
            kept=kept,
            repo_finding=repo_finding,
            requests=pending_requests(decisions, found),
            lifecycle=reconcile(
                found, decisions, notices_of(repo), cfg, repo in vulnerable, now, finished
            ),
        )
    return reports


@dataclass(frozen=True)
class Survey:
    """What discovery found, before any issue is read or written."""

    deployments: list[Deployment]
    activity: list[RepoActivity]


def survey(
    gh: Any, config: Config, repos: list[dict[str, Any]], scanners: list[Scanner], scoped: bool
) -> Survey:
    """Scan every control plane and read repo activity. `scoped` (from --repo) keeps only the
    deployments of `repos`, so a partial run never rewrites the unattributed repo's issue."""
    deployments = discover(scanners, build_index(gh, config, repos), config.deployments)
    if scoped:
        tracked = {r["name"] for r in repos}
        deployments = [d for d in deployments if d.repo in tracked]
    return Survey(deployments, repo_activity(gh, config, repos))
