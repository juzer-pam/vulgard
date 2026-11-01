"""The stale topic: deployments not deployed in 30 days and repos with no commits in 90.

Staleness is one more SLA, so escalation, Linear priority and severity labels, and the
leaderboard work the same way they do for alerts:

    flagged_at = last_deployed + stale_days      (or last_commit + repo_inactive_days)
    deadline   = flagged_at + baseline_days      (time to redeploy, delete, or keep)
    status     = ok / due-soon / overdue
    severity   = deployments.severity[tier]      (repos: deployments.repo_severity)

Every clock comes from cloud and GitHub timestamps and is never stored, so editing a tracking
issue can't reset it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache, partial
from typing import Any, Self, assert_never

from .baseline import (
    Active,
    Decisions,
    Issued,
    Keep,
    Redeploy,
    Rejection,
    Request,
    deletable_by_request,
    fold,
    is_satisfied,
)
from .config import SEVERITIES, Config
from .estate import Deployment, RepoActivity, Scanner, build_index, discover, repo_activity
from .linear import PRIORITY, LinearClient
from .nag import load_issues, track
from .plan import (
    Escalation,
    IssueOp,
    LeaderboardSection,
    LinearContent,
    RepoPlan,
    RepoRun,
    Topic,
    TopicSpec,
    TrackedIssue,
    TrackingState,
    issue_op,
)
from .policy import SlaStatus
from .render import SEVERITY_ICON

REPO_KEY = "repo"
BASELINED_DAYS = 14
CLOSED = "✅ Every deployment here is up to date or baselined, and the repo is active. Closing."


@dataclass(frozen=True)
class StaleDeployment:
    deployment: Deployment
    days: int  # since last deployed


@dataclass(frozen=True)
class InactiveRepo:
    last_commit: datetime | None
    days: int | None  # None: no commits at all


type Subject = StaleDeployment | InactiveRepo


@dataclass(frozen=True)
class StaleFinding:
    key: str  # deployment key, or REPO_KEY
    subject: Subject
    severity: str
    flagged_at: datetime
    deadline: datetime
    status: SlaStatus
    escalate: bool
    deadline_days: int  # negative when overdue

    @property
    def name(self) -> str:
        match self.subject:
            case StaleDeployment(deployment=d):
                return d.name
            case InactiveRepo():
                return "repo"
            case _ as unreachable:
                assert_never(unreachable)


@dataclass
class StaleReport:
    """Everything the planner renders for one repo."""

    repo: str
    owners: list[str]
    deployments: list[Deployment]  # attributed here, for the inventory
    notes: dict[str, str] = field(default_factory=dict)  # key -> why it landed in this repo
    findings: list[StaleFinding] = field(default_factory=list)  # needing a baseline
    kept: list[tuple[StaleFinding, Issued[Keep]]] = field(default_factory=list)
    active: Issued[Active] | None = None
    requests: list[tuple[Issued[Request], Deployment]] = field(default_factory=list)  # pending
    rejected: tuple[Rejection, ...] = ()

    @property
    def needs_tracking(self) -> bool:
        return bool(self.findings or self.requests)

    @property
    def overdue(self) -> list[StaleFinding]:
        return [f for f in self.findings if f.status is SlaStatus.OVERDUE]

    @property
    def persons(self) -> list[str]:
        found = [
            f.subject.deployment.person
            for f in self.findings
            if isinstance(f.subject, StaleDeployment) and f.subject.deployment.person
        ]
        return sorted({p for p in found if p not in self.owners})


@dataclass(frozen=True)
class StaleMemory:
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


type StaleState = TrackingState[StaleMemory]


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
        reads_commands=True,
        linear=cfg.linear,
    )


def _status(deadline: datetime, now: datetime, due_soon_days: int) -> tuple[SlaStatus, int]:
    left = (deadline - now).days
    if now > deadline:
        return SlaStatus.OVERDUE, left
    if left <= due_soon_days:
        return SlaStatus.DUE_SOON, left
    return SlaStatus.OK, left


def _finding(
    config: Config,
    key: str,
    subject: Subject,
    severity: str,
    since: datetime,
    days: int,
    now: datetime,
) -> StaleFinding:
    cfg = config.deployments
    flagged = since + timedelta(days=days)
    deadline = flagged + timedelta(days=cfg.baseline_days)
    status, left = _status(deadline, now, config.due_soon_days)
    esc = config.escalation
    escalate = (
        status is SlaStatus.OVERDUE
        and severity in esc.severities
        and -left >= esc.after_days_overdue
    )
    return StaleFinding(key, subject, severity, flagged, deadline, status, escalate, left)


def evaluate(
    config: Config,
    deployments: list[Deployment],
    activity: list[RepoActivity],
    decide: Callable[[str, list[Deployment]], Decisions],
    tracked: set[str],
    now: datetime,
) -> dict[str, StaleReport]:
    """Pure given `decide` (repo, its deployments -> baselines). Groups deployments by repo and
    builds findings. Owners are left empty for the caller to resolve.

    Deployments without a repo, or attributed to a repo vulgard doesn't track (archived or
    excluded), land in `deployments.unattributed_repo` with a note saying why.
    """
    cfg = config.deployments
    home = cfg.unattributed_repo or ""
    reports: dict[str, StaleReport] = {}

    def report(repo: str) -> StaleReport:
        if repo not in reports:
            reports[repo] = StaleReport(repo, [], [])
        return reports[repo]

    for d in deployments:
        if d.repo in tracked:
            r = report(d.repo)
        else:
            r = report(home)
            r.notes[d.key] = (
                f"attributed to `{d.repo}`, which vulgard doesn't track"
                if d.repo
                else "no repo found: tag the stack with `vulgard:repo` or add it to "
                "`deployments.attribution`"
            )
        r.deployments.append(d)
    for a in activity:
        if a.repo in tracked:
            report(a.repo)

    by_repo_activity = {a.repo: a for a in activity}
    for repo, r in reports.items():
        dec = decide(repo, r.deployments)
        r.active, r.rejected = dec.active, dec.rejected
        by_key = {d.key: d for d in r.deployments}
        for d in r.deployments:
            days = (now - d.last_deployed).days
            if days < cfg.stale_days:
                continue
            sev = cfg.severity[d.tier]
            subject = StaleDeployment(d, days)
            f = _finding(config, d.key, subject, sev, d.last_deployed, cfg.stale_days, now)
            keep = dec.keeps.get(d.key)
            if keep:
                r.kept.append((f, keep))
            else:
                r.findings.append(f)
        for key, req in dec.requests.items():
            d = by_key.get(key)
            if d is not None and not is_satisfied(req, d):
                r.requests.append((req, d))
        a = by_repo_activity.get(repo)
        idle_days = cfg.repo_inactive_days
        if a is not None:
            days_idle = (now - a.last_commit).days if a.last_commit else None
            if days_idle is None or days_idle >= idle_days:
                since = a.last_commit or a.created_at or now - timedelta(days=idle_days)
                if not r.active:
                    subject = InactiveRepo(a.last_commit, days_idle)
                    sev = cfg.repo_severity
                    finding = _finding(config, REPO_KEY, subject, sev, since, idle_days, now)
                    r.findings.append(finding)
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        r.findings.sort(key=lambda f: (f.deadline_days, rank[f.severity]))
    return {repo: r for repo, r in reports.items() if repo}


def run(
    gh: Any,
    linear: LinearClient | None,
    config: Config,
    repos: list[dict[str, Any]],
    scanners: list[Scanner],
    owners_of: Callable[[str], list[str]],
    apply: bool,
    now: datetime,
    scoped: bool = False,
) -> tuple[dict[str, StaleReport], list[RepoRun]]:
    """Discover, fold baselines from each tracking issue's comments, plan, and track.

    `scoped` (from --repo) keeps only deployments of `repos`, so the unattributed repo's issue
    isn't rewritten from a partial estate.
    """
    cfg, topic = config.deployments, spec(config)
    tracked = {r["name"] for r in repos}
    deployments = discover(scanners, build_index(gh, config, repos), cfg)
    home = {cfg.unattributed_repo} if cfg.unattributed_repo else set()
    if scoped:
        deployments = [d for d in deployments if d.repo in tracked]
        home &= tracked
    activity = repo_activity(gh, config, repos)
    issues = load_issues(gh, config, topic, sorted(tracked | home))

    @cache
    def may_command(repo: str, user: str) -> bool:
        return gh.can_write(config.org, repo, user)

    def decide(repo: str, found: list[Deployment]) -> Decisions:
        issue = issues.get(repo)
        if issue is None:
            return Decisions()
        seen = frozenset(TrackingState.from_body(issue.body, StaleMemory).memory.seen)
        allowed = partial(may_command, repo)
        return fold(issue.comments, found, allowed, now, cfg.max_keep_days, seen)

    reports = evaluate(config, deployments, activity, decide, tracked, now)
    for repo, r in reports.items():
        if r.needs_tracking or issues.get(repo):
            r.owners = owners_of(repo)
    plans = [plan_repo(r, config, issues.get(repo), now) for repo, r in sorted(reports.items())]
    return reports, track(gh, linear, config, plans, issues, apply)


# --- rendering


def _when(dt: datetime | None, now: datetime, relative: bool) -> str:
    if dt is None:
        return "never"
    if relative:
        return f"{dt:%Y-%m-%d} ({(now - dt).days}d ago)"
    return f"{dt:%Y-%m-%d}"


def _due(f: StaleFinding, relative: bool) -> str:
    if not relative:
        return f"baseline due {f.deadline:%Y-%m-%d}"
    if f.deadline_days < 0:
        return f"**baseline {-f.deadline_days}d overdue**"
    return f"baseline due in {f.deadline_days}d"


def commands_for(f: StaleFinding) -> str:
    match f.subject:
        case StaleDeployment(deployment=d):
            verbs = ["redeploy"] + (["delete"] if deletable_by_request(d) else [])
            cmds = [f"`/vulgard {v} {d.name}`" for v in verbs]
            cmds.append(f"`/vulgard keep {d.name} until YYYY-MM-DD: why`")
            return " · ".join(cmds)
        case InactiveRepo():
            return "`/vulgard active until YYYY-MM-DD: why`, or archive the repo"
        case _ as unreachable:
            assert_never(unreachable)


def finding_line(f: StaleFinding, now: datetime, relative: bool = True) -> str:
    icon = SEVERITY_ICON[f.severity]
    match f.subject:
        case StaleDeployment(deployment=d):
            who = f" · {d.person}" if d.person else ""
            busy = " · ⏳ deploy in progress" if d.sighting.in_progress else ""
            return (
                f"- {icon} **{d.tier}** `{d.name}` ({d.framework}): last deployed "
                f"{_when(d.last_deployed, now, relative)} · {_due(f, relative)}{who}{busy}"
            )
        case InactiveRepo(last_commit=last):
            return (
                f"- {icon} **repo**: no human commits on the default branch since "
                f"{_when(last, now, relative)} · {_due(f, relative)}"
            )
        case _ as unreachable:
            assert_never(unreachable)


def _finding_block(f: StaleFinding, now: datetime, relative: bool = True) -> list[str]:
    return [finding_line(f, now, relative), f"  {commands_for(f)}"]


def _sections(report: StaleReport, now: datetime, relative: bool = True) -> list[str]:
    lines: list[str] = []
    overdue = report.overdue
    pending = [f for f in report.findings if f.status is not SlaStatus.OVERDUE]
    for title, items in (("🚨 Baseline overdue", overdue), ("⏳ Needs a baseline", pending)):
        if items:
            lines += ["", f"### {title} ({len(items)})"]
            for f in items:
                lines += _finding_block(f, now, relative)
    if report.requests:
        lines += ["", f"### 🛠 Requested ({len(report.requests)})"]
        for req, d in report.requests:
            verb = "redeploy" if isinstance(req.command, Redeploy) else "delete"
            lines.append(
                f"- {verb} `{d.name}`, [requested]({req.url}) by @{req.author} on "
                f"{req.at:%Y-%m-%d}. This clears once vulgard sees it done."
            )
    return lines


def render_body(report: StaleReport, config: Config, state: StaleState, now: datetime) -> str:
    cfg = config.deployments
    lines = [
        f"Every deployment needs a deploy at least every **{cfg.stale_days} days**, and every repo "
        f"a human commit at least every **{cfg.repo_inactive_days} days**. Anything older needs a "
        f"baseline within **{cfg.baseline_days} days**: bring it up to date, delete it, or record "
        "why it stays as it is by commenting one of the commands below on this issue.",
    ]
    if report.owners:
        lines += ["", f"Owners: {' '.join(report.owners)}"]
    if state.linear:
        lines += ["", f"Tracked in Linear: [{state.linear.identifier}]({state.linear.url})"]
    lines += _sections(report, now)
    if report.kept:
        lines += ["", f"### 🗂 Kept ({len(report.kept)})"]
        for f, keep in report.kept:
            assert isinstance(f.subject, StaleDeployment)
            lines.append(
                f"- `{f.subject.deployment.name}` kept until **{keep.command.until}** by "
                f"[@{keep.author}]({keep.url}): {keep.command.reason}"
            )
    if report.active:
        a = report.active
        lines += [
            "",
            f"Marked active until **{a.command.until}** by [@{a.author}]({a.url}): "
            f"{a.command.reason}",
        ]
    if report.rejected:
        lines += ["", f"### ⚠️ Commands vulgard didn't accept ({len(report.rejected)})"]
        lines += [f"- [@{r.author}]({r.url}) `{r.line}`: {r.reason}" for r in report.rejected]
    if report.deployments:
        lines += [
            "",
            "<details><summary>All deployments of this repo</summary>",
            "",
            "| Deployment | Framework | Tier | Last deployed | Repo from |",
            "|---|---|---|---|---|",
        ]
        for d in report.deployments:
            how = report.notes.get(d.key, d.attributed_by)
            lines.append(
                f"| `{d.name}` | {d.framework} | {d.tier} | {d.last_deployed:%Y-%m-%d} | {how} |"
            )
        lines += ["", "</details>"]
    lines += [
        "",
        "<details><summary>Commands</summary>",
        "",
        "- `/vulgard redeploy <name>`: bring it up to date from the default branch",
        "- `/vulgard delete <name>`: delete it (never production)",
        "- `/vulgard keep <name> until YYYY-MM-DD: why`: leave it as it is until then",
        "- `/vulgard active until YYYY-MM-DD: why`: the repo is maintained without commits",
        "- `/vulgard cancel <name>`: cancel an earlier command",
        "",
        "Deploying, deleting, committing or archiving by hand works too: vulgard sees it on its "
        "next run.",
        "</details>",
        "",
        "---",
        f"_Updated by vulgard on {now:%Y-%m-%d %H:%M} UTC. This issue closes itself once every "
        "deployment is baselined. Please don't edit it by hand; changes are overwritten._",
        state.to_comment(),
    ]
    return "\n".join(lines)


def render_description(report: StaleReport, config: Config, now: datetime) -> str:
    n = len(report.findings)
    return "\n".join(
        [
            f"**{report.repo}** has {n} deployment(s) or repo checks that need a baseline.",
            *_sections(report, now, relative=False),
            "",
            "---",
            "_Synced by vulgard. Record a baseline by commenting a `/vulgard` command on the "
            "GitHub issue; this issue closes itself once everything is baselined._",
        ]
    )


def _worst(report: StaleReport) -> str | None:
    present = {f.severity for f in report.findings}
    return next((s for s in SEVERITIES if s in present), None)


def _digest(report: StaleReport, newly: int) -> str:
    parts = [f"*{newly} newly stale*"] if newly else []
    deployments = [f for f in report.findings if isinstance(f.subject, StaleDeployment)]
    if deployments:
        parts.append(f"{len(deployments)} deployment(s) need a baseline")
    if report.overdue:
        parts.append(f"{len(report.overdue)} overdue")
    repo = next((f for f in report.findings if isinstance(f.subject, InactiveRepo)), None)
    if repo is not None:
        assert isinstance(repo.subject, InactiveRepo)
        days = repo.subject.days
        parts.append(f"no commits in {days}d" if days is not None else "no commits")
    return ", ".join(parts)


def plan_repo(
    report: StaleReport, config: Config, issue: TrackedIssue | None, now: datetime
) -> RepoPlan[StaleMemory]:
    """Pure. Mirrors vulns.plan_repo: announce what's new, remind, escalate."""
    topic = spec(config)
    prev = TrackingState.from_body(issue.body if issue else None, StaleMemory)
    op = issue_op(issue, report.needs_tracking)
    current = {f.key for f in report.findings}
    resolved = [k for k in prev.memory.flagged if k not in current]
    cutoff = (now - timedelta(days=BASELINED_DAYS)).date().isoformat()
    baselined = tuple(
        sorted(
            {b for b in prev.memory.baselined if b[1] >= cutoff}
            | {(k, now.date().isoformat()) for k in resolved}
        )
    )

    seen = tuple(sorted(set(prev.memory.seen) | {d.name for d in report.deployments}))

    def render(state: StaleState) -> str:
        return render_body(report, config, state, now)

    if op in (IssueOp.CLOSE, IssueOp.NONE):
        memory = StaleMemory(seen=seen, baselined=baselined)
        state = TrackingState(memory, prev.last_reminder, prev.linear)
        comments = [CLOSED] if op == IssueOp.CLOSE else []
        return RepoPlan(topic, report.repo, report.owners, op, state, "baselined", render, comments)

    fresh = op in (IssueOp.CREATE, IssueOp.REOPEN)
    newly = [f for f in report.findings if f.key not in prev.memory.flagged]
    newly_overdue = [f for f in report.overdue if f.key not in prev.memory.overdue]
    escalate = [f for f in report.findings if f.escalate and f.key not in prev.memory.escalated]
    reminder_due = prev.last_reminder is None or (
        (now - prev.last_reminder).days >= config.reminder_interval_days
    )
    mentions = " ".join([*report.owners, *report.persons])
    comments: list[str] = []
    detail = None
    if op == IssueOp.REOPEN or (not fresh and (newly or newly_overdue)):
        news = sorted(
            {f.key: f for f in [*newly, *newly_overdue]}.values(), key=lambda f: f.deadline_days
        )
        lines = [line for f in news for line in _finding_block(f, now)]
        comments.append(
            f"{mentions} {len(news)} item(s) need a baseline. Comment a command to record one:"
            "\n\n" + "\n".join(lines)
        )
        detail = f"{len(newly)} newly stale, {len(newly_overdue)} newly overdue"
    elif not fresh and reminder_due and report.findings:
        comments.append(
            f"{mentions} Reminder: {len(report.findings)} item(s) still need a baseline "
            f"({len(report.overdue)} overdue). See the list in the issue description."
        )
        detail = "periodic reminder"
    escalation = None
    if escalate:
        leads = "".join(f"{m} " for m in config.escalation.mentions)
        text = (
            f"Escalating: these are more than {config.escalation.after_days_overdue} days past "
            "their baseline deadline."
        )
        comments.append(f"{leads}{text}\n\n" + "\n".join(finding_line(f, now) for f in escalate))
        worst = ", ".join(
            f"{f.severity} `{f.name}` {-f.deadline_days}d overdue" for f in escalate[:3]
        )
        more = f" (+{len(escalate) - 3} more)" if len(escalate) > 3 else ""
        escalation = Escalation(
            detail=f"{len(escalate)} item(s)",
            linear_md=f"{text}\n\n"
            + "\n".join(finding_line(f, now, relative=False) for f in escalate),
            slack_detail=worst + more,
        )

    state = TrackingState(
        StaleMemory(
            seen=seen,
            flagged=tuple(sorted(current)),
            overdue=tuple(sorted(f.key for f in report.overdue)),
            escalated=tuple(
                sorted(set(prev.memory.escalated) & current | {f.key for f in escalate})
            ),
            baselined=baselined,
        ),
        last_reminder=now if comments or fresh else prev.last_reminder,
        linear=prev.linear,
    )
    worst = _worst(report)
    fields: dict[str, Any] = {
        "title": f"{report.repo}: {topic.title}",
        "description": render_description(report, config, now),
        "priority": PRIORITY[worst or "low"],
    }
    if report.findings:
        fields["dueDate"] = min(f.deadline for f in report.findings).date().isoformat()
    linear = LinearContent(
        fields=fields,
        worst_severity=worst,
        reopened="Reopened by vulgard: deployments in this repo need a baseline again.",
        news=(
            ["\n".join(finding_line(f, now, relative=False) for f in newly)]
            if newly and not fresh
            else []
        ),
    )
    pinged = fresh or newly or newly_overdue or escalate or detail
    return RepoPlan(
        topic,
        report.repo,
        report.owners,
        op,
        state,
        f"{len(report.findings)} item(s)",
        render,
        comments,
        comment_detail=detail,
        linear=linear,
        escalation=escalation,
        digest=_digest(report, len(newly)) if pinged else None,
        dm=tuple(report.persons),
    )


def render_summary(reports: Mapping[str, StaleReport]) -> str:
    """Markdown for the workflow step summary."""
    ranked = sorted(
        (r for r in reports.values() if r.findings),
        key=lambda r: (-len(r.overdue), -len(r.findings), r.repo),
    )
    if not ranked:
        return "## 🧹 Stale deployments\n\nEverything is up to date or baselined. 🎉"
    lines = [
        "## 🧹 Stale deployments",
        "",
        "| Repo | Need a baseline | Overdue | Requested | Owners |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {r.repo} | {len(r.findings)} | {len(r.overdue)} | {len(r.requests)} | "
        f"{' '.join(r.owners) or '-'} |"
        for r in ranked
    ]
    return "\n".join(lines)


# --- leaderboard


def leaderboard_sections(
    reports: Mapping[str, StaleReport],
    runs: list[RepoRun],
    team_of: Callable[[list[str]], str],
    now: datetime,
) -> list[LeaderboardSection]:
    """Most baselined this week (medals) and most overdue baselines, by team."""
    week = (now - timedelta(days=7)).date().isoformat()
    baselined: Counter[str] = Counter()
    for run in runs:
        memory = run.plan.state.memory
        if isinstance(memory, StaleMemory):
            baselined[team_of(run.plan.owners)] += sum(1 for _, d in memory.baselined if d >= week)
    overdue: Counter[str] = Counter()
    stale: Counter[str] = Counter()
    for r in reports.values():
        overdue[team_of(r.owners)] += len(r.overdue)
        stale[team_of(r.owners)] += len(r.findings)
    total = sum(stale.values())
    sections = [
        LeaderboardSection(
            f"🧹 Stale deployments: {total} need a baseline, {sum(overdue.values())} overdue",
            [],
        )
    ]
    if +baselined:
        rows = [f"{team}: {n}" for team, n in (+baselined).most_common()]
        sections.append(LeaderboardSection("Most baselined this week", rows, medals=True))
    if +overdue:
        rows = [f"{team}: {n} overdue" for team, n in (+overdue).most_common()]
        sections.append(LeaderboardSection("Most overdue baselines", rows))
    return sections

