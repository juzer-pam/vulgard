"""One runner per topic for `nag`, so the command loops over topics instead of branching on them.

A runner reads what it needs, plans and writes its tracking issues through the engine, and
returns a `TopicResult` with everything `nag` combines across topics: the runs for Slack, the
step summary, and the leaderboard blocks.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from functools import cache, cached_property, partial
from typing import Any

import httpx

from . import inspector_plan, inspector_sla, stale_render
from .baseline import Decisions, fold
from .clients import Clients
from .config import Config
from .estate import Deployment, ScanError, discover
from .execute import Outcome, execute, result_comment
from .github import GitHubError
from .inspector import (
    InspectorReport,
    attributed_repos,
    branch_dependencies,
    build_report,
    is_shared_asset_image,
)
from .inspector_render import parent_description, render_summary, unattributed_description
from .inspector_sla import (
    PARENT_CLOSED,
    SPEC,
    TITLE,
    UNATTRIBUTED_CLOSED,
    UNATTRIBUTED_TITLE,
    InspectorMemory,
    InspectorRepo,
)
from .lifecycle import Finished, Notice, describe, finished_from, notices_from
from .linear import CLOSED_STATES, LinearClient, LinearError, sync_team_issue
from .nag import load_issues, track
from .plan import (
    Action,
    ActionKind,
    LinearRef,
    RepoPlan,
    RepoRun,
    Topic,
    TrackedIssue,
    TrackingState,
)
from .policy import DependabotPR, RepoReport, summarize_closed
from .render import render_org_summary
from .repos import build_index, is_public, resolve_owners, selected_repos
from .slack import Block
from .stale import StaleMemory, StaleReport, evaluate, spec, survey
from .stale_plan import plan_repo
from .vulns import collect, critical_repos, leaderboard_blocks, nag

SCAN_ERRORS = (ScanError, GitHubError, httpx.HTTPError)


def load_kev(clients: Clients, config: Config) -> frozenset[str]:
    if not config.kev.enabled:
        return frozenset()
    try:
        return clients.kev()
    except (httpx.HTTPError, ValueError, KeyError) as e:
        print(f"warning: couldn't load the CISA KEV catalog, skipping: {e}", file=sys.stderr)
        return frozenset()


@dataclass
class NagContext:
    clients: Clients
    config: Config
    only: list[str] | None  # --repo
    apply: bool
    execute: bool
    leaderboard: bool  # build leaderboard blocks, which costs extra lookups
    now: datetime
    linear: LinearClient | None

    @cached_property
    def reports(self) -> dict[str, RepoReport]:
        """Open alerts per repo, collected once however many topics need them."""
        kev = load_kev(self.clients, self.config)
        return collect(self.clients.github, self.config, self.only, kev)


@dataclass
class TopicResult:
    runs: list[RepoRun] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)  # beyond what the runs carry
    summary: str | None = None  # markdown for the workflow step summary
    leaderboard: list[Block] = field(default_factory=list)  # Slack Block Kit blocks
    repos: set[str] = field(default_factory=set)
    failed: bool = False


def run_vulns(ctx: NagContext) -> TopicResult:
    gh, config = ctx.clients.github, ctx.config
    reports = ctx.reports
    runs = nag(gh, config, reports, apply=ctx.apply, now=ctx.now, linear=ctx.linear)
    since = ctx.now - timedelta(days=7)
    closed = summarize_closed(gh.list_closed_alerts(config.org, since), set(reports), since)
    blocks: list[Block] = []
    if ctx.leaderboard:
        for repo in closed.fixed:
            if not reports[repo].owners:
                reports[repo].owners = resolve_owners(gh, config, repo)
        blocks = leaderboard_blocks(config, reports, closed)
    return TopicResult(
        runs=runs,
        summary=render_org_summary(config, reports, closed),
        leaderboard=blocks,
        repos=set(reports),
    )


def _stale_pass(ctx: NagContext) -> tuple[dict[str, StaleReport], list[RepoRun]]:
    """Discover, fold baselines from each tracking issue's comments, plan, and track. With
    `deployments.report_only` nothing is written and no runs are returned."""
    gh, config = ctx.clients.github, ctx.config
    cfg, topic = config.deployments, spec(config)
    repos = selected_repos(gh, config, ctx.only)
    tracked = {r["name"] for r in repos}
    found = survey(gh, config, repos, ctx.clients.scanners(), scoped=bool(ctx.only))
    home = {cfg.unattributed_repo} if cfg.unattributed_repo else set()
    if ctx.only:
        home &= tracked
    issues = load_issues(gh, config, topic, sorted(tracked | home))
    vulnerable = critical_repos(ctx.reports) if cfg.auto.repos else frozenset()

    @cache
    def may_command(repo: str, user: str) -> bool:
        return gh.can_write(config.org, repo, user)

    def decide(repo: str, deployments: list[Deployment]) -> Decisions:
        issue = issues.get(repo)
        if issue is None:
            return Decisions()
        state = TrackingState.from_body(issue.body, StaleMemory)
        seen = frozenset(state.memory.seen)
        allowed = partial(may_command, repo)
        return fold(issue.comments, deployments, allowed, ctx.now, cfg.max_keep_days, seen)

    def notices_of(repo: str) -> list[Notice]:
        issue = issues.get(repo)
        return notices_from(issue.comments) if issue else []

    def finished_of(repo: str) -> list[Finished]:
        issue = issues.get(repo)
        return finished_from(issue.comments) if issue else []

    reports = evaluate(
        config,
        found.deployments,
        found.activity,
        tracked,
        ctx.now,
        decide,
        notices_of,
        vulnerable,
        finished_of,
    )
    reports = {
        repo: replace(r, owners=resolve_owners(gh, config, repo))
        if r.needs_tracking or issues.get(repo)
        else r
        for repo, r in reports.items()
    }
    if cfg.report_only:
        return reports, []
    plans = [plan_repo(r, config, issues.get(repo), ctx.now) for repo, r in sorted(reports.items())]
    return reports, track(gh, ctx.linear, config, plans, issues, ctx.apply)


def _execute_ops(
    ctx: NagContext, reports: dict[str, StaleReport], runs: list[RepoRun]
) -> list[Action]:
    """Run each repo's due ops after its issue was written, and comment on what started or
    failed. Without `apply`, only says what would run."""
    gh, config = ctx.clients.github, ctx.config
    executor = ctx.clients.executor()
    actions: list[Action] = []
    for run in runs:
        report = reports[run.repo]
        for op in report.lifecycle.ops:
            if not ctx.apply:
                what = "would" if op.runnable else f"can't ({op.blocked})"
                actions.append(Action(run.repo, ActionKind.EXECUTE, f"{what} {describe(op)}"))
                continue
            result = execute(op, executor, config.deployments)
            failed = result.outcome in (Outcome.FAILED, Outcome.RUN_FAILED)
            kind = ActionKind.EXECUTE_ERROR if failed else ActionKind.EXECUTE
            actions.append(Action(run.repo, kind, f"{result.outcome}: {describe(op)}"))
            mentions = " ".join(p for p in [op.deployment.person, *report.owners] if p)
            comment = result_comment(result, mentions)
            if comment and run.issue_number is not None:
                try:
                    gh.comment_issue(config.org, run.repo, run.issue_number, comment)
                except (GitHubError, httpx.HTTPError) as e:
                    actions.append(Action(run.repo, ActionKind.GITHUB_ERROR, str(e)))
    return actions


def run_stale(ctx: NagContext) -> TopicResult:
    cfg = ctx.config.deployments
    try:
        reports, runs = _stale_pass(ctx)
    except SCAN_ERRORS as e:
        print(f"error: skipped stale deployments: {e}", file=sys.stderr)
        return TopicResult(failed=True)
    if cfg.report_only:
        n = sum(1 for r in reports.values() if r.findings)
        print(f"Stale deployments are report-only: {n} repo(s) would get a tracking issue.")
    blocks: list[Block] = []
    if ctx.leaderboard and not cfg.report_only:
        blocks = stale_render.leaderboard_blocks(reports, runs, ctx.now)
    return TopicResult(
        runs=runs,
        actions=_execute_ops(ctx, reports, runs) if ctx.execute else [],
        summary=stale_render.render_summary(reports),
        leaderboard=blocks,
        repos=set(reports),
    )


def inspector_report(
    clients: Clients, config: Config, only: list[str] | None
) -> tuple[list[dict[str, Any]], InspectorReport]:
    """Inspector's findings as fix items, for `report` and `nag`, with the selected repos.
    `only` (from --repo) keeps just those repos and drops the unattributed buckets."""
    gh = clients.github
    repos = selected_repos(gh, config)
    deployments = discover(clients.scanners(), build_index(gh, config, repos), config.deployments)
    source = clients.inspector()
    findings = source.findings()
    runners = source.runners() if any(is_shared_asset_image(f.resource) for f in findings) else []
    scope = set(only) if only else None
    prs: defaultdict[str, list[DependabotPR]] = defaultdict(list)
    for raw in gh.list_dependabot_prs(config.org):
        pr = DependabotPR.from_api(raw)
        prs[pr.repo].append(pr)
    in_report = attributed_repos(findings, deployments, config.inspector, runners)
    branches = {
        repo: branch_dependencies(sbom)
        for repo in sorted(in_report & scope if scope else in_report)
        if (sbom := gh.get_sbom(config.org, repo)) is not None
    }
    report = build_report(findings, deployments, config.inspector, scope, prs, branches, runners)
    return repos, report


def _linear_team(config: Config, repo: InspectorRepo) -> str | None:
    target = config.linear.target(repo.repo, repo.owners)
    return target.team if target else None


def _linear_ref(issue: dict[str, Any]) -> LinearRef:
    return LinearRef(issue["id"], issue["identifier"], issue["url"])


def _sub_issue_repo(title: str) -> str | None:
    suffix = f": {TITLE}"
    return title.removesuffix(suffix) if title.endswith(suffix) else None


@dataclass
class _Parents:
    """Each team's parent issue id, and the repo sub-issues already under the parents."""

    ids: dict[str, str] = field(default_factory=dict)
    sub_issues: dict[str, dict[str, Any]] = field(default_factory=dict)
    actions: list[Action] = field(default_factory=list)


def _sync_parents(ctx: NagContext, linear: LinearClient, repos: list[InspectorRepo]) -> _Parents:
    """One parent issue per team that has repos with items. A --repo run sees only some repos,
    so it reads the parents but never writes them."""
    config = ctx.config
    by_team: defaultdict[str, list[InspectorRepo]] = defaultdict(list)
    for repo in repos:
        if repo.items and (team := _linear_team(config, repo)):
            by_team[team].append(repo)
    teams = {route.team for route in config.linear.teams.values()} | set(by_team)
    if config.linear.default_team:
        teams.add(config.linear.default_team)
    found = _Parents()
    for team in sorted(teams):
        try:
            parent = linear.find_issue(team, TITLE)
            for child in linear.sub_issues(parent["id"]) if parent else []:
                if (name := _sub_issue_repo(child["title"])) is not None:
                    found.sub_issues[name] = child
            ref = _linear_ref(parent) if parent else None
            if not ctx.only:
                description = parent_description(by_team[team]) if by_team[team] else None
                result = sync_team_issue(
                    linear, config, team, TITLE, description, PARENT_CLOSED, parent, ctx.apply
                )
                found.actions += result.actions
                ref = result.ref
        except (LinearError, httpx.HTTPError) as e:
            found.actions.append(Action(None, ActionKind.LINEAR_ERROR, f"team {team}: {e}"))
            continue
        if ref is not None:
            found.ids[team] = ref.id
    return found


def _sync_unattributed(
    ctx: NagContext, linear: LinearClient, report: InspectorReport
) -> list[Action]:
    """One issue in `linear.default_team` for the findings with no repo. Never on GitHub."""
    config = ctx.config
    team = config.linear.default_team
    if team is None:
        why = "findings with no repo: set linear.default_team"
        return [Action(None, ActionKind.LINEAR_SKIP, why)] if report.unattributed else []
    description = unattributed_description(report.unattributed) if report.unattributed else None
    try:
        existing = linear.find_issue(team, UNATTRIBUTED_TITLE)
        result = sync_team_issue(
            linear,
            config,
            team,
            UNATTRIBUTED_TITLE,
            description,
            UNATTRIBUTED_CLOSED,
            existing,
            ctx.apply,
        )
    except (LinearError, httpx.HTTPError) as e:
        return [Action(None, ActionKind.LINEAR_ERROR, f"team {team}: {e}")]
    return result.actions


def _linear_issue(
    linear: LinearClient, config: Config, repo: InspectorRepo, parents: _Parents
) -> dict[str, Any] | None:
    """A repo's Linear issue: the sub-issue under its team's parent, else the issue with its
    title in its team, which a --repo run may have created without a parent."""
    issue = parents.sub_issues.get(repo.repo)
    if issue is None and repo.items and (team := _linear_team(config, repo)):
        issue = linear.find_issue(team, f"{repo.repo}: {TITLE}")
    return issue


def _inspector_pass(
    ctx: NagContext,
) -> tuple[list[InspectorRepo], InspectorReport, list[RepoRun], list[Action]]:
    """A GitHub issue per selected private repo with items, a Linear sub-issue per repo under
    a parent issue per team, and one Linear issue for findings with no repo. Public repos, and
    repos vulgard doesn't select, are tracked in Linear only, so only with --linear. With
    `inspector.report_only` nothing is written and no runs are returned."""
    gh, config, linear = ctx.clients.github, ctx.config, ctx.linear
    selected, report = inspector_report(ctx.clients, config, ctx.only)
    private = {r["name"] for r in selected if not is_public(r)}
    if ctx.only:
        private &= set(ctx.only)
    issues = load_issues(gh, config, SPEC, sorted(private))
    states = {
        repo: TrackingState.from_body(issue.body if issue else None, InspectorMemory)
        for repo, issue in issues.items()
    }
    owners = {repo: resolve_owners(gh, config, repo) for repo in report.by_repo}

    def assess(repo: str) -> InspectorRepo:
        memory = states[repo].memory if repo in states else InspectorMemory()
        items = report.by_repo.get(repo, [])
        return inspector_sla.evaluate(
            repo, items, memory, config, ctx.now, repo in private, owners.get(repo, [])
        )

    assessed = {repo: assess(repo) for repo in sorted(private | set(report.by_repo))}
    if config.inspector.report_only:
        return list(assessed.values()), report, [], []
    actions: list[Action] = []
    parents = _Parents()
    if linear is None:
        skipped = sum(1 for r in assessed.values() if r.items and not r.github)
        if skipped:
            print(
                f"Skipping {skipped} repo(s) that are tracked in Linear only: pass --linear.",
                file=sys.stderr,
            )
    else:
        parents = _sync_parents(ctx, linear, list(assessed.values()))
        actions += parents.actions
        for name in sorted(parents.sub_issues.keys() - assessed.keys()):
            if not ctx.only or name in ctx.only:
                assessed[name] = assess(name)
    plans: list[RepoPlan[InspectorMemory]] = []
    for repo in assessed.values():
        team = _linear_team(config, repo)
        parent = parents.ids.get(team) if team else None
        if repo.github:
            state, open_issue = states[repo.repo], _open(issues[repo.repo])
            if state.linear is None and repo.repo in parents.sub_issues:
                state = replace(state, linear=_linear_ref(parents.sub_issues[repo.repo]))
        elif linear is None:
            continue
        else:
            try:
                found = _linear_issue(linear, config, repo, parents)
            except (LinearError, httpx.HTTPError) as e:
                actions.append(Action(repo.repo, ActionKind.LINEAR_ERROR, str(e)))
                continue
            state = TrackingState(InspectorMemory(), linear=_linear_ref(found) if found else None)
            open_issue = None if found is None else found["state"]["type"] not in CLOSED_STATES
        plans.append(inspector_plan.plan_repo(repo, config, state, open_issue, ctx.now, parent))
    runs = track(gh, linear, config, plans, issues, ctx.apply)
    if linear is not None and not ctx.only:
        actions += _sync_unattributed(ctx, linear, report)
    return list(assessed.values()), report, runs, actions


def _open(issue: TrackedIssue | None) -> bool | None:
    return None if issue is None else issue.open


def run_inspector(ctx: NagContext) -> TopicResult:
    cfg = ctx.config.inspector
    try:
        repos, report, runs, actions = _inspector_pass(ctx)
    except SCAN_ERRORS as e:
        print(f"error: skipped Inspector findings: {e}", file=sys.stderr)
        return TopicResult(failed=True)
    if cfg.report_only:
        n = sum(1 for r in repos if r.items)
        print(f"Inspector findings are report-only: {n} repo(s) have fix items.")
    return TopicResult(
        runs=runs,
        actions=actions,
        summary=render_summary(repos, report.unattributed, cfg),
        repos={r.repo for r in repos},
    )


RUNNERS: dict[Topic, Callable[[NagContext], TopicResult]] = {
    Topic.VULNS: run_vulns,
    Topic.STALE: run_stale,
    Topic.INSPECTOR: run_inspector,
}
