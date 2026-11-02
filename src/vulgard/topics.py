"""One runner per topic for `nag`, so the command loops over topics instead of branching on them.

A runner reads what it needs, plans and writes its tracking issues through the engine, and
returns a `TopicResult` with everything `nag` combines across topics: the runs for Slack, the
step summary, and the leaderboard blocks.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from functools import cache, cached_property, partial

import httpx

from . import stale_render
from .baseline import Decisions, fold
from .clients import Clients
from .config import Config
from .estate import Deployment, ScanError
from .execute import Outcome, execute, result_comment
from .github import GitHubError
from .lifecycle import Finished, Notice, describe, finished_from, notices_from
from .linear import LinearClient
from .nag import load_issues, track
from .plan import Action, ActionKind, RepoRun, Topic, TrackingState
from .policy import RepoReport, summarize_closed
from .render import render_org_summary
from .repos import resolve_owners, selected_repos
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
    leaderboard: list[str] = field(default_factory=list)  # Slack mrkdwn blocks
    repos: set[str] = field(default_factory=set)
    failed: bool = False


def run_vulns(ctx: NagContext) -> TopicResult:
    gh, config = ctx.clients.github, ctx.config
    reports = ctx.reports
    runs = nag(gh, config, reports, apply=ctx.apply, now=ctx.now, linear=ctx.linear)
    since = ctx.now - timedelta(days=7)
    closed = summarize_closed(gh.list_closed_alerts(config.org, since), set(reports), since)
    blocks: list[str] = []
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
    blocks: list[str] = []
    if ctx.leaderboard and not cfg.report_only:
        blocks = stale_render.leaderboard_blocks(reports, runs, ctx.now)
    return TopicResult(
        runs=runs,
        actions=_execute_ops(ctx, reports, runs) if ctx.execute else [],
        summary=stale_render.render_summary(reports),
        leaderboard=blocks,
        repos=set(reports),
    )


RUNNERS: dict[Topic, Callable[[NagContext], TopicResult]] = {
    Topic.VULNS: run_vulns,
    Topic.STALE: run_stale,
}
