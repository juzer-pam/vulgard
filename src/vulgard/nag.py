"""The tracking engine: applies topic plans to GitHub issues and Linear, for every topic.

It owns finding, creating, reopening, updating and closing tracking issues, and syncing the
Linear issue. What a topic considers dirty, and what it says, lives in the topic module.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, assert_never

import httpx

from .config import Config
from .linear import LinearClient, LinearError, sync_linear
from .plan import Action, ActionKind, IssueOp, RepoPlan, RepoRun, TopicSpec, TrackedIssue


def _tracked(raw: dict[str, Any]) -> TrackedIssue:
    return TrackedIssue(
        number=raw["number"],
        open=raw.get("state", "open") == "open",
        body=raw.get("body") or "",
        html_url=raw.get("html_url", ""),
    )


def load_issues(
    gh: Any, config: Config, spec: TopicSpec, repos: list[str]
) -> dict[str, TrackedIssue | None]:
    """The latest tracking issue (open first, else the most recently closed) per repo."""
    issues: dict[str, TrackedIssue | None] = {}
    for repo in repos:
        raw = gh.find_issue(config.org, repo, spec.label)
        issues[repo] = _tracked(raw) if raw else None
    return issues


def _individual_owners(owners: list[str]) -> list[str]:
    return [o.lstrip("@") for o in owners if "/" not in o]


def _write_issue(
    gh: Any, config: Config, plan: RepoPlan[Any], issue: TrackedIssue | None
) -> str | None:
    """Apply plan.op. The body (with the state) is written before comments, so a crash in
    between re-diffs to "nothing new" instead of posting twice."""
    org, repo, spec = config.org, plan.repo, plan.spec
    match plan.op:
        case IssueOp.NONE:
            return issue.html_url if issue else None
        case IssueOp.CLOSE:
            assert issue is not None
            for c in plan.comments:
                gh.comment_issue(org, repo, issue.number, c)
            gh.update_issue(org, repo, issue.number, state="closed")
            return issue.html_url
        case IssueOp.CREATE:
            gh.ensure_label(org, repo, spec.label)
            raw = gh.create_issue(
                org,
                repo,
                spec.title,
                plan.render(plan.state),
                [spec.label],
                _individual_owners(plan.owners),
            )
            issue = _tracked(raw)
        case IssueOp.REOPEN:
            assert issue is not None
            gh.update_issue(org, repo, issue.number, state="open", body=plan.render(plan.state))
        case IssueOp.UPDATE:
            assert issue is not None
            body = plan.render(plan.state)
            if body != issue.body:
                gh.update_issue(org, repo, issue.number, body=body)
        case _ as unreachable:
            assert_never(unreachable)
    for c in plan.comments:
        gh.comment_issue(org, repo, issue.number, c)
    return issue.html_url


def _apply(
    gh: Any,
    linear: LinearClient | None,
    config: Config,
    plan: RepoPlan[Any],
    issue: TrackedIssue | None,
    apply: bool,
) -> RepoRun:
    run = RepoRun(plan, issue.html_url if issue else None, plan.actions())
    created_in_linear = False
    if linear is not None:
        try:
            result = sync_linear(linear, config, plan, apply)
        except (LinearError, httpx.HTTPError) as e:
            run.actions.append(Action(plan.repo, ActionKind.LINEAR_ERROR, str(e)))
        else:
            run.actions += result.actions
            plan.state = replace(plan.state, linear=result.ref)
            created_in_linear = result.created
    if not apply:
        return run
    run.issue_url = _write_issue(gh, config, plan, issue)
    ref = plan.state.linear
    if linear is not None and created_in_linear and ref and run.issue_url:
        try:
            linear.attach_url(ref.id, run.issue_url, f"{plan.repo} tracking issue")
        except (LinearError, httpx.HTTPError) as e:
            run.actions.append(Action(plan.repo, ActionKind.LINEAR_ERROR, str(e)))
    return run


def track(
    gh: Any,
    linear: LinearClient | None,
    config: Config,
    plans: list[RepoPlan[Any]],
    issues: dict[str, TrackedIssue | None],
    apply: bool,
) -> list[RepoRun]:
    """The only writer of tracking issues and tracked Linear issues, for every topic."""
    return [_apply(gh, linear, config, p, issues.get(p.repo), apply) for p in plans]
