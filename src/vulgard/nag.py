"""The tracking engine: applies topic plans to GitHub issues and Linear, for every topic.

It owns finding, creating, reopening, updating and closing tracking issues, and syncing the
Linear issue. What a topic considers dirty, and what it says, lives in the topic module.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, assert_never

import httpx

from .config import Config
from .github import GitHubError
from .linear import LinearClient, LinearError, sync_linear
from .plan import (
    Action,
    ActionKind,
    IssueComment,
    IssueOp,
    RepoPlan,
    RepoRun,
    TopicSpec,
    TrackedIssue,
    TrackingState,
)
from .policy import parse_time


def _tracked(raw: dict[str, Any], comments: tuple[IssueComment, ...] = ()) -> TrackedIssue:
    return TrackedIssue(
        number=raw["number"],
        open=raw.get("state", "open") == "open",
        body=raw.get("body") or "",
        html_url=raw.get("html_url", ""),
        comments=comments,
    )


def _comment(raw: dict[str, Any]) -> IssueComment:
    return IssueComment(
        id=raw["id"],
        author=(raw.get("user") or {}).get("login", ""),
        body=raw.get("body") or "",
        created_at=parse_time(raw["created_at"]),
        html_url=raw.get("html_url", ""),
    )


def load_issues(
    gh: Any, config: Config, spec: TopicSpec, repos: list[str]
) -> dict[str, TrackedIssue | None]:
    """The latest tracking issue (open first, else the most recently closed) per repo, with its
    comments for topics that read `/vulgard` commands."""
    issues: dict[str, TrackedIssue | None] = {}
    for repo in repos:
        raw = gh.find_issue(config.org, repo, spec.label)
        if raw is None:
            issues[repo] = None
            continue
        comments: tuple[IssueComment, ...] = ()
        if spec.reads_commands:
            listed = gh.list_issue_comments(config.org, repo, raw["number"])
            comments = tuple(_comment(c) for c in listed)
        issues[repo] = _tracked(raw, comments)
    return issues


def _individual_owners(owners: list[str]) -> list[str]:
    return [o.lstrip("@") for o in owners if "/" not in o]


def _write_issue(
    gh: Any, config: Config, plan: RepoPlan[Any], issue: TrackedIssue | None
) -> TrackedIssue | None:
    """Apply plan.op. The body (with the state) is written before comments, so a crash in
    between re-diffs to "nothing new" instead of posting twice."""
    org, repo, spec = config.org, plan.repo, plan.spec
    match plan.op:
        case IssueOp.NONE:
            return issue
        case IssueOp.CLOSE:
            assert issue is not None
            fields: dict[str, Any] = {"state": "closed"}
            if TrackingState.from_body(issue.body, spec.memory_type) != plan.state:
                fields["body"] = plan.render(plan.state)
            for c in plan.comments:
                gh.comment_issue(org, repo, issue.number, c)
            gh.update_issue(org, repo, issue.number, **fields)
            return issue
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
    return issue


def _apply(
    gh: Any,
    linear: LinearClient | None,
    config: Config,
    plan: RepoPlan[Any],
    issue: TrackedIssue | None,
    apply: bool,
) -> RepoRun:
    """One repo. A GitHub or Linear failure is recorded on its run and doesn't stop the others."""
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
    try:
        written = _write_issue(gh, config, plan, issue)
    except (GitHubError, httpx.HTTPError) as e:
        run.actions.append(Action(plan.repo, ActionKind.GITHUB_ERROR, str(e)))
        return run
    run.issue_url = written.html_url if written else None
    run.issue_number = written.number if written else None
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
