from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import timedelta
from functools import partial
from typing import Any

import httpx
from botocore.exceptions import BotoCoreError, ClientError

from . import stale
from .clients import Clients, live_clients
from .config import SEVERITIES, Config, load_config
from .enforce import apply_enforce, plan_enforce
from .estate import build_index, discover, repo_activity
from .fixtures import fixture_clients
from .github import GitHubError
from .linear import LinearError
from .plan import ActionKind, RepoRun, Topic
from .policy import (
    ClosedSummary,
    RepoReport,
    evaluate,
    now_utc,
    parse_codeowners_default,
    summarize_closed,
)
from .render import render_org_summary
from .rollout import apply_rollout, plan_rollout
from .slack import (
    SlackError,
    leaderboard_message,
    notify_slack,
    send_leaderboard,
    team_of_owners,
)
from .vercel import VercelError
from .vulns import nag

CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
STALE_ERRORS = (GitHubError, LinearError, VercelError, BotoCoreError, ClientError, httpx.HTTPError)


def selected_repos(gh: Any, config: Config, only: list[str] | None = None) -> list[dict]:
    repos = [
        r
        for r in gh.list_repos(config.org)
        if not r.get("archived") and config.repo_selected(r["name"])
    ]
    if only:
        repos = [r for r in repos if r["name"] in only]
    return repos


def resolve_owners(gh: Any, config: Config, repo: str) -> list[str]:
    if repo in config.owners:
        return config.owners[repo]
    for path in CODEOWNERS_PATHS:
        text = gh.get_file(config.org, repo, path)
        if text:
            owners = parse_codeowners_default(text)
            if owners:
                return owners
    return config.default_owners


def load_kev(clients: Clients, config: Config) -> frozenset[str]:
    if not config.kev.enabled:
        return frozenset()
    try:
        return clients.kev()
    except (httpx.HTTPError, ValueError, KeyError) as e:
        print(f"warning: couldn't load the CISA KEV catalog, skipping: {e}", file=sys.stderr)
        return frozenset()


def collect(
    gh: Any,
    config: Config,
    only: list[str] | None = None,
    kev: frozenset[str] = frozenset(),
) -> dict[str, RepoReport]:
    repos = [r["name"] for r in selected_repos(gh, config, only)]
    reports = evaluate(
        config,
        gh.list_open_alerts(config.org),
        gh.list_dependabot_prs(config.org),
        repos,
        kev=kev,
    )
    for report in reports.values():
        if report.alerts or report.dependabot_prs:
            report.owners = resolve_owners(gh, config, report.repo)
    return reports


def print_rows(header: list[str], rows: list[list[str]]) -> None:
    table = [header, *rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for i, row in enumerate(table):
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)))
        if i == 0:
            print("  ".join("-" * w for w in widths))


def print_table(reports: dict[str, RepoReport]) -> None:
    rows = sorted(
        (r for r in reports.values() if r.alerts or r.dependabot_prs), key=lambda r: -r.risk_score
    )
    if not rows:
        print(f"No open alerts or Dependabot PRs across {len(reports)} repos.")
        return
    header = [
        "repo", *SEVERITIES, "overdue", "due soon", "exploited", "ready PRs", "stale PRs", "owners"
    ]
    print_rows(
        header,
        [
            [
                r.repo,
                *(str(r.severity_counts()[s]) for s in SEVERITIES),
                str(len(r.overdue)),
                str(len(r.due_soon)),
                str(len(r.known_exploited)),
                str(len(r.ready_prs)),
                str(len(r.stale_prs)),
                " ".join(r.owners) or "-",
            ]
            for r in rows
        ],
    )


def report_json(reports: dict[str, RepoReport]) -> str:
    def encode(o: Any) -> Any:
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)

    payload = {name: asdict(r) for name, r in sorted(reports.items())}
    return json.dumps(payload, default=encode, indent=2)


def write_step_summary(markdown: str, path: str | None) -> None:
    target = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as f:
            f.write(markdown + "\n")


def report_stale(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    """Every deployment with its repo, attribution, tier and person; then inactive repos."""
    cfg, now = config.deployments, now_utc()
    repos = selected_repos(clients.github, config, args.repo)
    index = build_index(clients.github, config, repos)
    deployments = discover(clients.scanners(), index, cfg)
    if args.repo:
        deployments = [d for d in deployments if d.repo in args.repo]
    activity = repo_activity(clients.github, config, repos)
    if args.format == "json":
        payload = {
            "deployments": [
                {
                    "key": d.key,
                    "name": d.name,
                    "repo": d.repo,
                    "attributed_by": d.attributed_by,
                    "framework": d.framework,
                    "tier": d.tier,
                    "person": d.person,
                    "last_deployed": d.last_deployed.isoformat(),
                    "protected": d.sighting.protected,
                    "in_progress": d.sighting.in_progress,
                }
                for d in deployments
            ],
            "repos": {a.repo: a.last_commit.isoformat() if a.last_commit else None
                      for a in activity},
        }
        print(json.dumps(payload, indent=2))
        return 0
    shown = [d for d in deployments if args.all or (now - d.last_deployed).days >= cfg.stale_days]
    print(f"{len(shown)} of {len(deployments)} deployment(s)"
          + ("" if args.all else f" not deployed in {cfg.stale_days}+ days") + ":")
    print_rows(
        ["repo", "deployment", "framework", "tier", "person", "days", "repo from", "flags"],
        [
            [
                d.repo or "-",
                d.name,
                d.framework,
                d.tier,
                d.person or "-",
                str((now - d.last_deployed).days),
                d.attributed_by,
                " ".join(
                    f for f, on in (("protected", d.sighting.protected),
                                    ("deploying", d.sighting.in_progress)) if on
                ) or "-",
            ]
            for d in shown
        ],
    )
    inactive = sorted(
        (a for a in activity
         if a.last_commit is None or (now - a.last_commit).days >= cfg.repo_inactive_days),
        key=lambda a: a.last_commit or now,
    )
    print(f"\n{len(inactive)} of {len(activity)} repo(s) with no human commits in "
          f"{cfg.repo_inactive_days}+ days:")
    print_rows(
        ["repo", "last commit"],
        [[a.repo, f"{a.last_commit:%Y-%m-%d}" if a.last_commit else "never"] for a in inactive],
    )
    return 0


def cmd_report(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    if args.topic == Topic.STALE:
        return report_stale(clients, config, args)
    reports = collect(clients.github, config, args.repo, load_kev(clients, config))
    if args.format == "json":
        print(report_json(reports))
    elif args.format == "markdown":
        print(render_org_summary(config, reports))
    else:
        print_table(reports)
    return 0


def nag_topics(config: Config, args: argparse.Namespace) -> list[Topic]:
    if args.topic:
        return [Topic(t) for t in dict.fromkeys(args.topic)]
    return [Topic.VULNS] + ([Topic.STALE] if config.deployments.enabled else [])


def cmd_nag(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    gh, now = clients.github, now_utc()
    topics = nag_topics(config, args)
    if Topic.STALE in topics and not config.deployments.enabled:
        print("error: --topic stale needs deployments.enabled in the config", file=sys.stderr)
        return 1
    linear = clients.linear if args.linear else None
    if args.linear and linear is None:
        print(f"Skipping Linear: ${config.linear.api_key_env} is not set.", file=sys.stderr)

    runs: list[RepoRun] = []
    failed = False
    reports: dict[str, RepoReport] = {}
    closed: ClosedSummary | None = None
    if Topic.VULNS in topics:
        reports = collect(gh, config, args.repo, load_kev(clients, config))
        runs += nag(gh, config, reports, apply=args.apply, now=now, linear=linear)
        since = now - timedelta(days=7)
        closed = summarize_closed(gh.list_closed_alerts(config.org, since), set(reports), since)
    stale_reports: dict[str, stale.StaleReport] = {}
    stale_runs: list[RepoRun] = []
    if Topic.STALE in topics:
        try:
            stale_reports, stale_runs = stale.run(
                gh,
                linear,
                config,
                selected_repos(gh, config, args.repo),
                clients.scanners(),
                partial(resolve_owners, gh, config),
                args.apply,
                now,
                scoped=bool(args.repo),
            )
        except STALE_ERRORS as e:
            print(f"error: skipped stale deployments: {e}", file=sys.stderr)
            failed = True
        runs += stale_runs
    actions = [a for r in runs for a in r.actions]

    if args.slack:
        if clients.slack is None:
            print(
                f"Skipping Slack channel and DM messages: ${config.slack.token_env} is not set.",
                file=sys.stderr,
            )
        else:
            actions += notify_slack(clients.slack, config, runs, args.apply)
        if Topic.VULNS in topics and not args.no_leaderboard:
            assert closed is not None
            for repo in closed.fixed:
                if not reports[repo].owners:
                    reports[repo].owners = resolve_owners(gh, config, repo)
            sections = (
                stale.leaderboard_sections(stale_reports, stale_runs, team_of_owners, now)
                if Topic.STALE in topics and not failed
                else None
            )
            text, blocks = leaderboard_message(config, reports, closed, sections)
            send = partial(send_leaderboard, clients.slack, clients.slack_webhook, config)
            actions.append(send(text, blocks, args.apply))

    prefix = "" if args.apply else "[dry-run] "
    taken = [a for a in actions if a.kind != ActionKind.NOOP]
    if args.redact:
        for kind, n in sorted(Counter(a.kind for a in taken).items()):
            print(f"{prefix}{kind}: {n}")
    else:
        for a in taken:
            print(f"{prefix}{a.repo or 'slack'}: {a.kind} ({a.detail})")
        if Topic.VULNS in topics:
            write_step_summary(render_org_summary(config, reports, closed), args.summary_file)
        if stale_runs:
            write_step_summary(stale.render_summary(stale_reports), args.summary_file)
    repos = len(set(reports) | set(stale_reports))
    print(f"{prefix}{len(taken)} action(s) across {repos} repos.")
    return 1 if failed or any(a.kind.is_error for a in actions) else 0


def cmd_rollout(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    gh = clients.github
    prefix = "" if args.apply else "[dry-run] "
    for repo in selected_repos(gh, config, args.repo):
        if repo["name"] == config.rollout.workflow_repo:
            continue
        plan = plan_rollout(gh, config, repo)
        if plan.skipped_reason:
            print(f"{prefix}{plan.repo}: skip ({plan.skipped_reason})")
            continue
        files = ", ".join(plan.files)
        target = f"open rollout PR {plan.existing_pr}" if plan.existing_pr else "a new PR"
        if not args.apply:
            print(f"{prefix}{plan.repo}: would write {files} to {target}")
            if args.show:
                for path, content in plan.files.items():
                    print(f"\n--- {path} ---\n{content}")
            continue
        try:
            url = apply_rollout(gh, config, plan)
            print(f"{plan.repo}: {'updated' if plan.existing_pr else 'opened'} {url}")
        except GitHubError as e:
            print(f"{plan.repo}: failed: {e}", file=sys.stderr)
    return 0


def cmd_enforce(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    gh = clients.github
    repos = selected_repos(gh, config)
    try:
        plan = plan_enforce(gh, config, args.mode, repos)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    verb = "update" if plan.existing_id else "create"
    if args.mode == "status-check":
        print(
            f"Ruleset applies to {len(plan.enrolled)} enrolled repo(s): {', '.join(plan.enrolled)}"
        )
    if not args.apply:
        print(f"[dry-run] would {verb} org ruleset:\n{json.dumps(plan.ruleset, indent=2)}")
        return 0
    apply_enforce(gh, config, plan)
    print(f"{verb.capitalize()}d org ruleset '{plan.ruleset['name']}'.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulgard",
        description="Make your org actually fix vulnerable dependencies.",
    )
    parser.add_argument(
        "--config", default="vulgard.yml", help="config file (default: %(default)s)"
    )
    parser.add_argument("--org", help="GitHub org (overrides config)")
    parser.add_argument(
        "--fixtures", help="read GitHub data from a JSON fixture instead of the API"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_repo_filter(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", action="append", help="limit to this repo (repeatable)")

    p = sub.add_parser("report", help="show open alerts and SLA status per repo")
    p.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    p.add_argument(
        "--topic", choices=[t.value for t in Topic], default=Topic.VULNS, help="what to report"
    )
    p.add_argument(
        "--all", action="store_true", help="with --topic stale, list every deployment"
    )
    add_repo_filter(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("nag", help="open/update tracking issues, ping owners, escalate")
    p.add_argument("--apply", action="store_true", help="make changes (default is dry-run)")
    p.add_argument(
        "--slack", action="store_true", help="notify team channels, DM owners, post the leaderboard"
    )
    p.add_argument(
        "--linear", action="store_true", help="mirror tracking issues into Linear"
    )
    p.add_argument(
        "--summary-file", help="write markdown summary here (default $GITHUB_STEP_SUMMARY)"
    )
    p.add_argument(
        "--redact",
        action="store_true",
        help="print only action counts and skip the summary, for public workflow logs",
    )
    p.add_argument(
        "--topic",
        action="append",
        choices=[t.value for t in Topic],
        help="what to track (repeatable; default: vulns, plus stale when deployments.enabled)",
    )
    p.add_argument(
        "--no-leaderboard", action="store_true", help="with --slack, skip the leaderboard"
    )
    add_repo_filter(p)
    p.set_defaults(func=cmd_nag)

    p = sub.add_parser("rollout", help="open PRs adding dependabot.yml and the vulgard workflow")
    p.add_argument("--apply", action="store_true", help="open PRs (default is dry-run)")
    p.add_argument("--show", action="store_true", help="print the generated files in dry-run")
    add_repo_filter(p)
    p.set_defaults(func=cmd_rollout)

    p = sub.add_parser("enforce", help="create an org ruleset that makes the check required")
    p.add_argument("--mode", choices=["status-check", "workflow"], default="status-check")
    p.add_argument("--apply", action="store_true", help="write the ruleset (default is dry-run)")
    p.set_defaults(func=cmd_enforce)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config, args.org)
        clients = fixture_clients(args.fixtures) if args.fixtures else live_clients(config)
        return args.func(clients, config, args)
    except (ValueError, FileNotFoundError, GitHubError, LinearError, SlackError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
