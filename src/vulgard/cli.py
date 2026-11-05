from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from typing import Any

from . import inspector_render, stale_render
from .clients import Clients, live_clients
from .config import SEVERITIES, Config, load_config
from .enforce import apply_enforce, plan_enforce
from .estate import ScanError
from .fixtures import fixture_clients
from .github import GitHubError
from .linear import LinearError
from .plan import ActionKind, Topic
from .policy import RepoReport, now_utc
from .render import format_table, render_org_summary
from .repos import build_index, resolve_owners, selected_repos
from .rollout import apply_rollout, merge_open_rollout_prs, plan_lifecycle_rollout, plan_rollout
from .rollout_onboarding import collect_open_rollout_prs, sync_rollout_onboarding
from .slack import (
    RolloutPR,
    SlackError,
    leaderboard_message,
    notify_leads,
    notify_slack,
    send_leaderboard,
)
from .stale import survey
from .topics import RUNNERS, NagContext, inspector_report, load_kev
from .vulns import collect


def print_rows(header: list[str], rows: list[list[str]]) -> None:
    print(format_table(header, rows))


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
    repos = selected_repos(clients.github, config, args.repo)
    found = survey(clients.github, config, repos, clients.scanners(), scoped=bool(args.repo))
    if args.format == "json":
        print(json.dumps(stale_render.survey_json(found), indent=2))
    else:
        print(stale_render.survey_text(found, config.deployments, now_utc(), args.all))
    return 0


def report_inspector(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    _, report = inspector_report(clients, config, args.repo)
    if args.format == "json":
        print(json.dumps(inspector_render.report_json(report), indent=2))
    else:
        print(inspector_render.report_text(report, config.inspector))
    return 0


def cmd_report(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    if args.topic == Topic.STALE:
        return report_stale(clients, config, args)
    if args.topic == Topic.INSPECTOR:
        return report_inspector(clients, config, args)
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
    enabled = {Topic.STALE: config.deployments.enabled, Topic.INSPECTOR: config.inspector.enabled}
    return [Topic.VULNS] + [topic for topic, on in enabled.items() if on]


def cmd_nag(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    topics = nag_topics(config, args)
    if Topic.STALE in topics and not config.deployments.enabled:
        print("error: --topic stale needs deployments.enabled in the config", file=sys.stderr)
        return 1
    if Topic.INSPECTOR in topics and not config.inspector.enabled:
        print("error: --topic inspector needs inspector.enabled in the config", file=sys.stderr)
        return 1
    if args.execute and Topic.STALE not in topics:
        print("error: --execute only applies to the stale topic", file=sys.stderr)
        return 1
    linear = clients.linear if args.linear else None
    if args.linear and linear is None:
        print(
            "Skipping Linear: no Linear API key is set (see linear.api_key_env).", file=sys.stderr
        )

    now = now_utc()
    ctx = NagContext(
        clients=clients,
        config=config,
        only=args.repo,
        apply=args.apply,
        execute=args.execute,
        leaderboard=args.slack and not args.no_leaderboard and config.slack.leaderboard_due(now),
        now=now,
        linear=linear,
    )
    results = [RUNNERS[topic](ctx) for topic in topics]
    runs = [run for res in results for run in res.runs]
    actions = [a for run in runs for a in run.actions] + [a for res in results for a in res.actions]

    if args.slack:
        if clients.slack is None:
            print(
                f"Skipping Slack channel and DM messages: ${config.slack.token_env} is not set.",
                file=sys.stderr,
            )
        else:
            actions += notify_slack(clients.slack, config, runs, args.apply)
        if any(res.leaderboard for res in results):
            text, payload = leaderboard_message([res.leaderboard for res in results])
            actions.append(
                send_leaderboard(
                    clients.slack, clients.slack_webhook, config, text, payload, args.apply
                )
            )

    prefix = "" if args.apply else "[dry-run] "
    taken = [a for a in actions if a.kind != ActionKind.NOOP]
    if args.redact:
        for kind, n in sorted(Counter(a.kind for a in taken).items()):
            print(f"{prefix}{kind}: {n}")
    else:
        for a in taken:
            where = a.repo or ("linear" if a.kind.startswith("linear") else "slack")
            print(f"{prefix}{where}: {a.kind} ({a.detail})")
        for res in results:
            if res.summary:
                write_step_summary(res.summary, args.summary_file)
    repos = {repo for res in results for repo in res.repos}
    print(f"{prefix}{len(taken)} action(s) across {len(repos)} repos.")
    failed = any(res.failed for res in results) or any(a.kind.is_error for a in actions)
    return 1 if failed else 0


def cmd_rollout(clients: Clients, config: Config, args: argparse.Namespace) -> int:
    gh = clients.github
    prefix = "" if args.apply else "[dry-run] "
    own = config.rollout.workflow_repo
    repos = [r for r in selected_repos(gh, config, args.repo) if r["name"] != own]
    if args.lifecycle:
        frameworks = build_index(gh, config, repos).frameworks
        plans = [
            plan_lifecycle_rollout(gh, config, r, frameworks.get(r["name"], frozenset()))
            for r in repos
        ]
    else:
        plans = [plan_rollout(gh, config, r) for r in repos]
    tally: Counter[str] = Counter()

    def report(outcome: str, line: str, error: bool = False) -> None:
        tally[outcome] += 1
        if not args.redact:
            print(f"{prefix}{line}", file=sys.stderr if error else sys.stdout)

    open_prs: list[tuple[str, str | None]] = []
    for plan in plans:
        if plan.skipped_reason:
            report("skip", f"{plan.repo}: skip ({plan.skipped_reason})")
            if plan.existing_pr:
                open_prs.append((plan.repo, plan.existing_pr))
            continue
        files = ", ".join(plan.files)
        target = f"open rollout PR {plan.existing_pr}" if plan.existing_pr else "a new PR"
        if not args.apply:
            report("would write", f"{plan.repo}: would write {files} to {target}")
            if args.show and not args.redact:
                for path, content in plan.files.items():
                    print(f"\n--- {path} ---\n{content}")
            open_prs.append((plan.repo, plan.existing_pr))
            continue
        try:
            url = apply_rollout(gh, config, plan)
            verb = "updated" if plan.existing_pr else "opened"
            report(verb, f"{plan.repo}: {verb} {url}")
            open_prs.append((plan.repo, url))
        except GitHubError as e:
            report("failed", f"{plan.repo}: failed: {e}", error=True)
    seeded = [
        RolloutPR(repo, resolve_owners(gh, config, repo), url) for repo, url in open_prs
    ]
    rollout_prs = collect_open_rollout_prs(gh, config, seeded)
    team_tickets: dict[str, str] = {}
    if args.linear:
        linear = clients.linear
        if linear is None:
            print(
                "Skipping Linear onboarding: no Linear API key is set (see linear.api_key_env).",
                file=sys.stderr,
            )
        else:
            team_tickets, linear_actions = sync_rollout_onboarding(
                linear, config, rollout_prs, args.apply
            )
            for a in linear_actions:
                report(a.kind, f"{a.repo or 'linear'}: {a.kind} ({a.detail})", a.kind.is_error)
    slack = clients.slack
    if args.slack and slack is None:
        print(f"Skipping team lead DMs: ${config.slack.token_env} is not set.", file=sys.stderr)
    elif args.slack and slack is not None:
        for a in notify_leads(slack, config, rollout_prs, args.apply, team_tickets):
            report(a.kind, f"{a.repo or 'slack'}: {a.kind} ({a.detail})", a.kind.is_error)
    if args.merge:
        merge_repos = [r for r in selected_repos(gh, config, args.repo) if r["name"] != own]
        if not args.apply:
            for repo in merge_repos:
                pr = gh.find_open_pr(config.org, repo["name"], config.rollout.branch)
                if pr:
                    report("would merge", f"{repo['name']}: would merge {pr['html_url']}")
        else:
            for name, url, err in merge_open_rollout_prs(gh, config, merge_repos):
                if err:
                    report("merge failed", f"{name}: merge failed ({err}): {url}", error=True)
                else:
                    report("merged", f"{name}: merged {url}")
    if args.redact:
        for outcome, n in sorted(tally.items()):
            print(f"{prefix}{outcome}: {n}")
    return 1 if tally["failed"] or tally["merge failed"] else 0


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
        choices=[t.value for t in RUNNERS],
        help="what to track (repeatable; default: vulns, plus stale when deployments.enabled "
        "and inspector when inspector.enabled)",
    )
    p.add_argument(
        "--no-leaderboard", action="store_true", help="with --slack, skip the leaderboard"
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="with --apply, carry out requested and due automatic redeploys and deletes",
    )
    add_repo_filter(p)
    p.set_defaults(func=cmd_nag)

    p = sub.add_parser("rollout", help="open PRs adding dependabot.yml and the vulgard workflow")
    p.add_argument("--apply", action="store_true", help="open PRs (default is dry-run)")
    p.add_argument("--show", action="store_true", help="print the generated files in dry-run")
    p.add_argument(
        "--slack", action="store_true", help="DM each team lead their open rollout PRs to approve"
    )
    p.add_argument(
        "--linear",
        action="store_true",
        help="create one onboarding issue per team and link open rollout PRs",
    )
    p.add_argument(
        "--redact", action="store_true", help="print only outcome counts, for public workflow logs"
    )
    p.add_argument(
        "--merge",
        action="store_true",
        help="with --apply, squash-merge every open rollout PR after writing branches",
    )
    p.add_argument(
        "--lifecycle",
        action="store_true",
        help="instead, add vulgard-lifecycle.yml to repos with Serverless, SST or CDK apps",
    )
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
    except (ValueError, FileNotFoundError, GitHubError, LinearError, ScanError, SlackError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
