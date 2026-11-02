from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from typing import Any

from . import stale_render
from .clients import Clients, live_clients
from .config import SEVERITIES, Config, load_config
from .enforce import apply_enforce, plan_enforce
from .fixtures import fixture_clients
from .github import GitHubError
from .linear import LinearError
from .plan import ActionKind, Topic
from .policy import RepoReport, now_utc
from .render import format_table, render_org_summary
from .repos import build_index, selected_repos
from .rollout import apply_rollout, plan_lifecycle_rollout, plan_rollout
from .slack import SlackError, leaderboard_message, notify_slack, send_leaderboard
from .stale import survey
from .topics import RUNNERS, NagContext, load_kev
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
    topics = nag_topics(config, args)
    if Topic.STALE in topics and not config.deployments.enabled:
        print("error: --topic stale needs deployments.enabled in the config", file=sys.stderr)
        return 1
    if args.execute and Topic.STALE not in topics:
        print("error: --execute only applies to the stale topic", file=sys.stderr)
        return 1
    linear = clients.linear if args.linear else None
    if args.linear and linear is None:
        print(f"Skipping Linear: ${config.linear.api_key_env} is not set.", file=sys.stderr)

    ctx = NagContext(
        clients=clients,
        config=config,
        only=args.repo,
        apply=args.apply,
        execute=args.execute,
        leaderboard=args.slack and not args.no_leaderboard,
        now=now_utc(),
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
        blocks = [block for res in results for block in res.leaderboard]
        if blocks:
            text, payload = leaderboard_message(blocks)
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
            print(f"{prefix}{a.repo or 'slack'}: {a.kind} ({a.detail})")
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
    for plan in plans:
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
    except (ValueError, FileNotFoundError, GitHubError, LinearError, SlackError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
