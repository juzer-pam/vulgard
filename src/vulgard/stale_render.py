"""Everything the stale topic says: the issue body, the Linear description, comments, the step
summary, the leaderboard blocks and the `report --topic stale` tables."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, assert_never

from .baseline import Redeploy
from .config import Config, DeploymentsConfig, team_of_owners
from .lifecycle import PAST, RUN_FAILED, RUNNING_NOW, Op, Trigger
from .plan import RepoRun, TrackingState
from .policy import SlaStatus
from .render import SEVERITY_ICON, format_table
from .slack import ranking
from .stale import (
    DeploymentFinding,
    Finding,
    RepoFinding,
    Sla,
    StaleMemory,
    StaleReport,
    Survey,
)

MAX_ITEMS = 40  # per section, so a catch-all repo's issue stays under GitHub's body limit
MAX_INVENTORY = 50
MAX_REJECTED = 20


def _when(dt: datetime | None, now: datetime, relative: bool) -> str:
    if dt is None:
        return "never"
    if relative:
        return f"{dt:%Y-%m-%d} ({(now - dt).days}d ago)"
    return f"{dt:%Y-%m-%d}"


def _due(sla: Sla, relative: bool) -> str:
    if not relative:
        return f"baseline due {sla.deadline:%Y-%m-%d}"
    if sla.days_left < 0:
        return f"**baseline {-sla.days_left}d overdue**"
    return f"baseline due in {sla.days_left}d"


def commands_for(f: Finding) -> str:
    match f:
        case DeploymentFinding(deployment=d):
            verbs = ["redeploy"] + (["delete"] if d.delete_refusal is None else [])
            cmds = [f"`/vulgard {v} {d.name}`" for v in verbs]
            cmds.append(f"`/vulgard keep {d.name} until YYYY-MM-DD: why`")
            return " · ".join(cmds)
        case RepoFinding():
            return "`/vulgard active until YYYY-MM-DD: why`, or archive the repo"
        case _ as unreachable:
            assert_never(unreachable)


def finding_line(f: Finding, now: datetime, relative: bool = True) -> str:
    icon = SEVERITY_ICON[f.sla.severity]
    match f:
        case DeploymentFinding(deployment=d, sla=sla):
            who = f" · {d.person}" if d.person else ""
            busy = " · ⏳ deploy in progress" if d.sighting.in_progress else ""
            return (
                f"- {icon} **{d.tier}** `{d.name}` ({d.framework}): last deployed "
                f"{_when(d.last_deployed, now, relative)} · {_due(sla, relative)}{who}{busy}"
            )
        case RepoFinding(last_commit=last, sla=sla):
            return (
                f"- {icon} **repo**: no human commits on the default branch since "
                f"{_when(last, now, relative)} · {_due(sla, relative)}"
            )
        case _ as unreachable:
            assert_never(unreachable)


def finding_block(f: Finding, now: datetime, relative: bool = True) -> list[str]:
    return [finding_line(f, now, relative), f"  {commands_for(f)}"]


def _request_status(blocked: str | None) -> str:
    if blocked is None:
        return "This clears once vulgard sees it done."
    if blocked == RUNNING_NOW:
        return "In progress. vulgard checks again on the next run."
    if blocked == RUN_FAILED:
        return (
            "Its run failed (see vulgard's comment). Fix the cause, then do it by hand or post "
            "the command again."
        )
    return f"vulgard can't do this one: {blocked}. Do it by hand."


def _requested(report: StaleReport) -> list[str]:
    if not report.requests:
        return []
    blocked = {o.deployment.key: o.blocked for o in report.lifecycle.ops if o.blocked}
    lines = ["", f"### Requested ({len(report.requests)})"]
    for req, d in report.requests:
        verb = "redeploy" if isinstance(req.command, Redeploy) else "delete"
        lines.append(
            f"- {verb} `{d.name}`, [requested]({req.url}) by @{req.author} on "
            f"{req.at:%Y-%m-%d}. {_request_status(blocked.get(d.key))}"
        )
    return lines


def _stop(name: str) -> str:
    return f"Stop it with `/vulgard keep {name} until YYYY-MM-DD: why` or `/vulgard cancel {name}`."


def _due_op(op: Op) -> str:
    d = op.deployment
    if op.blocked == RUNNING_NOW:
        what = "is already running."
    elif op.blocked:
        what = f"can't be {PAST[op.verb]} automatically: {op.blocked}."
    else:
        what = f"is due to be **{PAST[op.verb]}** at the next `--execute` run. {_stop(d.name)}"
    return f"- `{d.name}` ({d.person}) {what}"


def _automatic(report: StaleReport) -> list[str]:
    life = report.lifecycle
    due = [op for op in life.ops if op.trigger is not Trigger.REQUEST]
    if not (due or life.scheduled):
        return []
    lines = ["", f"### Automatic ({len(due) + len(life.scheduled)})"]
    lines += [_due_op(op) for op in due]
    for s in life.scheduled:
        d = s.deployment
        lines.append(
            f"- `{d.name}` ({d.person}) will be **{PAST[s.verb]}** on **{s.due:%Y-%m-%d}**. "
            f"{_stop(d.name)}"
        )
    return lines


def sections(report: StaleReport, now: datetime, relative: bool = True) -> list[str]:
    lines: list[str] = []
    pending = [f for f in report.findings if f.sla.status is not SlaStatus.OVERDUE]
    for title, items in (("🚨 Baseline overdue", report.overdue), ("⏳ Needs a baseline", pending)):
        if not items:
            continue
        lines += ["", f"### {title} ({len(items)})"]
        for f in items[:MAX_ITEMS]:
            lines += finding_block(f, now, relative)
        if len(items) > MAX_ITEMS:
            more = len(items) - MAX_ITEMS
            lines.append(f"- …and {more} more. `vulgard report --topic stale` lists them all.")
    return lines + _requested(report) + _automatic(report)


def render_body(
    report: StaleReport, config: Config, state: TrackingState[StaleMemory], now: datetime
) -> str:
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
    lines += sections(report, now)
    if report.kept:
        lines += ["", f"### Kept ({len(report.kept)})"]
        for f, keep in report.kept[:MAX_ITEMS]:
            lines.append(
                f"- `{f.name}` kept until **{keep.command.until}** by "
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
        lines += ["", f"### Commands vulgard didn't accept ({len(report.rejected)})"]
        lines += [
            f"- [@{r.author}]({r.url}) `{r.line}`: {r.reason}"
            for r in report.rejected[:MAX_REJECTED]
        ]
    if report.deployments:
        shown = report.deployments[:MAX_INVENTORY]
        lines += [
            "",
            "<details><summary>All deployments of this repo</summary>",
            "",
            "| Deployment | Framework | Tier | Last deployed | Repo from |",
            "|---|---|---|---|---|",
        ]
        for d in shown:
            how = report.notes.get(d.key, d.attributed_by)
            lines.append(
                f"| `{d.name}` | {d.framework} | {d.tier} | {d.last_deployed:%Y-%m-%d} | {how} |"
            )
        if len(report.deployments) > len(shown):
            lines += ["", f"…and {len(report.deployments) - len(shown)} more."]
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


def render_description(report: StaleReport, now: datetime) -> str:
    n = len(report.findings)
    return "\n".join(
        [
            f"**{report.repo}** has {n} deployment(s) or repo checks that need a baseline.",
            *sections(report, now, relative=False),
            "",
            "---",
            "_Synced by vulgard. Record a baseline by commenting a `/vulgard` command on the "
            "GitHub issue; this issue closes itself once everything is baselined._",
        ]
    )


def render_summary(reports: Mapping[str, StaleReport]) -> str:
    """Markdown for the workflow step summary."""
    ranked = sorted(
        (r for r in reports.values() if r.findings),
        key=lambda r: (-len(r.overdue), -len(r.findings), r.repo),
    )
    if not ranked:
        return "## Stale deployments\n\nEverything is up to date or baselined."
    lines = [
        "## Stale deployments",
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


def leaderboard_blocks(
    reports: Mapping[str, StaleReport], runs: list[RepoRun], now: datetime
) -> list[str]:
    """Most baselined this week (medals) and most overdue baselines, by team."""
    week = (now - timedelta(days=7)).date().isoformat()
    baselined: Counter[str] = Counter()
    for run in runs:
        memory = run.plan.state.memory
        if isinstance(memory, StaleMemory):
            team = team_of_owners(run.plan.owners)
            baselined[team] += sum(1 for _, d in memory.baselined if d >= week)
    overdue: Counter[str] = Counter()
    stale: Counter[str] = Counter()
    for r in reports.values():
        team = team_of_owners(r.owners)
        overdue[team] += len(r.overdue)
        stale[team] += len(r.findings)
    blocks = [
        f"*Stale deployments: {sum(stale.values())} need a baseline, "
        f"{sum(overdue.values())} overdue*"
    ]
    if +baselined:
        rows = [f"{team}: {n}" for team, n in (+baselined).most_common()]
        blocks.append(ranking("Most baselined this week", rows, medals=True))
    if +overdue:
        rows = [f"{team}: {n} overdue" for team, n in (+overdue).most_common()]
        blocks.append(ranking("Most overdue baselines", rows, medals=False))
    return blocks


def survey_text(s: Survey, cfg: DeploymentsConfig, now: datetime, show_all: bool) -> str:
    """Every deployment with its repo, attribution, tier and person; then inactive repos."""
    shown = [d for d in s.deployments if show_all or (now - d.last_deployed).days >= cfg.stale_days]
    scope = "" if show_all else f" not deployed in {cfg.stale_days}+ days"
    rows = []
    for d in shown:
        marks = (("protected", d.sighting.protected), ("deploying", d.sighting.in_progress))
        flags = " ".join(name for name, on in marks if on) or "-"
        days = str((now - d.last_deployed).days)
        person = d.person or "-"
        row = [d.repo or "-", d.name, d.framework, d.tier, person, days, d.attributed_by, flags]
        rows.append(row)
    inactive = sorted(
        (
            a
            for a in s.activity
            if a.last_commit is None or (now - a.last_commit).days >= cfg.repo_inactive_days
        ),
        key=lambda a: a.last_commit or now,
    )
    repo_rows = [
        [a.repo, f"{a.last_commit:%Y-%m-%d}" if a.last_commit else "never"] for a in inactive
    ]
    header = ["repo", "deployment", "framework", "tier", "person", "days", "repo from", "flags"]
    return "\n".join(
        [
            f"{len(shown)} of {len(s.deployments)} deployment(s){scope}:",
            format_table(header, rows),
            "",
            f"{len(inactive)} of {len(s.activity)} repo(s) with no human commits in "
            f"{cfg.repo_inactive_days}+ days:",
            format_table(["repo", "last commit"], repo_rows),
        ]
    )


def survey_json(s: Survey) -> dict[str, Any]:
    return {
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
            for d in s.deployments
        ],
        "repos": {a.repo: a.last_commit.isoformat() if a.last_commit else None for a in s.activity},
    }
