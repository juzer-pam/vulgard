"""Baselines: human decisions, recorded as `/vulgard` commands on a repo's stale tracking issue.

The comment thread is the decision log. It's append-only, each comment has one authenticated
author, and it's re-folded from scratch every run, so vulgard keeps no copy of decisions that
could drift. The engine reopens tracking issues instead of recreating them, so the thread
outlives clean periods.

    /vulgard redeploy <name>                        bring it up to date
    /vulgard delete <name>                          delete it (never production)
    /vulgard keep <name> until <YYYY-MM-DD>: <why>  leave it as is until then
    /vulgard active until <YYYY-MM-DD>: <why>       the repo is maintained without commits
    /vulgard cancel <name>                          cancel a request, a keep or an automatic op
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import assert_never

from .estate import Deployment, Tier
from .plan import IssueComment

COMMAND_RE = re.compile(r"^[ \t]*/vulgard[ \t]+(?P<verb>\w+)[ \t]*(?P<rest>.*)$", re.M)
UNTIL_RE = re.compile(
    r"^(?:(?P<name>\S+)\s+)?until\s+(?P<date>\d{4}-\d{2}-\d{2})\s*:\s*(?P<why>.+)$"
)
COMMANDS = ("redeploy", "delete", "keep", "active", "cancel")


@dataclass(frozen=True)
class Redeploy:
    target: str  # deployment key


@dataclass(frozen=True)
class Delete:
    target: str


@dataclass(frozen=True)
class Keep:
    target: str
    until: date
    reason: str


@dataclass(frozen=True)
class Active:
    until: date
    reason: str


@dataclass(frozen=True)
class Cancel:
    target: str


type Command = Redeploy | Delete | Keep | Active | Cancel
type Request = Redeploy | Delete


@dataclass(frozen=True)
class Issued[C: Command]:
    """A command with its provenance. `comment_id` makes request ids deterministic."""

    command: C
    comment_id: int
    author: str
    at: datetime
    url: str


@dataclass(frozen=True)
class Rejection:
    """Shown in the issue body, so re-folding never posts a reply twice."""

    author: str
    url: str
    line: str
    reason: str


@dataclass(frozen=True)
class Decisions:
    """Effective decisions for one repo at `now`. The latest command per target wins."""

    keeps: Mapping[str, Issued[Keep]] = field(default_factory=dict)  # by key, unexpired
    active: Issued[Active] | None = None  # unexpired
    requests: Mapping[str, Issued[Request]] = field(default_factory=dict)
    cancels: Mapping[str, Issued[Cancel]] = field(default_factory=dict)
    rejected: tuple[Rejection, ...] = ()


def _until(rest: str, today: date, max_days: int) -> tuple[str | None, date, str] | str:
    m = UNTIL_RE.match(rest.strip())
    if not m:
        return "expected `until YYYY-MM-DD: why`"
    try:
        until = date.fromisoformat(m["date"])
    except ValueError:
        return f"{m['date']} isn't a date"
    if until <= today:
        return f"{until} is in the past"
    latest = today + timedelta(days=max_days)
    if until > latest:
        return f"keeps last at most {max_days} days; pick a date up to {latest}"
    return m["name"], until, m["why"].strip()


def parse_line(
    verb: str,
    rest: str,
    by_name: Mapping[str, Deployment],
    gone: frozenset[str],
    today: date,
    max_days: int,
) -> Command | str | None:
    """Pure. A command, why it was rejected, or None when it names a deployment that existed
    before and is gone now (moot, not wrong: typically a delete that worked)."""

    def resolve(name: str | None) -> Deployment | str | None:
        if not name:
            return f"`/vulgard {verb}` needs a deployment name"
        if name in gone:
            return None
        d = by_name.get(name)
        return d if d else f"no deployment named `{name}` in this repo"

    match verb:
        case "redeploy" | "delete" | "cancel":
            d = resolve(rest.split()[0] if rest.split() else None)
            if d is None or isinstance(d, str):
                return d
            if verb == "redeploy":
                return Redeploy(d.key)
            if verb == "cancel":
                return Cancel(d.key)
            if not deletable_by_request(d):
                return "vulgard never deletes production; delete it by hand if you really mean it"
            return Delete(d.key)
        case "keep":
            parsed = _until(rest, today, max_days)
            if isinstance(parsed, str):
                return parsed
            name, until, why = parsed
            d = resolve(name)
            return d if d is None or isinstance(d, str) else Keep(d.key, until, why)
        case "active":
            parsed = _until(rest, today, max_days)
            if isinstance(parsed, str):
                return parsed
            name, until, why = parsed
            if name:
                return "`/vulgard active` applies to the whole repo and takes no name"
            return Active(until, why)
        case _:
            return f"unknown command `{verb}`; use one of {', '.join(COMMANDS)}"


def fold(
    comments: tuple[IssueComment, ...],
    deployments: list[Deployment],
    may_command: Callable[[str], bool],
    now: datetime,
    max_days: int,
    seen: frozenset[str] = frozenset(),
) -> Decisions:
    """Pure given `may_command` (author -> has write access). Bot comments are skipped.
    `seen` holds deployment names from earlier runs, so commands for deleted ones are moot.

    Later commands for the same target supersede earlier ones: a keep cancels a request, a
    request cancels a keep, and cancel clears both. Expired keeps and actives drop out, so
    the finding comes back by itself.
    """
    by_name = {d.name: d for d in deployments}
    gone = frozenset(seen - by_name.keys())
    keeps: dict[str, Issued[Keep]] = {}
    requests: dict[str, Issued[Request]] = {}
    cancels: dict[str, Issued[Cancel]] = {}
    active: Issued[Active] | None = None
    rejected: list[Rejection] = []
    for c in sorted(comments, key=lambda c: (c.created_at, c.id)):
        if c.author.endswith("[bot]"):
            continue
        for m in COMMAND_RE.finditer(c.body):
            line = m[0].strip()
            verb, today = m["verb"].lower(), c.created_at.date()
            parsed = parse_line(verb, m["rest"], by_name, gone, today, max_days)
            if parsed is None:
                continue
            if isinstance(parsed, str):
                rejected.append(Rejection(c.author, c.html_url, line, parsed))
                continue
            if not may_command(c.author):
                reason = "only people with write access to the repo can baseline"
                rejected.append(Rejection(c.author, c.html_url, line, reason))
                continue
            match parsed:
                case Keep(target=t):
                    keeps[t] = Issued(parsed, c.id, c.author, c.created_at, c.html_url)
                    requests.pop(t, None)
                    cancels.pop(t, None)
                case Redeploy(target=t) | Delete(target=t):
                    requests[t] = Issued(parsed, c.id, c.author, c.created_at, c.html_url)
                    keeps.pop(t, None)
                    cancels.pop(t, None)
                case Cancel(target=t):
                    cancels[t] = Issued(parsed, c.id, c.author, c.created_at, c.html_url)
                    keeps.pop(t, None)
                    requests.pop(t, None)
                case Active():
                    active = Issued(parsed, c.id, c.author, c.created_at, c.html_url)
                case _ as unreachable:
                    assert_never(unreachable)
    today = now.date()
    return Decisions(
        keeps={k: v for k, v in keeps.items() if v.command.until > today},
        active=active if active and active.command.until > today else None,
        requests=requests,
        cancels=cancels,
        rejected=tuple(rejected),
    )


def is_satisfied(request: Issued[Request], d: Deployment | None) -> bool:
    """Read from the world: a redeploy is done once it was deployed after the comment, a delete
    once the deployment is gone."""
    match request.command:
        case Redeploy():
            return d is not None and d.last_deployed >= request.at
        case Delete():
            return d is None
        case _ as unreachable:
            assert_never(unreachable)


def deletable_by_request(d: Deployment) -> bool:
    return d.tier is not Tier.PRODUCTION and not d.sighting.protected
