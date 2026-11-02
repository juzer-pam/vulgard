"""Lifecycle: turn baselines into redeploys and deletes. Pure policy, no I/O.

Ops come from two sources.

A request is a `/vulgard redeploy|delete <name>` comment from someone with write access. The
next `nag --apply --execute` run carries it out.

An automatic op targets a PERSONAL deployment in an `auto.repos` repo that hasn't deployed in
`auto.personal_stale_days`, or whose repo has open critical alerts. vulgard first posts a
notice on the tracking issue. It acts once `auto.notice_days` have passed since that comment
was posted. `/vulgard keep` or `/vulgard cancel` stops it.

The notice time comes from the bot's own comment, never from the issue body, because anyone
with write access can edit the body. A notice only counts when it is newer than the
deployment's last deploy and than the last keep, so a stale notice can't fire an op later.

Every delete carries a `SafeDelete` from `check_delete`, and `recheck` repeats the same rules
against the live target right before the delete.

Each op has a deterministic `request_id`. Every API receives it as an idempotency key: the
workflow run name, the CloudFormation `ClientRequestToken`, the Amplify `jobReason` and the
Vercel `meta`. `execute` looks for an existing op with that id before it starts one. When it
finds one that ended, vulgard says so once, in a comment with a hidden `vulgard-op` marker.
Later runs read the marker back: a successful redeploy counts as a deploy, and a failed op is
blocked until someone posts a new command.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from enum import StrEnum
from typing import Any, assert_never

from .baseline import Decisions, Delete, Issued, Redeploy, Request, pending_requests
from .config import DeploymentsConfig, Tier
from .estate import (
    EMPTY_INDEX,
    AmplifyBranch,
    CfnStack,
    Deployment,
    Framework,
    Sighting,
    SstStage,
    VercelProject,
    classify,
)
from .plan import IssueComment

RUNNING_NOW = "a deploy or delete is running right now"
NO_REPO = "no repo to run it from; attribute the deployment first"
SANDBOX = "Amplify sandboxes run from a laptop (`npx ampx sandbox`); delete it instead"
RUN_FAILED = "its run failed (see vulgard's comment)"
NOTICE_RE = re.compile(r"<!-- vulgard-notice (\{.*?\}) -->")
FINISHED_RE = re.compile(r"<!-- vulgard-op (\{.*?\}) -->")


class Verb(StrEnum):
    REDEPLOY = "redeploy"
    DELETE = "delete"


class Trigger(StrEnum):
    REQUEST = "request"  # a /vulgard command
    STALE = "stale"  # personal, not deployed in auto.personal_stale_days
    VULNERABLE = "vulnerable"  # personal, in a repo with open critical alerts


PAST = {Verb.REDEPLOY: "redeployed", Verb.DELETE: "deleted"}
TRIGGER_WHY = {
    Trigger.REQUEST: "requested",
    Trigger.STALE: "personal and not deployed recently",
    Trigger.VULNERABLE: "personal, and the repo has open critical alerts",
}


@dataclass(frozen=True)
class SafeDelete:
    """Proof that a deployment passed `check_delete`. Executors delete only with one."""

    deployment: Deployment


def check_delete(d: Deployment, automatic: bool) -> SafeDelete | str:
    """A SafeDelete, or why this deployment can't be deleted."""
    if d.delete_refusal:
        return d.delete_refusal
    if d.sighting.in_progress:
        return RUNNING_NOW
    if automatic and d.tier is not Tier.PERSONAL:
        return "automatic deletes only apply to personal deployments"
    if automatic and d.framework is Framework.VERCEL:
        return "Vercel projects are never deleted automatically"
    return SafeDelete(d)


def request_id(key: str, verb: Verb, origin: str) -> str:
    """Deterministic per decision: the same request on the next run gets the same id."""
    digest = hashlib.sha256(f"{key}|{verb}|{origin}".encode()).hexdigest()
    return f"vg-{digest[:12]}"


@dataclass(frozen=True)
class Op:
    """One redeploy or delete. A runnable delete carries its proof, and anything vulgard can't
    do says why in `blocked`."""

    deployment: Deployment
    verb: Verb
    trigger: Trigger
    request_id: str
    delete: SafeDelete | None = None
    blocked: str | None = None

    def __post_init__(self) -> None:
        carries_proof = self.verb is Verb.DELETE and self.blocked is None
        assert carries_proof == (self.delete is not None), "a runnable delete carries its proof"

    @property
    def runnable(self) -> bool:
        return self.blocked is None

    @property
    def automatic(self) -> bool:
        return self.trigger is not Trigger.REQUEST


def _redeploy_blocker(d: Deployment) -> str | None:
    if d.sighting.in_progress:
        return RUNNING_NOW
    match d.sighting.native:
        case AmplifyBranch() | VercelProject():
            return None
        case CfnStack() | SstStage():
            if d.framework is Framework.AMPLIFY:
                return SANDBOX
            return NO_REPO if d.repo is None else None
        case _ as unreachable:
            assert_never(unreachable)


def plan_op(d: Deployment, verb: Verb, trigger: Trigger, rid: str) -> Op:
    """Pure. An op, or the reason vulgard can't carry it out."""
    match verb:
        case Verb.DELETE:
            safe = check_delete(d, automatic=trigger is not Trigger.REQUEST)
            if isinstance(safe, str):
                return Op(d, verb, trigger, rid, blocked=safe)
            if isinstance(d.sighting.native, SstStage) and d.repo is None:
                return Op(d, verb, trigger, rid, blocked=NO_REPO)  # only `sst remove` deletes SST
            return Op(d, verb, trigger, rid, delete=safe)
        case Verb.REDEPLOY:
            return Op(d, verb, trigger, rid, blocked=_redeploy_blocker(d))
        case _ as unreachable:
            assert_never(unreachable)


def requested_op(req: Issued[Request], d: Deployment) -> Op:
    match req.command:
        case Redeploy():
            verb = Verb.REDEPLOY
        case Delete():
            verb = Verb.DELETE
        case _ as unreachable:
            assert_never(unreachable)
    rid = request_id(d.key, verb, f"comment:{req.comment_id}")
    return plan_op(d, verb, Trigger.REQUEST, rid)


def recheck(
    proof: SafeDelete, live: Sighting | None, cfg: DeploymentsConfig, automatic: bool
) -> str | None:
    """Why a delete must not go ahead, from a fresh read of the target. It repeats the planning
    rules on what the target looks like now, and refuses if it was deployed again since."""
    planned = proof.deployment
    if live is None:
        return "it's already gone"
    if live.last_deployed > planned.last_deployed:
        return "it was deployed again since it was planned; leaving it alone"
    now = classify(live, EMPTY_INDEX, cfg)
    if now is None:
        return "it's ignored by the configuration now"
    refused = check_delete(now, automatic)
    if isinstance(refused, str):
        return refused
    if now.tier is not planned.tier:
        return "its tier changed since it was planned"
    return None


# --- automatic ops and their notices


@dataclass(frozen=True)
class Notice:
    """An announcement vulgard posted that it will act on `key`."""

    key: str
    verb: Verb
    at: datetime  # when the bot's comment was posted


def notice_marker(key: str, verb: Verb) -> str:
    """Hidden line that goes in the notice comment, one per deployment announced."""
    return f"<!-- vulgard-notice {json.dumps({'key': key, 'verb': verb.value}, sort_keys=True)} -->"


def _markers(
    comments: tuple[IssueComment, ...], pattern: re.Pattern[str]
) -> list[tuple[dict[str, Any], datetime]]:
    """JSON markers in comments by a `[bot]` author, with the comment's posting time. A person
    can't post one, so a person can't forge or backdate one."""
    found: list[tuple[dict[str, Any], datetime]] = []
    for c in comments:
        if not c.author.endswith("[bot]"):
            continue
        for m in pattern.finditer(c.body):
            try:
                raw = json.loads(m[1])
            except ValueError:
                continue
            if isinstance(raw, dict):
                found.append((raw, c.created_at))
    return found


def notices_from(comments: tuple[IssueComment, ...]) -> list[Notice]:
    found: list[Notice] = []
    for raw, at in _markers(comments, NOTICE_RE):
        try:
            found.append(Notice(raw["key"], Verb(raw["verb"]), at))
        except (ValueError, KeyError):
            continue
    return found


# --- ops that ended


@dataclass(frozen=True)
class Finished:
    """vulgard's record, in its own comment, that an op ran to the end."""

    key: str
    verb: Verb
    request_id: str
    succeeded: bool
    at: datetime  # when the bot's comment was posted


def finish_marker(op: Op, succeeded: bool) -> str:
    """Hidden line in the comment that reports how an op ended, so it's reported once."""
    raw = {
        "key": op.deployment.key,
        "verb": op.verb.value,
        "request_id": op.request_id,
        "succeeded": succeeded,
    }
    return f"<!-- vulgard-op {json.dumps(raw, sort_keys=True)} -->"


def finished_from(comments: tuple[IssueComment, ...]) -> list[Finished]:
    found: list[Finished] = []
    for raw, at in _markers(comments, FINISHED_RE):
        try:
            verb, succeeded = Verb(raw["verb"]), raw["succeeded"] is True
            found.append(Finished(raw["key"], verb, raw["request_id"], succeeded, at))
        except (ValueError, KeyError):
            continue
    return found


def confirmed(deployments: list[Deployment], finished: list[Finished]) -> list[Deployment]:
    """Pure. A successful redeploy counts as a deploy, even one that changed nothing and so left
    the stack's own timestamp where it was (CloudFormation skips empty updates)."""
    latest: dict[str, datetime] = {}
    for f in finished:
        if f.succeeded and f.verb is Verb.REDEPLOY:
            latest[f.key] = max(f.at, latest.get(f.key, f.at))
    out: list[Deployment] = []
    for d in deployments:
        at = latest.get(d.key)
        if at is not None and at > d.last_deployed:
            d = replace(d, sighting=replace(d.sighting, last_deployed=at))
        out.append(d)
    return out


def _settled(op: Op, finished: Mapping[str, Finished]) -> Op | None:
    """None once the op succeeded. A failed one is blocked, so it isn't reported every run."""
    f = finished.get(op.request_id)
    if f is None:
        return op
    return None if f.succeeded else replace(op, blocked=RUN_FAILED, delete=None)


@dataclass(frozen=True)
class Scheduled:
    """An automatic op still inside its notice period."""

    deployment: Deployment
    verb: Verb
    trigger: Trigger
    due: date
    fresh: bool  # no notice comment exists yet, so this run must post one


@dataclass(frozen=True)
class Lifecycle:
    """What a repo's tracking issue says about ops, and what `--execute` may run."""

    scheduled: tuple[Scheduled, ...] = ()
    ops: tuple[Op, ...] = ()


def auto_trigger(
    d: Deployment, cfg: DeploymentsConfig, vulnerable: bool, now: datetime
) -> Trigger | None:
    """Pure. Why `d` qualifies for an automatic op, if it does."""
    auto = cfg.auto
    if d.tier is not Tier.PERSONAL or not auto.enabled_for(d.repo):
        return None
    if (now - d.last_deployed).days >= auto.personal_stale_days:
        return Trigger.STALE
    return Trigger.VULNERABLE if vulnerable else None


def _first_notice(
    notices: list[Notice], d: Deployment, verb: Verb, decisions: Decisions
) -> date | None:
    """The date of the earliest notice that still counts: newer than the last deploy and the
    last keep, so an old notice can't make an op fire without fresh warning."""
    floor = max(d.last_deployed, decisions.last_keep.get(d.key, d.last_deployed))
    valid = [n.at for n in notices if n.key == d.key and n.verb is verb and n.at > floor]
    return min(valid).date() if valid else None


def reconcile(
    deployments: list[Deployment],
    decisions: Decisions,
    notices: list[Notice],
    cfg: DeploymentsConfig,
    vulnerable: bool,
    now: datetime,
    finished: list[Finished] | None = None,
) -> Lifecycle:
    """Pure. Requests become ops. A qualifying personal deployment gets a notice, then an op
    once the notice period has passed. A keep, or a cancel newer than the last deploy, stops
    it, whichever trigger qualified it. Ops that already ended (`finished`) don't run again."""
    ops = [requested_op(req, d) for req, d in pending_requests(decisions, deployments)]
    requested = {op.deployment.key for op in ops}
    verb = Verb.DELETE if cfg.auto.delete else Verb.REDEPLOY
    today = now.date()
    scheduled: list[Scheduled] = []
    for d in deployments:
        trigger = auto_trigger(d, cfg, vulnerable, now)
        cancel = decisions.cancels.get(d.key)
        cancelled = cancel is not None and cancel.at > d.last_deployed
        if trigger is None or d.key in requested or d.key in decisions.keeps or cancelled:
            continue
        posted = _first_notice(notices, d, verb, decisions)
        due = (posted or today) + timedelta(days=cfg.auto.notice_days)
        if posted is not None and posted < today and due <= today:
            rid = request_id(d.key, verb, f"auto:{posted.isoformat()}")
            ops.append(plan_op(d, verb, trigger, rid))
        else:
            scheduled.append(Scheduled(d, verb, trigger, due, fresh=posted is None))
    ended = {f.request_id: f for f in finished or []}
    live = [s for op in ops if (s := _settled(op, ended)) is not None]
    return Lifecycle(tuple(scheduled), tuple(live))


def describe(op: Op) -> str:
    return f"{op.verb} `{op.deployment.name}` ({TRIGGER_WHY[op.trigger]}, {op.request_id})"
