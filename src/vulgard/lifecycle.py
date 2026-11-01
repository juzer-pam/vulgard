"""Lifecycle: turn baselines into redeploys and deletes, and carry them out idempotently.

Ops come from two sources.

A request is a `/vulgard redeploy|delete <name>` comment from someone with write access. The
next `nag --apply --execute` run carries it out.

An automatic op targets a PERSONAL deployment in an `auto.repos` repo that hasn't deployed in
`auto.personal_stale_days`, or whose repo has open critical alerts. vulgard first posts a
notice on the tracking issue. It acts once `auto.notice_days` have passed since the notice was
first planned. `/vulgard keep` or `/vulgard cancel` stops it.

Every delete is built from a `SafeDelete`, which only `check_delete` can create, and the
executor re-reads the live target before deleting. Production is never deleted.

Each op has a deterministic `request_id`. Every API receives it as an idempotency key: the
workflow run name, the CloudFormation `ClientRequestToken`, the Amplify `jobReason` and the
Vercel `meta`. `execute` looks for an existing op with that id before it starts one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import StrEnum
from typing import Protocol, assert_never

from .baseline import Cancel, Delete, Issued, Redeploy, Request
from .config import DeploymentsConfig
from .estate import (
    AmplifyBranch,
    CfnStack,
    Deployment,
    Framework,
    SstStage,
    Tier,
    VercelProject,
)

_TOKEN = object()


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
    """Proof that a deployment passed `check_delete`. Delete steps only accept this."""

    deployment: Deployment
    token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        assert self.token is _TOKEN, "SafeDelete is only created by check_delete"


def check_delete(d: Deployment, automatic: bool) -> SafeDelete | str:
    """A SafeDelete, or why this deployment can't be deleted."""
    s = d.sighting
    if d.tier is Tier.PRODUCTION or s.protected:
        return "vulgard never deletes production or protected deployments"
    if s.in_progress:
        return "a deploy is running right now"
    if automatic and d.tier is not Tier.PERSONAL:
        return "automatic deletes only apply to personal deployments"
    if automatic and d.framework is Framework.VERCEL:
        return "Vercel projects are never deleted automatically"
    return SafeDelete(d, _TOKEN)


# --- steps: how an op is carried out


@dataclass(frozen=True)
class Dispatch:
    """Run the repo's lifecycle workflow (or `deployments.workflows[repo]`)."""

    repo: str
    workflow: str
    inputs: Mapping[str, str]


@dataclass(frozen=True)
class CfnDelete:
    target: SafeDelete  # Serverless and CDK stacks, and Amplify sandboxes


@dataclass(frozen=True)
class AmplifyRelease:
    branch: AmplifyBranch


@dataclass(frozen=True)
class AmplifyDelete:
    target: SafeDelete


@dataclass(frozen=True)
class VercelRedeploy:
    project: VercelProject


@dataclass(frozen=True)
class VercelDelete:
    target: SafeDelete


type Step = Dispatch | CfnDelete | AmplifyRelease | AmplifyDelete | VercelRedeploy | VercelDelete


def request_id(key: str, verb: Verb, origin: str) -> str:
    """Deterministic per decision: the same request on the next run gets the same id."""
    digest = hashlib.sha256(f"{key}|{verb}|{origin}".encode()).hexdigest()
    return f"vg-{digest[:12]}"


def _inputs(d: Deployment, verb: Verb, rid: str) -> dict[str, str]:
    stack = d.sighting.native.name if isinstance(d.sighting.native, CfnStack) else ""
    return {
        "action": verb.value,
        "framework": d.framework.value,
        "app": d.sighting.app,
        "stage": d.sighting.stage or "",
        "stack": stack,
        "request_id": rid,
    }


def _dispatch(d: Deployment, verb: Verb, rid: str, cfg: DeploymentsConfig) -> Dispatch | str:
    if d.repo is None:
        return "no repo to run it from; attribute the deployment first"
    return Dispatch(d.repo, cfg.workflow_for(d.repo), _inputs(d, verb, rid))


def plan_step(
    d: Deployment, verb: Verb, rid: str, cfg: DeploymentsConfig, automatic: bool
) -> Step | str:
    """Pure. How to carry out `verb` on `d`, or why vulgard can't."""
    native = d.sighting.native
    match verb:
        case Verb.REDEPLOY:
            if d.sighting.in_progress:
                return "a deploy is running right now"
            match native:
                case AmplifyBranch():
                    return AmplifyRelease(native)
                case VercelProject():
                    return VercelRedeploy(native)
                case CfnStack() if d.framework is Framework.AMPLIFY:
                    return "Amplify sandboxes run from a laptop (`npx ampx sandbox`); delete it"
                case CfnStack() | SstStage():
                    return _dispatch(d, verb, rid, cfg)
                case _ as unreachable:
                    assert_never(unreachable)
        case Verb.DELETE:
            safe = check_delete(d, automatic)
            if isinstance(safe, str):
                return safe
            match native:
                case CfnStack():
                    return CfnDelete(safe)
                case SstStage():
                    return _dispatch(d, verb, rid, cfg)  # only `sst remove` can delete SST
                case AmplifyBranch():
                    return AmplifyDelete(safe)
                case VercelProject():
                    return VercelDelete(safe)
                case _ as unreachable:
                    assert_never(unreachable)
        case _ as unreachable:
            assert_never(unreachable)


@dataclass(frozen=True)
class Op:
    deployment: Deployment
    verb: Verb
    trigger: Trigger
    request_id: str
    step: Step | str  # str: why it can't be done automatically

    @property
    def runnable(self) -> bool:
        return not isinstance(self.step, str)


def requested_op(req: Issued[Request], d: Deployment, cfg: DeploymentsConfig) -> Op:
    match req.command:
        case Redeploy():
            verb = Verb.REDEPLOY
        case Delete():
            verb = Verb.DELETE
        case _ as unreachable:
            assert_never(unreachable)
    rid = request_id(d.key, verb, f"comment:{req.comment_id}")
    return Op(d, verb, Trigger.REQUEST, rid, plan_step(d, verb, rid, cfg, automatic=False))


# --- automatic ops and their notices


@dataclass(frozen=True)
class Notice:
    """Recorded in issue memory with the date it was first planned. The notice period counts
    from that date."""

    key: str
    verb: Verb
    trigger: Trigger
    posted: date

    def to_json(self) -> list[str]:
        return [self.key, self.verb.value, self.trigger.value, self.posted.isoformat()]

    @classmethod
    def from_json(cls, raw: list[str]) -> Notice:
        key, verb, trigger, posted = raw
        return cls(key, Verb(verb), Trigger(trigger), date.fromisoformat(posted))


@dataclass(frozen=True)
class Scheduled:
    notice: Notice
    deployment: Deployment
    due: date
    fresh: bool  # notice posted this run


@dataclass
class Lifecycle:
    """What a repo's tracking issue says about ops, and what `--execute` may run."""

    scheduled: list[Scheduled] = field(default_factory=list)  # notice period running
    ops: list[Op] = field(default_factory=list)  # requested, and automatic ones now due
    notices: list[Notice] = field(default_factory=list)  # to remember: scheduled and due


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


def reconcile(
    deployments: list[Deployment],
    requests: list[tuple[Issued[Request], Deployment]],
    kept: set[str],
    cancels: Mapping[str, Issued[Cancel]],
    notices: tuple[Notice, ...],
    cfg: DeploymentsConfig,
    vulnerable: bool,
    now: datetime,
) -> Lifecycle:
    """Pure. Requests become ops. Qualifying personal deployments get a notice, then an op once
    the notice period has passed. A keep, or a cancel newer than the last deploy, stops it."""
    life = Lifecycle(ops=[requested_op(req, d, cfg) for req, d in requests])
    requested = {d.key for _, d in requests}
    prev = {n.key: n for n in notices}
    today = now.date()
    verb = Verb.DELETE if cfg.auto.delete else Verb.REDEPLOY
    for d in deployments:
        trigger = auto_trigger(d, cfg, vulnerable, now)
        cancel = cancels.get(d.key)
        stopped = d.key in kept or (cancel is not None and cancel.at > d.last_deployed)
        if trigger is None or stopped or d.key in requested:
            continue
        notice = prev.get(d.key)
        fresh = notice is None or notice.verb is not verb
        if fresh:
            notice = Notice(d.key, verb, trigger, today)
        assert notice is not None
        life.notices.append(notice)
        due = notice.posted + timedelta(days=cfg.auto.notice_days)
        if notice.posted < today and due <= today:
            rid = request_id(d.key, verb, f"auto:{notice.posted.isoformat()}")
            op = Op(d, verb, notice.trigger, rid, plan_step(d, verb, rid, cfg, automatic=True))
            life.ops.append(op)
        else:
            life.scheduled.append(Scheduled(notice, d, due, fresh))
    return life


# --- execution


class OpFailed(RuntimeError):
    """A lifecycle op that the control plane reports as failed."""


class Outcome(StrEnum):
    STARTED = "started"
    RUNNING = "running"  # an op with this request id already exists
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Result:
    op: Op
    outcome: Outcome
    detail: str  # a link when started or running, else the reason
    url: str | None = None


class Executor(Protocol):
    """Live or fixture. `find` returns a link to an existing op with this request id."""

    def find(self, step: Step, request_id: str) -> str | None: ...
    def recheck(self, step: Step) -> str | None: ...  # why a delete must not proceed
    def start(self, step: Step, request_id: str) -> str: ...


def execute(op: Op, executor: Executor, errors: tuple[type[Exception], ...]) -> Result:
    """Idempotent: an op already started with this request id is reported, not repeated."""
    step = op.step
    if isinstance(step, str):
        return Result(op, Outcome.SKIPPED, step)
    try:
        existing = executor.find(step, op.request_id)
        if existing:
            return Result(op, Outcome.RUNNING, existing, existing)
        if isinstance(step, (CfnDelete, AmplifyDelete, VercelDelete)):
            why = executor.recheck(step)
            if why:
                return Result(op, Outcome.SKIPPED, why)
        url = executor.start(step, op.request_id)
    except errors as e:
        return Result(op, Outcome.FAILED, str(e))
    return Result(op, Outcome.STARTED, url, url)


def describe(op: Op) -> str:
    return f"{op.verb} `{op.deployment.name}` ({TRIGGER_WHY[op.trigger]}, {op.request_id})"


def result_comment(r: Result, mentions: str) -> str | None:
    """The tracking-issue comment for a result, or None when there's nothing new to say."""
    match r.outcome:
        case Outcome.STARTED:
            return f"{mentions} Started {describe(r.op)}. [Progress]({r.url})".strip()
        case Outcome.FAILED:
            return f"{mentions} Couldn't {describe(r.op)}: {r.detail}".strip()
        case Outcome.RUNNING | Outcome.SKIPPED:
            return None
        case _ as unreachable:
            assert_never(unreachable)
