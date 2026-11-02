"""Carrying out an `Op` against the real world, idempotently.

`Executor` is the I/O boundary: a live one talks to GitHub, AWS and Vercel (`executor.py`) and a
fixture one records what it was asked to do. Every failure an executor can hit reaches this
module as `OpFailed`, so nothing here knows about boto3 or HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, assert_never

from .config import DeploymentsConfig
from .estate import Deployment, Found, NativeRef, OpFailed, RunState, Sighting
from .lifecycle import Op, SafeDelete, describe, finish_marker, recheck


class Executor(Protocol):
    def observe(self, native: NativeRef) -> Sighting | None:
        """A fresh read of the target, or None when it no longer exists."""
        ...

    def find(self, op: Op) -> Found | None:
        """An existing run of this op, found by its request id."""
        ...

    def redeploy(self, d: Deployment, request_id: str) -> str: ...

    def delete(self, proof: SafeDelete, request_id: str) -> str: ...


class Outcome(StrEnum):
    STARTED = "started"
    RUNNING = "running"  # an op with this request id already exists
    SUCCEEDED = "succeeded"  # it exists and finished
    RUN_FAILED = "run failed"  # it exists and ended badly; reported once, not retried
    FAILED = "failed"  # couldn't start it or read its state; tried again next run
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Result:
    op: Op
    outcome: Outcome
    detail: str  # a link when started or running, else the reason
    url: str | None = None


def execute(op: Op, executor: Executor, cfg: DeploymentsConfig) -> Result:
    """Idempotent: an op already started with this request id is reported, not repeated. A
    delete is re-checked against a fresh read of the target first."""
    if op.blocked:
        return Result(op, Outcome.SKIPPED, op.blocked)
    try:
        existing = executor.find(op)
        if existing:
            return _existing(op, existing)
        if op.delete is not None:
            native = op.delete.deployment.sighting.native
            why = recheck(op.delete, executor.observe(native), cfg, op.automatic)
            if why:
                return Result(op, Outcome.SKIPPED, why)
            url = executor.delete(op.delete, op.request_id)
        else:
            url = executor.redeploy(op.deployment, op.request_id)
    except OpFailed as e:
        return Result(op, Outcome.FAILED, str(e))
    return Result(op, Outcome.STARTED, url, url)


def _existing(op: Op, found: Found) -> Result:
    match found.state:
        case RunState.RUNNING:
            return Result(op, Outcome.RUNNING, found.url, found.url)
        case RunState.SUCCEEDED:
            return Result(op, Outcome.SUCCEEDED, found.url, found.url)
        case RunState.FAILED:
            return Result(op, Outcome.RUN_FAILED, found.why, found.url)
        case _ as unreachable:
            assert_never(unreachable)


def result_comment(r: Result, mentions: str) -> str | None:
    """The tracking-issue comment for a result, or None when there's nothing new to say. Ended
    ops carry a marker, so the next run knows they were reported."""
    match r.outcome:
        case Outcome.STARTED:
            return f"{mentions} Started {describe(r.op)}. [Progress]({r.url})".strip()
        case Outcome.SUCCEEDED:
            return f"Finished {describe(r.op)}. [Details]({r.url})\n\n{finish_marker(r.op, True)}"
        case Outcome.RUN_FAILED:
            text = (
                f"{mentions} Couldn't {describe(r.op)}: {r.detail}. [Details]({r.url}). "
                "vulgard won't try this one again. Fix the cause, then do it by hand or post "
                "the command again."
            )
            return f"{text.strip()}\n\n{finish_marker(r.op, False)}"
        case Outcome.FAILED:
            return f"{mentions} Couldn't {describe(r.op)}: {r.detail}".strip()
        case Outcome.RUNNING | Outcome.SKIPPED:
            return None
        case _ as unreachable:
            assert_never(unreachable)
