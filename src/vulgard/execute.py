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
from .estate import Deployment, NativeRef, OpFailed, Sighting
from .lifecycle import Op, SafeDelete, describe, recheck


class Executor(Protocol):
    def observe(self, native: NativeRef) -> Sighting | None:
        """A fresh read of the target, or None when it no longer exists."""
        ...

    def find(self, op: Op) -> str | None:
        """A link to an existing run of this op, found by its request id."""
        ...

    def redeploy(self, d: Deployment, request_id: str) -> str: ...

    def delete(self, proof: SafeDelete, request_id: str) -> str: ...


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


def execute(op: Op, executor: Executor, cfg: DeploymentsConfig) -> Result:
    """Idempotent: an op already started with this request id is reported, not repeated. A
    delete is re-checked against a fresh read of the target first."""
    if op.blocked:
        return Result(op, Outcome.SKIPPED, op.blocked)
    try:
        existing = executor.find(op)
        if existing:
            return Result(op, Outcome.RUNNING, existing, existing)
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
