from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, assert_never

from .policy import Alert, DependabotPR, RepoReport, parse_time

STATE_RE = re.compile(r"<!-- vulgard-state (\{.*?\}) -->", re.S)


class ActionKind(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    COMMENT = "comment"
    ESCALATE = "escalate"
    CLOSE = "close"
    NOOP = "noop"
    LINEAR_CREATE = "linear-create"
    LINEAR_UPDATE = "linear-update"
    LINEAR_CLOSE = "linear-close"
    LINEAR_SKIP = "linear-skip"
    LINEAR_ERROR = "linear-error"
    SLACK = "slack"
    SLACK_SKIP = "slack-skip"
    SLACK_ERROR = "slack-error"

    @property
    def is_error(self) -> bool:
        return self in (ActionKind.LINEAR_ERROR, ActionKind.SLACK_ERROR)


@dataclass
class Action:
    repo: str | None  # None for org-wide actions such as Slack messages
    kind: ActionKind
    detail: str = ""


@dataclass(frozen=True)
class LinearRef:
    id: str
    identifier: str
    url: str
    digest: str = ""


@dataclass(frozen=True)
class TrackingState:
    """Memory between runs, stored as JSON in a hidden comment in the tracking issue body."""

    overdue: tuple[int, ...] = ()
    escalated: tuple[int, ...] = ()
    ready_prs: tuple[int, ...] = ()
    last_reminder: datetime | None = None
    linear: LinearRef | None = None

    @classmethod
    def from_body(cls, body: str | None) -> TrackingState:
        match = STATE_RE.search(body or "")
        if not match:
            return cls()
        try:
            raw = json.loads(match.group(1))
        except json.JSONDecodeError:
            return cls()
        linear = raw.get("linear")
        return cls(
            overdue=tuple(raw.get("overdue", ())),
            escalated=tuple(raw.get("escalated", ())),
            ready_prs=tuple(raw.get("ready_prs", ())),
            last_reminder=parse_time(raw["last_reminder"]) if raw.get("last_reminder") else None,
            linear=LinearRef(**linear) if linear else None,
        )

    def to_comment(self) -> str:
        raw: dict[str, Any] = asdict(self)
        raw["last_reminder"] = self.last_reminder.isoformat() if self.last_reminder else None
        return f"<!-- vulgard-state {json.dumps(raw, sort_keys=True)} -->"


class IssueOp(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    CLOSE = "close"
    NONE = "none"


@dataclass
class RepoPlan:
    report: RepoReport
    op: IssueOp
    state: TrackingState
    comments: list[str] = field(default_factory=list)
    newly_overdue: list[Alert] = field(default_factory=list)
    newly_ready: list[DependabotPR] = field(default_factory=list)
    escalate: list[Alert] = field(default_factory=list)
    reminder: bool = False

    @property
    def repo(self) -> str:
        return self.report.repo

    @property
    def pinged(self) -> bool:
        return bool(
            self.op == IssueOp.CREATE
            or self.newly_overdue
            or self.newly_ready
            or self.escalate
            or self.reminder
        )

    def actions(self) -> list[Action]:
        match self.op:
            case IssueOp.NONE:
                return [Action(self.repo, ActionKind.NOOP, "clean")]
            case IssueOp.CLOSE:
                return [Action(self.repo, ActionKind.CLOSE, "all alerts resolved")]
            case IssueOp.CREATE | IssueOp.UPDATE:
                kind = ActionKind.CREATE if self.op == IssueOp.CREATE else ActionKind.UPDATE
                actions = [Action(self.repo, kind, f"{len(self.report.alerts)} alert(s)")]
            case _ as unreachable:
                assert_never(unreachable)
        if self.op == IssueOp.UPDATE and (self.newly_overdue or self.newly_ready):
            detail = (
                f"{len(self.newly_overdue)} newly overdue, "
                f"{len(self.newly_ready)} newly ready PR(s)"
            )
            actions.append(Action(self.repo, ActionKind.COMMENT, detail))
        elif self.reminder:
            actions.append(Action(self.repo, ActionKind.COMMENT, "periodic reminder"))
        if self.escalate:
            actions.append(Action(self.repo, ActionKind.ESCALATE, f"{len(self.escalate)} alert(s)"))
        return actions


@dataclass
class RepoRun:
    plan: RepoPlan
    issue_url: str | None
    actions: list[Action]

    @property
    def repo(self) -> str:
        return self.plan.repo
