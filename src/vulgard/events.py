from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .policy import Alert, DependabotPR, RepoReport


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
    SLACK_ERROR = "slack-error"

    @property
    def is_error(self) -> bool:
        return self in (ActionKind.LINEAR_ERROR, ActionKind.SLACK_ERROR)


@dataclass
class Action:
    repo: str
    kind: ActionKind
    detail: str = ""


@dataclass
class RepoPlan:
    report: RepoReport
    actions: list[Action]
    body: str | None
    comments: list[str]
    state: dict[str, Any]
    newly_overdue: list[Alert] = field(default_factory=list)
    newly_ready: list[DependabotPR] = field(default_factory=list)
    escalate: list[Alert] = field(default_factory=list)
    reminder: bool = False
    opened: bool = False
    closing: bool = False
    issue_url: str | None = None

    @property
    def repo(self) -> str:
        return self.report.repo

    @property
    def pinged(self) -> bool:
        return bool(
            self.opened or self.newly_overdue or self.newly_ready or self.escalate or self.reminder
        )
