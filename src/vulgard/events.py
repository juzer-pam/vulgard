from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import Alert, RepoReport


@dataclass
class Action:
    repo: str
    # create | update | comment | escalate | close | noop
    # | linear-create | linear-update | linear-close | linear-skip | linear-error
    # | slack | slack-error
    kind: str
    detail: str = ""


@dataclass
class RepoPlan:
    """What one nag run decided for a repo; consumed by the GitHub, Linear, and Slack writers."""

    report: RepoReport
    actions: list[Action]
    body: str | None
    comments: list[str]
    state: dict[str, Any]
    newly_overdue: list[Alert] = field(default_factory=list)
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
        return bool(self.opened or self.newly_overdue or self.escalate or self.reminder)
