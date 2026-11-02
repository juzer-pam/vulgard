"""Generic tracking plan types, shared by every topic (vulnerabilities, stale deployments).

A topic owns its domain policy and renders everything it wants said into a `RepoPlan`. The
engine (`nag.track`) owns where and when it's said: the GitHub tracking issue, persisted memory,
the Linear issue and Slack. The engine never reads a topic's domain types.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, Self, assert_never

from .config import LinearOverride
from .policy import parse_time

STATE_RE = re.compile(r"<!-- vulgard-state (\{.*?\}) -->", re.S)
ENGINE_KEYS = ("last_reminder", "linear")


class Topic(StrEnum):
    VULNS = "vulns"
    STALE = "stale"


@dataclass(frozen=True)
class TopicSpec:
    """Static identity of a topic. One tracking issue per (repo, topic), found by `label`."""

    topic: Topic
    label: str
    title: str  # GitHub issue title; the Linear title is f"{repo}: {title}"
    slack_header: str  # channel digest header
    slack_dm_header: str
    escalation_header: str  # after the escalation mentions, in slack.escalation_channel
    linear_closed: str  # Linear comment when the topic goes clean
    memory_type: type[Memory]  # parses the topic's part of the state comment
    reads_commands: bool = False  # the engine loads issue comments only for these topics
    linear: LinearOverride = field(default_factory=LinearOverride)  # replaces routed settings


class ActionKind(StrEnum):
    CREATE = "create"
    REOPEN = "reopen"
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
    GITHUB_ERROR = "github-error"
    EXECUTE = "execute"
    EXECUTE_ERROR = "execute-error"

    @property
    def is_error(self) -> bool:
        return self in (
            ActionKind.LINEAR_ERROR,
            ActionKind.SLACK_ERROR,
            ActionKind.GITHUB_ERROR,
            ActionKind.EXECUTE_ERROR,
        )


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


class Memory(Protocol):
    """Topic-owned memory, persisted in the tracking issue body next to the engine's keys.

    It caches what the world can't tell us, such as what was already announced. Losing it may
    repeat an announcement; it must never cause an extra destructive action.
    """

    def to_json(self) -> dict[str, Any]: ...

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Self: ...


@dataclass(frozen=True)
class TrackingState[M: Memory]:
    """Memory between runs, stored as flat JSON in a hidden comment in the issue body.

    Anyone with write access can edit the body, so everything read from here is a hint.
    """

    memory: M
    last_reminder: datetime | None = None
    linear: LinearRef | None = None

    @classmethod
    def from_body(cls, body: str | None, memory_type: type[M]) -> TrackingState[M]:
        match = STATE_RE.search(body or "")
        raw: dict[str, Any] = {}
        if match:
            try:
                raw = json.loads(match.group(1))
            except json.JSONDecodeError:
                raw = {}
        linear = raw.get("linear")
        return cls(
            memory=memory_type.from_json({k: v for k, v in raw.items() if k not in ENGINE_KEYS}),
            last_reminder=parse_time(raw["last_reminder"]) if raw.get("last_reminder") else None,
            linear=LinearRef(**linear) if linear else None,
        )

    def to_comment(self) -> str:
        raw: dict[str, Any] = {
            **self.memory.to_json(),
            "last_reminder": self.last_reminder.isoformat() if self.last_reminder else None,
            "linear": asdict(self.linear) if self.linear else None,
        }
        return f"<!-- vulgard-state {json.dumps(raw, sort_keys=True)} -->"


class IssueOp(StrEnum):
    CREATE = "create"
    REOPEN = "reopen"  # the latest closed tracking issue is reopened instead of opening a new one
    UPDATE = "update"
    CLOSE = "close"
    NONE = "none"


def issue_op(issue: TrackedIssue | None, needs_tracking: bool) -> IssueOp:
    if needs_tracking:
        if issue is None:
            return IssueOp.CREATE
        return IssueOp.UPDATE if issue.open else IssueOp.REOPEN
    return IssueOp.CLOSE if issue is not None and issue.open else IssueOp.NONE


@dataclass(frozen=True)
class IssueComment:
    id: int
    author: str  # GitHub login, without "@"
    body: str
    created_at: datetime
    html_url: str


@dataclass(frozen=True)
class TrackedIssue:
    """The latest tracking issue for (repo, topic), open or closed.

    Closed when clean and reopened when dirty, so the comment thread outlives clean periods.
    """

    number: int
    open: bool
    body: str
    html_url: str
    comments: tuple[IssueComment, ...] = ()  # only loaded when spec.reads_commands


@dataclass(frozen=True)
class LinearContent:
    """Everything topic-specific the engine needs to create or update the Linear issue."""

    fields: dict[str, Any]  # title, description, priority, dueDate: overwritten on every change
    worst_severity: str | None  # picks the severity label
    reopened: str  # comment when a closed Linear issue is reopened
    news: list[str] = field(default_factory=list)  # comments on update, with absolute dates


@dataclass(frozen=True)
class Escalation:
    """The GitHub comment is in `RepoPlan.comments`. This holds the text for the other channels."""

    detail: str  # Action detail, e.g. "2 alert(s)"
    linear_md: str
    slack_detail: str  # one bullet in slack.escalation_channel, after the repo link


@dataclass
class RepoPlan[M: Memory]:
    """A topic's complete, rendered decision for one repo. The engine applies it."""

    spec: TopicSpec
    repo: str
    owners: list[str]
    op: IssueOp
    state: TrackingState[M]
    summary: str  # Action detail, e.g. "4 alert(s)"
    render: Callable[[TrackingState[M]], str]  # issue body, given the final state
    comments: list[str] = field(default_factory=list)  # with @mentions and relative dates
    comment_detail: str | None = None  # Action detail when comments carry news
    linear: LinearContent | None = None  # set iff the issue stays open
    escalation: Escalation | None = None
    digest: str | None = None  # Slack line after the repo link; None means not pinged
    dm: tuple[str, ...] = ()  # handles to DM besides owners

    def __post_init__(self) -> None:
        live = self.op in (IssueOp.CREATE, IssueOp.REOPEN, IssueOp.UPDATE)
        assert live == (self.linear is not None), "Linear content iff the issue stays open"

    @property
    def pinged(self) -> bool:
        return self.digest is not None

    def actions(self) -> list[Action]:
        match self.op:
            case IssueOp.NONE:
                return [Action(self.repo, ActionKind.NOOP, "clean")]
            case IssueOp.CLOSE:
                return [Action(self.repo, ActionKind.CLOSE, self.summary)]
            case IssueOp.CREATE:
                actions = [Action(self.repo, ActionKind.CREATE, self.summary)]
            case IssueOp.REOPEN:
                actions = [Action(self.repo, ActionKind.REOPEN, self.summary)]
            case IssueOp.UPDATE:
                actions = [Action(self.repo, ActionKind.UPDATE, self.summary)]
            case _ as unreachable:
                assert_never(unreachable)
        if self.comment_detail:
            actions.append(Action(self.repo, ActionKind.COMMENT, self.comment_detail))
        if self.escalation:
            actions.append(Action(self.repo, ActionKind.ESCALATE, self.escalation.detail))
        return actions


@dataclass
class RepoRun:
    plan: RepoPlan[Any]
    issue_url: str | None
    actions: list[Action]
    issue_number: int | None = None

    @property
    def repo(self) -> str:
        return self.plan.repo


# --- helpers the topic planners share


def mention_prefix(mentions: list[str]) -> str:
    """`@a @b ` ready to put in front of a comment."""
    return "".join(f"{m} " for m in mentions)


def slack_summary(items: list[str]) -> str:
    """The first three items, then how many more."""
    more = f" (+{len(items) - 3} more)" if len(items) > 3 else ""
    return ", ".join(items[:3]) + more


def reminder_due(prev: TrackingState[Any], now: datetime, interval_days: int) -> bool:
    return prev.last_reminder is None or (now - prev.last_reminder).days >= interval_days


def reminder_clock(prev: TrackingState[Any], now: datetime, spoke: bool) -> datetime | None:
    """The reminder clock restarts whenever vulgard says something on the issue."""
    return now if spoke else prev.last_reminder

