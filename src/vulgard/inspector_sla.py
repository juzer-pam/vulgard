"""The inspector topic's deadlines: each fix item is due `sla_days[severity]` after a vulgard
tracking issue first listed it.

    deadline = first listed + sla_days[severity]
    status   = ok / due-soon / overdue

The first-listed date is kept in the GitHub issue's memory under the item's key, so the clock
survives status changes and doesn't reset between runs. A repo tracked only in Linear (public
repos, and repos vulgard doesn't track) has no memory, so its clocks restart every run.

Pure. The plan is in `inspector_plan.py`, rendering in `inspector_render.py`.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Self

from .config import SEVERITIES, Config
from .inspector import FixItem, FixStatus
from .plan import Topic, TopicSpec
from .policy import SlaStatus

TITLE = "Security: vulnerable packages running in AWS"
UNATTRIBUTED_TITLE = f"No repo: {TITLE}"
CLOSED = "✅ Amazon Inspector no longer finds these vulnerable packages. Closing."
PARENT_CLOSED = "✅ None of this team's repos have vulnerable packages running in AWS. Closing."
UNATTRIBUTED_CLOSED = "✅ Every vulnerable package running in AWS has a repo or is gone. Closing."


@dataclass(frozen=True)
class InspectorMemory:
    listed: tuple[tuple[str, str], ...] = ()  # (item key, ISO date it was first listed)
    overdue: tuple[str, ...] = ()
    escalated: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "listed": [list(pair) for pair in self.listed],
            "overdue": list(self.overdue),
            "escalated": list(self.escalated),
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Self:
        return cls(
            listed=tuple((str(key), str(day)) for key, day in raw.get("listed", ())),
            overdue=tuple(raw.get("overdue", ())),
            escalated=tuple(raw.get("escalated", ())),
        )


SPEC = TopicSpec(
    topic=Topic.INSPECTOR,
    label="vulgard-inspector",
    title=TITLE,
    slack_title="Vulnerable packages running in AWS",
    slack_header="Amazon Inspector found vulnerable packages running in AWS from these repos:",
    slack_dm_header="Amazon Inspector found vulnerable packages running in AWS from repos you own:",
    escalation_header="These vulnerable packages running in AWS are well past their fix deadline:",
    linear_closed=CLOSED,
    memory_type=InspectorMemory,
    links_linear=True,
)


def item_key(item: FixItem) -> str:
    """Stable across runs and statuses: the ecosystem, else the package manager, and the name."""
    return f"{item.ecosystem or item.findings[0].package_manager}:{item.package.lower()}"


@dataclass(frozen=True)
class TrackedItem:
    item: FixItem
    key: str
    listed: date
    deadline: date
    status: SlaStatus
    escalate: bool
    days_left: int  # negative when overdue


@dataclass(frozen=True)
class InspectorRepo:
    """Everything the planner renders for one repo. `github` is False for public repos and for
    repos vulgard doesn't track, which get no GitHub issue."""

    repo: str
    items: list[TrackedItem]  # worst first, as `fix_items` sorts them
    github: bool
    owners: list[str] = field(default_factory=list)

    @property
    def overdue(self) -> list[TrackedItem]:
        return [i for i in self.items if i.status is SlaStatus.OVERDUE]

    @property
    def due_soon(self) -> list[TrackedItem]:
        return [i for i in self.items if i.status is SlaStatus.DUE_SOON]

    @property
    def statuses(self) -> Counter[FixStatus]:
        return Counter(i.item.status for i in self.items)

    @property
    def worst_severity(self) -> str | None:
        present = {i.item.severity for i in self.items}
        return next((s for s in SEVERITIES if s in present), None)


def _track(item: FixItem, listed: date, config: Config, today: date) -> TrackedItem:
    severity = item.severity
    deadline = listed + timedelta(days=config.sla_days[severity])
    left = (deadline - today).days
    if left < 0:
        status = SlaStatus.OVERDUE
    elif left <= config.due_soon_days:
        status = SlaStatus.DUE_SOON
    else:
        status = SlaStatus.OK
    esc = config.escalation
    escalate = (
        status is SlaStatus.OVERDUE
        and severity in esc.severities
        and -left >= esc.after_days_overdue
    )
    return TrackedItem(item, item_key(item), listed, deadline, status, escalate, left)


def evaluate(
    repo: str,
    items: list[FixItem],
    memory: InspectorMemory,
    config: Config,
    now: datetime,
    github: bool,
    owners: list[str],
) -> InspectorRepo:
    """Items listed before keep their date; new ones, and ones whose remembered date doesn't
    parse, are listed today."""
    today = now.date()
    first: dict[str, date] = {}
    for key, day in memory.listed:
        try:
            first[key] = min(date.fromisoformat(day), today)
        except ValueError:
            continue
    tracked = [_track(item, first.get(item_key(item), today), config, today) for item in items]
    return InspectorRepo(repo, tracked, github, owners)
