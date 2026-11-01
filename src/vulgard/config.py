from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("critical", "high", "medium", "low")

DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


@dataclass
class EscalationConfig:
    after_days_overdue: int = 7
    severities: list[str] = field(default_factory=lambda: ["critical", "high"])
    mentions: list[str] = field(default_factory=list)


@dataclass
class IssueConfig:
    label: str = "vulgard"
    title: str = "Security debt: vulnerable dependencies need attention"


@dataclass
class RolloutConfig:
    workflow_repo: str = "vulgard"
    workflow_ref: str = "main"
    fail_on_severity: str = "high"
    engine: str = "github"
    auto_merge: list[str] = field(default_factory=list)  # repo names or globs that opt in
    auto_merge_update_types: list[str] = field(
        default_factory=lambda: ["version-update:semver-patch", "version-update:semver-minor"]
    )
    schedule_interval: str = "weekly"
    branch: str = "vulgard/rollout"


@dataclass
class SlackConfig:
    webhook_env: str = "SLACK_WEBHOOK_URL"
    token_env: str = "SLACK_BOT_TOKEN"
    default_channel: str | None = None  # org-wide: the leaderboard, plus unmapped repos
    escalation_channel: str | None = None
    channels: dict[str, str] = field(default_factory=dict)
    users: dict[str, str] = field(default_factory=dict)
    dm_owners: bool = True

    def mention(self, handle: str) -> str:
        slack_id = self.users.get(handle)
        if not slack_id:
            return handle
        return f"<!subteam^{slack_id}>" if slack_id.startswith("S") else f"<@{slack_id}>"

    def dm_target(self, handle: str) -> str | None:
        slack_id = self.users.get(handle, "")
        return slack_id if slack_id[:1] in ("U", "W") else None


@dataclass(frozen=True)
class LinearRoute:
    """Where a repo's Linear issue goes. Unset fields fall back to the `linear` defaults."""

    team: str
    labels: list[str] | None = None
    project: str | None = None
    state: str | None = None
    severity_labels: dict[str, str] | None = None


@dataclass(frozen=True)
class LinearTarget:
    team: str
    labels: tuple[str, ...]
    project: str | None
    state: str | None
    severity_labels: dict[str, str] = field(default_factory=dict)


@dataclass
class LinearConfig:
    api_key_env: str = "LINEAR_API_KEY"
    default_team: str | None = None
    # repo name/glob or owner handle -> team key, or a mapping with team/labels/project/state
    teams: dict[str, Any] = field(default_factory=dict)
    users: dict[str, str] = field(default_factory=dict)
    labels: list[str] = field(default_factory=lambda: ["vulgard"])
    project: str | None = None  # project name for new issues
    state: str | None = None  # workflow state name for new and reopened issues, e.g. "Triage"
    # worst open severity -> label, kept in sync, e.g. {critical: Critical, high: High}
    severity_labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _check_severities("linear.severity_labels", self.severity_labels)
        known = set(LinearRoute.__dataclass_fields__)
        for key, value in self.teams.items():
            if isinstance(value, LinearRoute):
                continue
            if isinstance(value, str):
                self.teams[key] = LinearRoute(team=value)
                continue
            unknown = set(value) - known if isinstance(value, dict) else set()
            if not isinstance(value, dict) or unknown or not value.get("team"):
                raise ValueError(
                    f"linear.teams[{key!r}] must be a team key or a mapping with 'team' and "
                    "optional 'labels', 'project', 'state', 'severity_labels'"
                    + (f" (unknown: {', '.join(sorted(unknown))})" if unknown else "")
                )
            where = f"linear.teams[{key!r}].severity_labels"
            _check_severities(where, value.get("severity_labels"))
            self.teams[key] = LinearRoute(**value)

    def target(self, repo: str, owners: list[str]) -> LinearTarget | None:
        default = LinearRoute(self.default_team) if self.default_team else None
        found = route(self.teams, repo, owners, default)
        if found is None:
            return None
        return LinearTarget(
            team=found.team,
            labels=tuple(self.labels if found.labels is None else found.labels),
            project=found.project or self.project,
            state=found.state or self.state,
            severity_labels=dict(
                self.severity_labels if found.severity_labels is None else found.severity_labels
            ),
        )


def _check_severities(where: str, mapping: dict[str, str] | None) -> None:
    unknown = set(mapping or {}) - set(SEVERITIES)
    if unknown:
        raise ValueError(f"Unknown severities in {where}: {', '.join(sorted(unknown))}")


@dataclass
class KevConfig:
    enabled: bool = True
    sla_days: int = 3


@dataclass
class RiskException:
    reason: str
    expires: date
    advisory: str | None = None  # GHSA or CVE id
    package: str | None = None
    repo: str = "*"


@dataclass
class Config:
    org: str
    include: list[str] = field(default_factory=lambda: ["*"])
    exclude: list[str] = field(default_factory=list)
    sla_days: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SLA_DAYS))
    due_soon_days: int = 5
    stale_pr_days: int = 14
    ready_pr_days: int = 2
    reminder_interval_days: int = 7
    owners: dict[str, list[str]] = field(default_factory=dict)
    default_owners: list[str] = field(default_factory=list)
    escalation: EscalationConfig = field(default_factory=EscalationConfig)
    issue: IssueConfig = field(default_factory=IssueConfig)
    rollout: RolloutConfig = field(default_factory=RolloutConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)
    linear: LinearConfig = field(default_factory=LinearConfig)
    kev: KevConfig = field(default_factory=KevConfig)
    exceptions: list[RiskException] = field(default_factory=list)

    def repo_selected(self, name: str) -> bool:
        if any(fnmatch.fnmatch(name, pat) for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(name, pat) for pat in self.include)

    def auto_merges(self, repo: str) -> bool:
        return any(fnmatch.fnmatch(repo, pat) for pat in self.rollout.auto_merge)


def route[T](mapping: dict[str, T], repo: str, owners: list[str], default: T | None) -> T | None:
    """Exact repo name, then repo glob (e.g. `payments-*`), then the first mapped owner."""
    if repo in mapping:
        return mapping[repo]
    for key, value in mapping.items():
        if not key.startswith("@") and fnmatch.fnmatch(repo, key):
            return value
    for owner in owners:
        if owner in mapping:
            return mapping[owner]
    return default


def _section(raw: dict[str, Any], key: str, cls: type) -> Any:
    data = raw.get(key) or {}
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown keys in '{key}': {', '.join(sorted(unknown))}")
    return cls(**data)


def _parse_exceptions(items: list[dict[str, Any]] | None) -> list[RiskException]:
    known = set(RiskException.__dataclass_fields__)
    parsed = []
    for i, item in enumerate(items or []):
        unknown = set(item) - known
        if unknown:
            raise ValueError(f"Unknown keys in exceptions[{i}]: {', '.join(sorted(unknown))}")
        if not item.get("reason") or not item.get("expires"):
            raise ValueError(f"exceptions[{i}] needs a 'reason' and an 'expires' date")
        if not (item.get("advisory") or item.get("package")):
            raise ValueError(f"exceptions[{i}] needs an 'advisory' or a 'package'")
        expires = item["expires"]
        if isinstance(expires, str):
            expires = date.fromisoformat(expires)
        parsed.append(RiskException(**{**item, "expires": expires}))
    return parsed


def parse_config(raw: dict[str, Any], org_override: str | None = None) -> Config:
    org = org_override or raw.get("org")
    if not org:
        raise ValueError("An 'org' is required (set it in the config file or pass --org)")

    repos = raw.get("repos") or {}
    sla = dict(DEFAULT_SLA_DAYS)
    sla.update({k.lower(): int(v) for k, v in (raw.get("sla_days") or {}).items()})
    bad = set(sla) - set(SEVERITIES)
    if bad:
        raise ValueError(f"Unknown severities in sla_days: {', '.join(sorted(bad))}")

    auto_merge = (raw.get("rollout") or {}).get("auto_merge", [])
    if not isinstance(auto_merge, list):
        raise ValueError(
            "rollout.auto_merge is a list of repos that opt in to auto-merge, "
            'for example ["payments-api", "web-*"], or ["*"] for every repo'
        )

    if "label" in (raw.get("linear") or {}):
        raise ValueError('linear.label is now linear.labels, a list, e.g. ["vulgard"]')

    return Config(
        org=org,
        include=list(repos.get("include") or ["*"]),
        exclude=list(repos.get("exclude") or []),
        sla_days=sla,
        due_soon_days=int(raw.get("due_soon_days", 5)),
        stale_pr_days=int(raw.get("stale_pr_days", 14)),
        ready_pr_days=int(raw.get("ready_pr_days", 2)),
        reminder_interval_days=int(raw.get("reminder_interval_days", 7)),
        owners={k: list(v) for k, v in (raw.get("owners") or {}).items()},
        default_owners=list(raw.get("default_owners") or []),
        escalation=_section(raw, "escalation", EscalationConfig),
        issue=_section(raw, "issue", IssueConfig),
        rollout=_section(raw, "rollout", RolloutConfig),
        slack=_section(raw, "slack", SlackConfig),
        linear=_section(raw, "linear", LinearConfig),
        kev=_section(raw, "kev", KevConfig),
        exceptions=_parse_exceptions(raw.get("exceptions")),
    )


def load_config(path: str | Path | None, org_override: str | None = None) -> Config:
    raw: dict[str, Any] = {}
    if path is not None:
        p = Path(path)
        if p.exists():
            raw = yaml.safe_load(p.read_text()) or {}
        elif str(path) != "vulgard.yml":
            raise FileNotFoundError(f"Config file not found: {path}")
    return parse_config(raw, org_override)
