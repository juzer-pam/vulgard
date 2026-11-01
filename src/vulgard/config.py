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
    auto_merge: bool = True
    auto_merge_update_types: list[str] = field(
        default_factory=lambda: ["version-update:semver-patch", "version-update:semver-minor"]
    )
    schedule_interval: str = "weekly"
    branch: str = "vulgard/rollout"


@dataclass
class SlackConfig:
    webhook_env: str = "SLACK_WEBHOOK_URL"
    token_env: str = "SLACK_BOT_TOKEN"
    digest_channel: str | None = None
    default_channel: str | None = None
    escalation_channel: str | None = None
    # Keyed by repo name or GitHub owner handle; repo wins, then owners in order.
    channels: dict[str, str] = field(default_factory=dict)
    # GitHub handle -> Slack user ID (U…/W…) or user group ID (S…).
    users: dict[str, str] = field(default_factory=dict)
    dm_owners: bool = True


@dataclass
class LinearConfig:
    api_key_env: str = "LINEAR_API_KEY"
    default_team: str | None = None
    # Keyed by repo name or GitHub owner handle -> Linear team key (e.g. "SEC").
    teams: dict[str, str] = field(default_factory=dict)
    # GitHub handle -> Linear user email, used to assign the issue.
    users: dict[str, str] = field(default_factory=dict)
    label: str = "vulgard"


@dataclass
class KevConfig:
    enabled: bool = True
    sla_days: int = 3
    feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )


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


def route(mapping: dict[str, str], repo: str, owners: list[str], default: str | None) -> str | None:
    if repo in mapping:
        return mapping[repo]
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
