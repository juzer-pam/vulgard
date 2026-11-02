"""GitHub-side repo data: which repos are in scope, who owns them, which frameworks they use and
how active they are. Wire parsing for the cloud control planes lives with their scanners."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .config import Config
from .estate import IDENTITY_FILES, MARKERS, Framework, RepoIndex, manifest_identity
from .policy import parse_codeowners_default, parse_time

CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def selected_repos(gh: Any, config: Config, only: list[str] | None = None) -> list[dict]:
    repos = [
        r
        for r in gh.list_repos(config.org)
        if not r.get("archived") and config.repo_selected(r["name"])
    ]
    if only:
        repos = [r for r in repos if r["name"] in only]
    return repos


def resolve_owners(gh: Any, config: Config, repo: str) -> list[str]:
    if repo in config.owners:
        return config.owners[repo]
    for path in CODEOWNERS_PATHS:
        text = gh.get_file(config.org, repo, path)
        if text:
            owners = parse_codeowners_default(text)
            if owners:
                return owners
    return config.default_owners


def build_index(gh: Any, config: Config, repos: list[dict[str, Any]]) -> RepoIndex:
    """One tree listing per repo, plus the serverless and SST manifests it finds."""
    found: dict[tuple[Framework, str], set[str]] = {}
    frameworks: dict[str, frozenset[Framework]] = {}
    for r in repos:
        name = r["name"]
        paths = [
            p
            for p in gh.list_tree_paths(config.org, name, r.get("default_branch") or "main")
            if "node_modules/" not in p
        ]
        marked = {fw: [p for p in paths if rx.search(p)] for fw, rx in MARKERS.items()}
        frameworks[name] = frozenset(fw for fw, hits in marked.items() if hits)
        for fw in IDENTITY_FILES:
            for path in marked[fw][:5]:
                text = gh.get_file(config.org, name, path)
                ident = manifest_identity(fw, text) if text else None
                if ident:
                    found.setdefault((fw, ident), set()).add(name)
    by_identity = {k: (next(iter(v)) if len(v) == 1 else None) for k, v in found.items()}
    return RepoIndex(frozenset(r["name"] for r in repos), by_identity, frameworks)


@dataclass(frozen=True)
class RepoActivity:
    repo: str
    last_commit: datetime | None  # None: no commits seen
    created_at: datetime | None = None  # anchors the inactivity clock when there are no commits


def _is_bot(commit: dict[str, Any]) -> bool:
    author = commit.get("author") or {}
    name = ((commit.get("commit") or {}).get("author") or {}).get("name", "")
    return author.get("type") == "Bot" or "[bot]" in author.get("login", "") or "[bot]" in name


def last_human_commit(commits: list[dict[str, Any]]) -> datetime | None:
    """Latest commit not made by a bot. If every listed commit is a bot's, the human one is
    older than all of them, so the oldest listed date is a safe upper bound."""
    dates = [
        (parse_time(c["commit"]["committer"]["date"]), _is_bot(c))
        for c in commits
        if (c.get("commit") or {}).get("committer")
    ]
    human = [d for d, bot in dates if not bot]
    if human:
        return max(human)
    return min((d for d, _ in dates), default=None)


def repo_activity(gh: Any, config: Config, repos: list[dict[str, Any]]) -> list[RepoActivity]:
    return [
        RepoActivity(
            r["name"],
            last_human_commit(
                gh.list_commits(config.org, r["name"], r.get("default_branch") or "main")
            ),
            parse_time(r["created_at"]) if r.get("created_at") else None,
        )
        for r in repos
    ]
