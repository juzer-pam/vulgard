from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

import yaml

from .config import Config

DEPENDABOT_PATH = ".github/dependabot.yml"
WORKFLOW_PATH = ".github/workflows/vulgard.yml"

MANIFESTS: dict[str, str] = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pip",
    "setup.py": "pip",
    "go.mod": "gomod",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "composer.json": "composer",
    "mix.exs": "mix",
    "pubspec.yaml": "pub",
    "Package.swift": "swift",
    "main.tf": "terraform",
}
SKIP_DIRS = ("node_modules/", "vendor/", "third_party/", ".git/", "dist/", "build/")


def detect_ecosystems(paths: list[str]) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {}

    def add(eco: str, directory: str) -> None:
        found.setdefault(eco, set()).add("/" + directory.strip("/") if directory else "/")

    for path in paths:
        if any(f"/{d}" in f"/{path}" for d in SKIP_DIRS):
            continue
        directory, name = posixpath.split(path)
        if name in MANIFESTS:
            add(MANIFESTS[name], directory)
        elif name.endswith((".csproj", ".fsproj", ".vbproj")) or name == "packages.config":
            add("nuget", directory)
        elif name == "Dockerfile" or name.endswith(".Dockerfile"):
            add("docker", directory)
        elif path.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            add("github-actions", "")
    return {eco: sorted(dirs) for eco, dirs in sorted(found.items())}


def render_dependabot_config(ecosystems: dict[str, list[str]], interval: str) -> str:
    updates = []
    for eco, dirs in ecosystems.items():
        entry: dict[str, Any] = {"package-ecosystem": eco}
        if dirs == ["/"]:
            entry["directory"] = "/"
        else:
            entry["directories"] = dirs
        entry["schedule"] = {"interval": interval}
        entry["open-pull-requests-limit"] = 10
        entry["groups"] = {
            "security": {"applies-to": "security-updates", "patterns": ["*"]},
            "minor-and-patch": {
                "applies-to": "version-updates",
                "update-types": ["minor", "patch"],
            },
        }
        updates.append(entry)
    header = (
        "# Managed by vulgard. Minor and patch updates are grouped into one PR per\n"
        "# ecosystem, so there are fewer to review.\n"
    )
    return header + yaml.safe_dump({"version": 2, "updates": updates}, sort_keys=False)


MANAGED_MARK = "# Managed by vulgard"


def render_caller_workflow(config: Config, repo: str) -> str:
    r = config.rollout
    source = f"{config.org}/{r.workflow_repo}"
    purpose = "Blocks PRs that add vulnerable dependencies."
    automerge = ""
    if config.auto_merges(repo):
        purpose += "\n# Auto-merges minor and patch Dependabot updates once required checks pass."
        automerge = f"""
  automerge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    uses: {source}/.github/workflows/automerge.yml@{r.workflow_ref}
    permissions:
      contents: write
      pull-requests: write
    with:
      update-types: {",".join(r.auto_merge_update_types)}
"""
    return f"""{MANAGED_MARK} ({source}). {purpose}
name: vulgard

on:
  pull_request:

permissions:
  contents: read

jobs:
  guard:
    uses: {source}/.github/workflows/guard.yml@{r.workflow_ref}
    permissions:
      contents: read
      pull-requests: write
    with:
      fail-on-severity: {r.fail_on_severity}
      engine: {r.engine}
{automerge}"""


PR_BODY = """\
This PR was opened by vulgard, the org-wide dependency security automation.

It adds or updates:
{items}

**What changes for you**
- PRs that add a dependency with a known **{severity}**-or-worse vulnerability fail the \
`vulgard / guard / scan` check.
- Dependabot opens **one grouped PR per ecosystem** for minor and patch updates, instead of \
one PR per package.
{automerge}
Please merge this PR. If something doesn't fit this repo, comment here instead of closing it.
"""

AUTOMERGE_ON = (
    "- Those grouped PRs **merge automatically** once your required checks pass. "
    "Major updates still need a human.\n"
)
AUTOMERGE_OFF = (
    "- Dependabot PRs still need a human to merge. Ask to add this repo to "
    "`rollout.auto_merge` if you want minor and patch updates merged automatically.\n"
)


@dataclass
class RolloutPlan:
    repo: str
    default_branch: str
    files: dict[str, str] = field(default_factory=dict)
    skipped_reason: str | None = None
    existing_pr: str | None = None


def plan_rollout(gh: Any, config: Config, repo: dict[str, Any]) -> RolloutPlan:
    """Files to add or refresh. Compares against the open rollout PR's branch if there is one."""
    name, branch = repo["name"], repo.get("default_branch", "main")
    plan = RolloutPlan(repo=name, default_branch=branch)
    if repo.get("archived") or repo.get("fork"):
        plan.skipped_reason = "archived" if repo.get("archived") else "fork"
        return plan
    existing = gh.find_open_pr(config.org, name, config.rollout.branch)
    plan.existing_pr = existing["html_url"] if existing else None
    ref = config.rollout.branch if existing else branch

    if gh.get_file(config.org, name, DEPENDABOT_PATH, ref) is None:
        ecosystems = detect_ecosystems(gh.list_tree_paths(config.org, name, branch))
        if ecosystems:
            plan.files[DEPENDABOT_PATH] = render_dependabot_config(
                ecosystems, config.rollout.schedule_interval
            )
    current = gh.get_file(config.org, name, WORKFLOW_PATH, ref)
    desired = render_caller_workflow(config, name)
    if current != desired and (current is None or current.startswith(MANAGED_MARK)):
        plan.files[WORKFLOW_PATH] = desired
    if not plan.files:
        plan.skipped_reason = "up to date"
    return plan


def apply_rollout(gh: Any, config: Config, plan: RolloutPlan) -> str | None:
    org, branch = config.org, config.rollout.branch
    gh.enable_security_features(org, plan.repo, allow_auto_merge=config.auto_merges(plan.repo))
    if not plan.files:
        return None
    if gh.get_branch_sha(org, plan.repo, branch) is None:
        base_sha = gh.get_branch_sha(org, plan.repo, plan.default_branch)
        gh.create_branch(org, plan.repo, branch, base_sha)
    for path, content in plan.files.items():
        gh.put_file(org, plan.repo, path, content, f"chore(security): vulgard {path}", branch)
    if plan.existing_pr:
        return plan.existing_pr
    items = "\n".join(f"- `{p}`" for p in plan.files)
    automerge = AUTOMERGE_ON if config.auto_merges(plan.repo) else AUTOMERGE_OFF
    pr = gh.create_pr(
        org,
        plan.repo,
        "chore(security): enable vulgard dependency checks",
        PR_BODY.format(
            items=items, severity=config.rollout.fail_on_severity, automerge=automerge
        ),
        branch,
        plan.default_branch,
    )
    return pr["html_url"]
