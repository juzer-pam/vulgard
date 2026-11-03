from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

import yaml

from .config import Config
from .estate import Framework

DEPENDABOT_PATH = ".github/dependabot.yml"
WORKFLOW_PATH = ".github/workflows/vulgard.yml"
LIFECYCLE_BRANCH = "vulgard/lifecycle"
WORKFLOW_FRAMEWORKS = frozenset({Framework.SERVERLESS, Framework.SST, Framework.CDK})

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
DOCS_ONLY_SKIP = "docs only (no dependency manifests)"


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


def rollout_skip_reason(paths: list[str]) -> str | None:
    """Skip repos with nothing for Dependabot or vulgard to scan (README-only, and so on).

    Workflows alone do not count: a docs repo with only a Pages workflow is still skipped.
    """
    eco = detect_ecosystems(paths)
    if set(eco) - {"github-actions"}:
        return None
    return DOCS_ONLY_SKIP


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
            "major": {
                "applies-to": "version-updates",
                "update-types": ["major"],
            },
        }
        updates.append(entry)
    header = (
        "# Managed by vulgard. Security, minor/patch, and major updates each become one\n"
        "# grouped PR per ecosystem, instead of one PR per package.\n"
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
- Dependabot opens **grouped PRs per ecosystem** (security, minor/patch, and major), instead of \
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
    """Files to put on a branch and open a PR for. `plan_rollout` and `plan_lifecycle_rollout`
    differ only in what they fill in here, and `apply_rollout` doesn't need to know which."""

    repo: str
    default_branch: str
    branch: str  # the PR's head branch
    pr_title: str = ""
    pr_body: str = ""
    enable_security: bool = True  # also turn on Dependabot alerts, security updates and auto-merge
    files: dict[str, str] = field(default_factory=dict)
    skipped_reason: str | None = None
    existing_pr: str | None = None


def render_lifecycle_workflow(config: Config, role: str) -> str:
    r, aws = config.rollout, config.deployments.aws
    source = f"{config.org}/{r.workflow_repo}"
    title = "vulgard ${{ inputs.action }} ${{ inputs.stage || inputs.stack }}"
    return f"""{MANAGED_MARK} ({source}). Lets vulgard redeploy or remove stale stacks.
name: vulgard lifecycle
run-name: "{title} [${{{{ inputs.request_id }}}}]"

on:
  workflow_dispatch:
    inputs:
      action:
        type: choice
        options: [redeploy, delete]
        required: true
      framework:
        type: string
        required: true
      app:
        type: string
        required: true
      stage:
        type: string
        default: ""
      stack:
        type: string
        default: ""
      request_id:
        type: string
        required: true

permissions:
  contents: read
  id-token: write

jobs:
  lifecycle:
    uses: {source}/.github/workflows/lifecycle.yml@{r.workflow_ref}
    with:
      action: ${{{{ inputs.action }}}}
      framework: ${{{{ inputs.framework }}}}
      app: ${{{{ inputs.app }}}}
      stage: ${{{{ inputs.stage }}}}
      stack: ${{{{ inputs.stack }}}}
      request_id: ${{{{ inputs.request_id }}}}
      role: {role}
      region: {aws.regions[0]}
"""


LIFECYCLE_BODY = """\
This PR was opened by vulgard. It adds `{path}`, which vulgard runs to redeploy or remove a \
stale Serverless, SST or CDK stack of this repo when someone comments \
`/vulgard redeploy <name>` or `/vulgard delete <name>` on the repo's stale-deployments issue.

It runs from the default branch with this repo's own deploy role, and it never deletes \
production. Only vulgard's GitHub App and repo admins can dispatch it. If your deploys need \
more than `npm ci` and the framework CLI (secrets, build steps, a monorepo path), say so here \
and we'll point vulgard at your existing deploy workflow instead.
"""


def plan_lifecycle_rollout(
    gh: Any, config: Config, repo: dict[str, Any], frameworks: frozenset[Framework]
) -> RolloutPlan:
    name, default = repo["name"], repo.get("default_branch", "main")
    plan = RolloutPlan(
        repo=name,
        default_branch=default,
        branch=LIFECYCLE_BRANCH,
        pr_title="ci: let vulgard redeploy or remove stale stacks",
        enable_security=False,
    )
    cfg = config.deployments
    role = cfg.aws.deploy_role_arn
    if not role:
        plan.skipped_reason = "set deployments.aws.deploy_role_arn first"
    elif not frameworks & WORKFLOW_FRAMEWORKS:
        plan.skipped_reason = "no Serverless, SST or CDK app"
    elif name in cfg.workflows:
        plan.skipped_reason = f"uses {cfg.workflows[name]}"
    if plan.skipped_reason or not role:
        return plan
    existing = gh.find_open_pr(config.org, name, LIFECYCLE_BRANCH)
    plan.existing_pr = existing["html_url"] if existing else None
    path = f".github/workflows/{cfg.lifecycle_workflow}"
    current = gh.get_file(config.org, name, path, LIFECYCLE_BRANCH if existing else default)
    desired = render_lifecycle_workflow(config, role)
    if current != desired and (current is None or current.startswith(MANAGED_MARK)):
        plan.files[path] = desired
        plan.pr_body = LIFECYCLE_BODY.format(path=path)
    else:
        plan.skipped_reason = "up to date"
    return plan


def plan_rollout(gh: Any, config: Config, repo: dict[str, Any]) -> RolloutPlan:
    """Files to add or refresh. Compares against the open rollout PR's branch if there is one."""
    name, default = repo["name"], repo.get("default_branch", "main")
    plan = RolloutPlan(
        repo=name,
        default_branch=default,
        branch=config.rollout.branch,
        pr_title="chore(security): enable vulgard dependency checks",
    )
    if repo.get("archived") or repo.get("fork"):
        plan.skipped_reason = "archived" if repo.get("archived") else "fork"
        return plan
    paths = gh.list_tree_paths(config.org, name, default)
    if skip := rollout_skip_reason(paths):
        plan.skipped_reason = skip
        return plan
    existing = gh.find_open_pr(config.org, name, config.rollout.branch)
    plan.existing_pr = existing["html_url"] if existing else None
    ref = config.rollout.branch if existing else default

    ecosystems = detect_ecosystems(paths)
    desired_dependabot = None
    if ecosystems:
        desired_dependabot = render_dependabot_config(
            ecosystems, config.rollout.schedule_interval
        )
    current_dependabot = gh.get_file(config.org, name, DEPENDABOT_PATH, ref)
    if desired_dependabot and (
        current_dependabot is None
        or (
            current_dependabot.startswith(MANAGED_MARK) and current_dependabot != desired_dependabot
        )
    ):
        plan.files[DEPENDABOT_PATH] = desired_dependabot
    current = gh.get_file(config.org, name, WORKFLOW_PATH, ref)
    desired = render_caller_workflow(config, name)
    if current != desired and (current is None or current.startswith(MANAGED_MARK)):
        plan.files[WORKFLOW_PATH] = desired
    if not plan.files:
        plan.skipped_reason = "up to date"
        return plan
    items = "\n".join(f"- `{p}`" for p in plan.files)
    automerge = AUTOMERGE_ON if config.auto_merges(name) else AUTOMERGE_OFF
    severity = config.rollout.fail_on_severity
    plan.pr_body = PR_BODY.format(items=items, severity=severity, automerge=automerge)
    return plan


def apply_rollout(gh: Any, config: Config, plan: RolloutPlan) -> str | None:
    org = config.org
    if plan.enable_security:
        gh.enable_security_features(org, plan.repo, allow_auto_merge=config.auto_merges(plan.repo))
    if not plan.files:
        return None
    if gh.get_branch_sha(org, plan.repo, plan.branch) is None:
        base_sha = gh.get_branch_sha(org, plan.repo, plan.default_branch)
        gh.create_branch(org, plan.repo, plan.branch, base_sha)
    for path, content in plan.files.items():
        gh.put_file(org, plan.repo, path, content, f"chore(security): vulgard {path}", plan.branch)
    if plan.existing_pr:
        return plan.existing_pr
    pr = gh.create_pr(
        org, plan.repo, plan.pr_title, plan.pr_body, plan.branch, plan.default_branch
    )
    return pr["html_url"]
