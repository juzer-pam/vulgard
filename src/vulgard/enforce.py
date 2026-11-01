from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Config
from .rollout import WORKFLOW_PATH

RULESET_NAME = "vulgard: block vulnerable dependencies"
STATUS_CHECK_CONTEXT = "guard / scan"
REQUIRED_WORKFLOW_PATH = ".github/workflows/guard-required.yml"


@dataclass
class EnforcePlan:
    mode: str
    ruleset: dict[str, Any]
    existing_id: int | None
    enrolled: list[str]


def build_ruleset(
    config: Config, mode: str, enrolled: list[str], workflow_repo_id: int | None
) -> dict[str, Any]:
    if mode == "status-check":
        # Only require the check where the caller workflow exists, otherwise every PR in a
        # not-yet-enrolled repo would wait forever on a check that never reports.
        if not enrolled:
            raise ValueError(
                f"No repos contain {WORKFLOW_PATH} on their default branch yet. "
                "Run `vulgard rollout --apply` and merge those PRs first."
            )
        repo_condition = {"include": enrolled, "exclude": [], "protected": False}
        rule = {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": True,
                "required_status_checks": [{"context": STATUS_CHECK_CONTEXT}],
            },
        }
    elif mode == "workflow":
        if workflow_repo_id is None:
            raise ValueError("workflow mode needs the id of the vulgard repository")
        repo_condition = {
            "include": ["~ALL"] if config.include == ["*"] else config.include,
            "exclude": config.exclude + [config.rollout.workflow_repo],
            "protected": False,
        }
        rule = {
            "type": "workflows",
            "parameters": {
                "do_not_enforce_on_create": True,
                "workflows": [
                    {
                        "path": REQUIRED_WORKFLOW_PATH,
                        "repository_id": workflow_repo_id,
                        "ref": f"refs/heads/{config.rollout.workflow_ref}",
                    }
                ],
            },
        }
    else:
        raise ValueError(f"Unknown enforcement mode: {mode}")

    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
            "repository_name": repo_condition,
        },
        "rules": [rule],
    }


def plan_enforce(gh: Any, config: Config, mode: str, repos: list[dict[str, Any]]) -> EnforcePlan:
    enrolled: list[str] = []
    workflow_repo_id = None
    if mode == "status-check":
        enrolled = sorted(
            r["name"] for r in repos if gh.get_file(config.org, r["name"], WORKFLOW_PATH)
        )
    else:
        workflow_repo_id = gh.get_repo(config.org, config.rollout.workflow_repo)["id"]
    ruleset = build_ruleset(config, mode, enrolled, workflow_repo_id)
    existing = next(
        (r["id"] for r in gh.list_org_rulesets(config.org) if r["name"] == RULESET_NAME), None
    )
    return EnforcePlan(mode=mode, ruleset=ruleset, existing_id=existing, enrolled=enrolled)


def apply_enforce(gh: Any, config: Config, plan: EnforcePlan) -> None:
    if plan.existing_id is None:
        gh.create_org_ruleset(config.org, plan.ruleset)
    else:
        gh.update_org_ruleset(config.org, plan.existing_id, plan.ruleset)
