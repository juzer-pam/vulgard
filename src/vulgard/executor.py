"""The live lifecycle executor: maps each step to GitHub, AWS or Vercel."""

from __future__ import annotations

from typing import Any, assert_never

from .aws import AwsOps, sight_cfn_stack
from .config import Config
from .estate import EMPTY_INDEX, classify, native_name
from .lifecycle import (
    AmplifyDelete,
    AmplifyRelease,
    CfnDelete,
    Dispatch,
    SafeDelete,
    Step,
    VercelDelete,
    VercelRedeploy,
)
from .vercel import Vercel, sight_vercel_project


class LiveExecutor:
    def __init__(self, gh: Any, config: Config, aws: AwsOps, vercel: Vercel | None):
        self._gh = gh
        self._config = config
        self._aws = aws
        self._vercel = vercel

    def _vercel_client(self) -> Vercel:
        if self._vercel is None:
            raise RuntimeError("Vercel ops need $VERCEL_TOKEN and deployments.vercel.team_id")
        return self._vercel

    def find(self, step: Step, request_id: str) -> str | None:
        match step:
            case Dispatch(repo=repo, workflow=wf):
                return self._gh.find_workflow_run(self._config.org, repo, wf, request_id)
            case CfnDelete(target=t):
                return self._aws.deleting(t.deployment.sighting.native, request_id)
            case AmplifyRelease(branch=b):
                return self._aws.amplify_job(b, request_id)
            case AmplifyDelete(target=t):
                ref = t.deployment.sighting.native
                return None if self._aws.amplify_branch(ref) else self._aws.amplify_url(ref)
            case VercelRedeploy(project=p):
                return self._vercel_client().find_redeploy(p.project_id, request_id)
            case VercelDelete(target=t):
                ref = t.deployment.sighting.native
                gone = self._vercel_client().project(ref.project_id) is None
                return f"https://vercel.com/{ref.team_id}" if gone else None
            case _ as unreachable:
                assert_never(unreachable)

    def recheck(self, step: Step) -> str | None:
        """Re-read the live target: it must still be the same, unprotected, idle deployment."""
        match step:
            case CfnDelete(target=t):
                ref = t.deployment.sighting.native
                raw = self._aws.stack(ref)
                live = sight_cfn_stack(raw, ref.account, ref.region) if raw else None
            case AmplifyDelete(target=t):
                live = self._aws.amplify_branch(t.deployment.sighting.native)
            case VercelDelete(target=t):
                ref = t.deployment.sighting.native
                raw = self._vercel_client().project(ref.project_id)
                live = sight_vercel_project(raw, ref.team_id) if raw else None
            case Dispatch() | AmplifyRelease() | VercelRedeploy():
                return None
            case _ as unreachable:
                assert_never(unreachable)
        return _changed(t, live, self._config)

    def start(self, step: Step, request_id: str) -> str:
        org = self._config.org
        match step:
            case Dispatch(repo=repo, workflow=wf, inputs=inputs):
                branch = self._gh.get_repo(org, repo).get("default_branch") or "main"
                self._gh.dispatch_workflow(org, repo, wf, branch, dict(inputs))
                return f"https://github.com/{org}/{repo}/actions/workflows/{wf}"
            case CfnDelete(target=t):
                return self._aws.delete_stack(t.deployment.sighting.native, request_id)
            case AmplifyRelease(branch=b):
                return self._aws.amplify_release(b, request_id)
            case AmplifyDelete(target=t):
                return self._aws.amplify_delete(t.deployment.sighting.native)
            case VercelRedeploy(project=p):
                return self._vercel_client().redeploy(p.project_id, request_id)
            case VercelDelete(target=t):
                return self._vercel_client().delete(t.deployment.sighting.native.project_id)
            case _ as unreachable:
                assert_never(unreachable)


def _changed(target: SafeDelete, live: Any, config: Config) -> str | None:
    """Why the live deployment no longer matches what was approved for deletion, if it doesn't."""
    d = target.deployment
    if live is None:
        return f"`{native_name(d.sighting.native)}` is already gone"
    if live.protected or live.in_progress:
        return "it's protected or a deploy is running now"
    if live.last_deployed > d.last_deployed:
        return "it was deployed again since; leaving it alone"
    now = classify(live, EMPTY_INDEX, config.deployments)
    if now is None or now.tier is not d.tier:
        return "its tier changed since it was planned"
    return None
