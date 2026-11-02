"""The live executor: maps each op to GitHub, AWS or Vercel.

This is where infrastructure failures become `OpFailed`, so `execute.py` and the policy code
never see boto3 or HTTP exceptions.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, assert_never

import httpx
from botocore.exceptions import BotoCoreError, ClientError

from .aws import AwsOps, sight_cfn_stack
from .config import Config
from .estate import (
    AmplifyBranch,
    CfnStack,
    Deployment,
    NativeRef,
    OpFailed,
    Sighting,
    SstStage,
    VercelProject,
)
from .github import GitHubError
from .lifecycle import NO_REPO, Op, SafeDelete, Verb
from .vercel import Vercel, VercelError, sight_vercel_project

OP_ERRORS = (GitHubError, VercelError, BotoCoreError, ClientError, httpx.HTTPError)


def _translated[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return fn(*args, **kwargs)
        except OP_ERRORS as e:
            raise OpFailed(str(e)) from e

    return wrapper


def workflow_inputs(d: Deployment, verb: Verb, request_id: str) -> dict[str, str]:
    """The inputs of the lifecycle workflow, which the repo's `vulgard-lifecycle.yml` declares."""
    native = d.sighting.native
    return {
        "action": verb.value,
        "framework": d.framework.value,
        "app": d.sighting.app,
        "stage": d.sighting.stage or "",
        "stack": native.name if isinstance(native, CfnStack) else "",
        "request_id": request_id,
    }


class LiveExecutor:
    def __init__(self, gh: Any, config: Config, aws: AwsOps, vercel: Vercel | None):
        self._gh = gh
        self._config = config
        self._aws = aws
        self._vercel = vercel

    def _vercel_client(self) -> Vercel:
        if self._vercel is None:
            raise OpFailed("Vercel ops need $VERCEL_TOKEN and deployments.vercel.team_id")
        return self._vercel

    def _workflow(self, d: Deployment) -> tuple[str, str]:
        if d.repo is None:
            raise OpFailed(NO_REPO)
        return d.repo, self._config.deployments.workflow_for(d.repo)

    def _find_run(self, d: Deployment, request_id: str) -> str | None:
        repo, workflow = self._workflow(d)
        return self._gh.find_workflow_run(self._config.org, repo, workflow, request_id)

    def _dispatch(self, d: Deployment, verb: Verb, request_id: str) -> str:
        org = self._config.org
        repo, workflow = self._workflow(d)
        branch = self._gh.get_repo(org, repo).get("default_branch") or "main"
        inputs = workflow_inputs(d, verb, request_id)
        self._gh.dispatch_workflow(org, repo, workflow, branch, inputs)
        return f"https://github.com/{org}/{repo}/actions/workflows/{workflow}"

    @_translated
    def observe(self, native: NativeRef) -> Sighting | None:
        match native:
            case CfnStack():
                raw = self._aws.stack(native)
                return sight_cfn_stack(raw, native.account, native.region) if raw else None
            case SstStage():
                return self._aws.sst_stage(native)
            case AmplifyBranch():
                return self._aws.amplify_branch(native)
            case VercelProject():
                raw = self._vercel_client().project(native.project_id)
                return sight_vercel_project(raw, native.team_id) if raw else None
            case _ as unreachable:
                assert_never(unreachable)

    @_translated
    def find(self, op: Op) -> str | None:
        d, rid = op.deployment, op.request_id
        redeploying = op.verb is Verb.REDEPLOY
        match d.sighting.native:
            case CfnStack() as ref:
                return self._find_run(d, rid) if redeploying else self._aws.deleting(ref, rid)
            case SstStage():
                return self._find_run(d, rid)
            case AmplifyBranch() as ref:
                return self._aws.amplify_job(ref, rid) if redeploying else None
            case VercelProject() as ref:
                vercel = self._vercel_client()
                return vercel.find_redeploy(ref.project_id, rid) if redeploying else None
            case _ as unreachable:
                assert_never(unreachable)

    @_translated
    def redeploy(self, d: Deployment, request_id: str) -> str:
        match d.sighting.native:
            case CfnStack() | SstStage():
                return self._dispatch(d, Verb.REDEPLOY, request_id)
            case AmplifyBranch() as ref:
                return self._aws.amplify_release(ref, request_id)
            case VercelProject() as ref:
                return self._vercel_client().redeploy(ref.project_id, request_id)
            case _ as unreachable:
                assert_never(unreachable)

    @_translated
    def delete(self, proof: SafeDelete, request_id: str) -> str:
        d = proof.deployment
        match d.sighting.native:
            case CfnStack() as ref:
                return self._aws.delete_stack(ref, request_id)
            case SstStage():
                return self._dispatch(d, Verb.DELETE, request_id)  # only `sst remove` deletes SST
            case AmplifyBranch() as ref:
                return self._aws.amplify_delete(ref)
            case VercelProject() as ref:
                return self._vercel_client().delete(ref.project_id)
            case _ as unreachable:
                assert_never(unreachable)
