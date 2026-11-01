from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from vulgard.baseline import Cancel, Delete, Issued
from vulgard.cli import main
from vulgard.config import DeploymentsConfig, parse_config
from vulgard.estate import (
    AmplifyBranch,
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    Sighting,
    SstStage,
    Tier,
    VercelProject,
)
from vulgard.executor import _changed
from vulgard.fixtures import FixtureExecutor, FixtureGitHub
from vulgard.lifecycle import (
    AmplifyDelete,
    AmplifyRelease,
    CfnDelete,
    Dispatch,
    Notice,
    OpFailed,
    Outcome,
    SafeDelete,
    Trigger,
    Verb,
    VercelDelete,
    VercelRedeploy,
    check_delete,
    execute,
    plan_step,
    reconcile,
    request_id,
    requested_op,
)
from vulgard.rollout import plan_lifecycle_rollout

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
CFG = DeploymentsConfig(
    people={"jlee": "@jlee"},
    workflows={"api": "deploy.yml"},
    auto={"repos": ["api"], "notice_days": 7},
)


def dep(
    native=None,
    framework=Framework.SERVERLESS,
    tier=Tier.PERSONAL,
    repo="api",
    days=100,
    protected=False,
    in_progress=False,
):
    native = native or CfnStack("1", "us-east-1", "api-jlee", "id", "bucket")
    s = Sighting(
        framework,
        native,
        "api",
        "jlee",
        NOW - timedelta(days=days),
        protected=protected,
        in_progress=in_progress,
    )
    person = "@jlee" if tier is Tier.PERSONAL else None
    return Deployment(s, repo, Attribution.MANIFEST, tier, person)


# --- safety


def test_only_check_delete_creates_a_safe_delete():
    with pytest.raises(AssertionError):
        SafeDelete(dep(), object())
    assert isinstance(check_delete(dep(), automatic=True), SafeDelete)


def test_check_delete_refuses_production_running_and_non_personal_automatic_deletes():
    prod = dep(tier=Tier.PRODUCTION, protected=True)
    assert "never deletes production" in check_delete(prod, automatic=False)
    assert "running" in check_delete(dep(in_progress=True), automatic=False)
    shared = dep(tier=Tier.SHARED)
    assert isinstance(check_delete(shared, automatic=False), SafeDelete)
    assert "personal" in check_delete(shared, automatic=True)


def test_vercel_projects_are_never_deleted_automatically():
    vercel = dep(VercelProject("team", "prj"), Framework.VERCEL)
    assert "never deleted automatically" in check_delete(vercel, automatic=True)


# --- the framework table


def test_step_table():
    rid = "vg-1"
    sls = dep()
    redeploy = plan_step(sls, Verb.REDEPLOY, rid, CFG, automatic=False)
    assert isinstance(redeploy, Dispatch) and redeploy.workflow == "deploy.yml"
    assert redeploy.inputs["stage"] == "jlee" and redeploy.inputs["request_id"] == rid
    assert isinstance(plan_step(sls, Verb.DELETE, rid, CFG, False), CfnDelete)

    sst = dep(SstStage("1", "us-east-1", "state", "inventory", "jlee"), Framework.SST)
    assert isinstance(plan_step(sst, Verb.DELETE, rid, CFG, False), Dispatch)

    branch = AmplifyBranch("1", "us-east-1", "app", "feature")
    amplify = dep(branch, Framework.AMPLIFY, tier=Tier.SHARED)
    assert isinstance(plan_step(amplify, Verb.REDEPLOY, rid, CFG, False), AmplifyRelease)
    assert isinstance(plan_step(amplify, Verb.DELETE, rid, CFG, False), AmplifyDelete)

    sandbox = dep(CfnStack("1", "r", "amplify-app-jlee-sandbox-1a", "id"), Framework.AMPLIFY)
    assert "sandbox" in plan_step(sandbox, Verb.REDEPLOY, rid, CFG, False)
    assert isinstance(plan_step(sandbox, Verb.DELETE, rid, CFG, True), CfnDelete)

    vercel = dep(VercelProject("team", "prj"), Framework.VERCEL, tier=Tier.SHARED)
    assert isinstance(plan_step(vercel, Verb.REDEPLOY, rid, CFG, False), VercelRedeploy)
    assert isinstance(plan_step(vercel, Verb.DELETE, rid, CFG, False), VercelDelete)

    orphan = dep(repo=None)
    assert "no repo" in plan_step(orphan, Verb.REDEPLOY, rid, CFG, False)


def test_request_ids_are_deterministic_per_decision():
    a = request_id("cfn:1/r/x", Verb.DELETE, "comment:7")
    assert a == request_id("cfn:1/r/x", Verb.DELETE, "comment:7")
    assert a != request_id("cfn:1/r/x", Verb.DELETE, "comment:8")
    assert a != request_id("cfn:1/r/x", Verb.REDEPLOY, "comment:7")


def test_requested_op_carries_the_comment_in_its_id():
    d = dep(tier=Tier.SHARED)
    req = Issued(Delete(d.key), 7, "jlee", NOW, "u")
    op = requested_op(req, d, CFG)
    assert op.trigger is Trigger.REQUEST and isinstance(op.step, CfnDelete)
    assert op.request_id == request_id(d.key, Verb.DELETE, "comment:7")


# --- automatic ops


def reconciled(d, notices=(), kept=(), cancels=None, vulnerable=False, now=NOW, cfg=CFG):
    return reconcile([d], [], set(kept), cancels or {}, tuple(notices), cfg, vulnerable, now)


def test_automatic_ops_wait_for_the_notice_period_with_a_stable_id():
    d = dep()
    first = reconciled(d)
    (scheduled,) = first.scheduled
    assert scheduled.fresh and scheduled.due == date(2026, 11, 8) and not first.ops
    again = reconciled(d, first.notices, now=NOW + timedelta(days=3))
    assert not again.scheduled[0].fresh and not again.ops
    due = reconciled(d, first.notices, now=NOW + timedelta(days=7))
    later = reconciled(d, due.notices, now=NOW + timedelta(days=8))
    assert due.ops[0].request_id == later.ops[0].request_id
    assert due.ops[0].verb is Verb.REDEPLOY and due.ops[0].trigger is Trigger.STALE


def test_a_notice_posted_today_never_runs_today():
    cfg = replace(CFG, auto=replace(CFG.auto, notice_days=0))
    assert not reconciled(dep(), cfg=cfg).ops


def test_keep_or_a_recent_cancel_stops_automatic_ops():
    d = dep()
    assert not reconciled(d, kept={d.key}).scheduled
    cancel = {d.key: Issued(Cancel(d.key), 1, "jlee", NOW - timedelta(days=1), "u")}
    assert not reconciled(d, cancels=cancel).scheduled
    old = {d.key: Issued(Cancel(d.key), 1, "jlee", NOW - timedelta(days=200), "u")}
    assert reconciled(d, cancels=old).scheduled


def test_only_opted_in_personal_deployments_qualify():
    assert not reconciled(dep(repo="web")).scheduled
    assert not reconciled(dep(tier=Tier.SHARED)).scheduled
    fresh = dep(days=5)
    assert not reconciled(fresh).scheduled
    vulnerable = reconciled(fresh, vulnerable=True).scheduled
    assert vulnerable and vulnerable[0].notice.trigger is Trigger.VULNERABLE


def test_auto_delete_turns_ops_into_deletes():
    cfg = replace(CFG, auto=replace(CFG.auto, delete=True))
    d = dep()
    notice = Notice(d.key, Verb.DELETE, Trigger.STALE, date(2026, 10, 1))
    (op,) = reconciled(d, [notice], cfg=cfg).ops
    assert op.verb is Verb.DELETE and isinstance(op.step, CfnDelete)


def test_notice_round_trips():
    n = Notice("cfn:1/r/x", Verb.DELETE, Trigger.VULNERABLE, date(2026, 11, 1))
    assert Notice.from_json(n.to_json()) == n


# --- execution


class Boom:
    def find(self, step, rid):
        raise OpFailed("DELETE_FAILED: bucket not empty")


def test_execute_is_idempotent_and_reports_failures():
    d = dep(tier=Tier.SHARED)
    op = requested_op(Issued(Delete(d.key), 7, "jlee", NOW, "u"), d, CFG)
    executor = FixtureExecutor({})
    assert execute(op, executor, (OpFailed,)).outcome is Outcome.STARTED
    assert execute(op, executor, (OpFailed,)).outcome is Outcome.RUNNING
    assert len(executor.started) == 1
    assert execute(op, Boom(), (OpFailed,)).outcome is Outcome.FAILED
    blocked = FixtureExecutor({"recheck": {"api-jlee": "it was deployed again since"}})
    result = execute(op, blocked, (OpFailed,))
    assert result.outcome is Outcome.SKIPPED and not blocked.started
    prod = dep(tier=Tier.PRODUCTION, protected=True)
    refused = requested_op(Issued(Delete(prod.key), 8, "jlee", NOW, "u"), prod, CFG)
    assert execute(refused, executor, (OpFailed,)).outcome is Outcome.SKIPPED


def test_live_recheck_refuses_changed_targets():
    config = parse_config({"org": "acme", "deployments": {"people": {"jlee": "@jlee"}}})
    d = dep()
    safe = check_delete(d, automatic=True)
    assert isinstance(safe, SafeDelete)
    assert "already gone" in _changed(safe, None, config)
    redeployed = replace(d.sighting, last_deployed=NOW)
    assert "deployed again" in _changed(safe, redeployed, config)
    renamed = replace(d.sighting, stage="prod")
    assert "tier changed" in _changed(safe, renamed, config)
    assert _changed(safe, d.sighting, config) is None


# --- rollout and CLI


def test_lifecycle_rollout_needs_a_role_and_a_workflow_framework():
    repo = {"name": "inventory", "default_branch": "main"}
    gh = FixtureGitHub({"repos": [repo]})
    bare = parse_config({"org": "acme"})
    plan = plan_lifecycle_rollout(gh, bare, repo, frozenset({Framework.SST}))
    assert plan.skipped_reason and "deploy_role_arn" in plan.skipped_reason
    role = {"aws": {"deploy_role_arn": "arn:aws:iam::1:role/GithubCI"}}
    config = parse_config({"org": "acme", "deployments": role})
    assert plan_lifecycle_rollout(gh, config, repo, frozenset({Framework.VERCEL})).skipped_reason
    plan = plan_lifecycle_rollout(gh, config, repo, frozenset({Framework.SST}))
    (content,) = plan.files.values()
    assert "role: arn:aws:iam::1:role/GithubCI" in content
    assert "[${{ inputs.request_id }}]" in content


def test_nag_execute_dry_run_lists_due_ops(capsys):
    fixtures = ["--fixtures", str(EXAMPLES / "demo-org.json")]
    config = ["--config", str(EXAMPLES / "vulgard.yml")]
    assert main([*fixtures, *config, "nag", "--topic", "stale", "--execute"]) == 0
    assert "automatic op(s) announced" in capsys.readouterr().out
