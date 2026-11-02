from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulgard.baseline import Cancel, Decisions, Delete, Issued, Keep
from vulgard.cli import main
from vulgard.config import AutoConfig, DeploymentsConfig, load_config, parse_config
from vulgard.estate import (
    AmplifyBranch,
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    OpFailed,
    Sighting,
    SstStage,
    Tier,
    VercelProject,
)
from vulgard.execute import Outcome, execute
from vulgard.executor import LiveExecutor, workflow_inputs
from vulgard.fixtures import FixtureGitHub, fixture_clients
from vulgard.github import GitHubError
from vulgard.lifecycle import (
    NO_REPO,
    RUNNING_NOW,
    SANDBOX,
    Notice,
    Op,
    SafeDelete,
    Trigger,
    Verb,
    check_delete,
    notice_marker,
    notices_from,
    plan_op,
    recheck,
    reconcile,
    request_id,
    requested_op,
)
from vulgard.plan import IssueComment
from vulgard.rollout import apply_rollout, plan_lifecycle_rollout
from vulgard.topics import NagContext, run_stale

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
CFG = DeploymentsConfig(
    people={"jlee": "@jlee"},
    workflows={"api": "deploy.yml"},
    auto=AutoConfig(repos=["api"], notice_days=7),
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


PLAIN = parse_config({"org": "acme"}).deployments  # no people, so nothing is personal


def bot_comment(body, days_ago, id=1, author="vulgard[bot]"):
    at = NOW - timedelta(days=days_ago)
    return IssueComment(id, author, body, at, f"u{id}")


# --- safety


def test_check_delete_refuses_production_running_and_non_personal_automatic_deletes():
    prod = dep(tier=Tier.PRODUCTION, protected=True)
    assert "never deletes production" in check_delete(prod, automatic=False)
    assert check_delete(dep(in_progress=True), automatic=False) == RUNNING_NOW
    shared = dep(tier=Tier.SHARED)
    assert isinstance(check_delete(shared, automatic=False), SafeDelete)
    assert "personal" in check_delete(shared, automatic=True)
    vercel = dep(VercelProject("team", "prj"), Framework.VERCEL)
    assert "never deleted automatically" in check_delete(vercel, automatic=True)


def test_a_runnable_delete_carries_its_proof_and_a_blocked_op_carries_a_reason():
    d = dep(tier=Tier.SHARED)
    op = plan_op(d, Verb.DELETE, Trigger.REQUEST, "vg-1")
    assert op.runnable and op.delete is not None and op.delete.deployment == d
    prod = plan_op(dep(tier=Tier.PRODUCTION), Verb.DELETE, Trigger.REQUEST, "vg-2")
    assert not prod.runnable and prod.delete is None
    with pytest.raises(AssertionError):
        Op(d, Verb.DELETE, Trigger.REQUEST, "vg-3")  # a delete without proof or a reason


def test_plan_op_blockers():
    sandbox = dep(CfnStack("1", "r", "amplify-app-jlee-sandbox-1a", "id"), Framework.AMPLIFY)
    assert plan_op(sandbox, Verb.REDEPLOY, Trigger.REQUEST, "r").blocked == SANDBOX
    assert plan_op(sandbox, Verb.DELETE, Trigger.STALE, "r").runnable
    assert plan_op(dep(repo=None), Verb.REDEPLOY, Trigger.REQUEST, "r").blocked == NO_REPO
    running = dep(in_progress=True)
    assert plan_op(running, Verb.REDEPLOY, Trigger.REQUEST, "r").blocked == RUNNING_NOW
    sst = dep(SstStage("1", "us-east-1", "state", "inv", "jlee"), Framework.SST, repo=None)
    assert plan_op(sst, Verb.DELETE, Trigger.REQUEST, "r").blocked == NO_REPO
    branch = dep(AmplifyBranch("1", "r", "app", "feature"), Framework.AMPLIFY, tier=Tier.SHARED)
    assert plan_op(branch, Verb.REDEPLOY, Trigger.REQUEST, "r").runnable
    assert plan_op(branch, Verb.DELETE, Trigger.REQUEST, "r").runnable


def test_request_ids_are_deterministic_per_decision():
    a = request_id("cfn:1/r/x", Verb.DELETE, "comment:7")
    assert a == request_id("cfn:1/r/x", Verb.DELETE, "comment:7")
    assert a != request_id("cfn:1/r/x", Verb.DELETE, "comment:8")
    assert a != request_id("cfn:1/r/x", Verb.REDEPLOY, "comment:7")


def test_requested_op_carries_the_comment_in_its_id():
    d = dep(tier=Tier.SHARED)
    req = Issued(Delete(d.key), 7, "jlee", NOW, "u")
    op = requested_op(req, d)
    assert op.trigger is Trigger.REQUEST and op.delete is not None
    assert op.request_id == request_id(d.key, Verb.DELETE, "comment:7")


def test_recheck_repeats_the_rules_against_a_fresh_read():
    d = dep(tier=Tier.SHARED)
    proof = check_delete(d, automatic=False)
    assert isinstance(proof, SafeDelete)
    cfg = parse_config({"org": "acme"}).deployments
    assert recheck(proof, d.sighting, cfg, automatic=False) is None
    assert "already gone" in recheck(proof, None, cfg, automatic=False)
    redeployed = replace(d.sighting, last_deployed=NOW)
    assert "deployed again" in recheck(proof, redeployed, cfg, automatic=False)
    protected = replace(d.sighting, protected=True)
    assert "never deletes production" in recheck(proof, protected, cfg, automatic=False)
    running = replace(d.sighting, in_progress=True)
    assert recheck(proof, running, cfg, automatic=False) == RUNNING_NOW
    prod = replace(d.sighting, stage="prod")
    assert recheck(proof, prod, cfg, automatic=False)


# --- notices come from the bot's own comments


def test_only_bot_comments_count_as_notices_and_garbage_is_ignored():
    d = dep()
    marker = notice_marker(d.key, Verb.REDEPLOY)
    comments = (
        bot_comment(f"text\n\n{marker}", 10, id=1),
        bot_comment(marker, 11, id=2, author="jlee"),
        bot_comment("<!-- vulgard-notice {not json} -->", 3, id=3),
        bot_comment('<!-- vulgard-notice {"key": "x", "verb": "explode"} -->', 3, id=4),
    )
    found = notices_from(comments)
    assert found == [Notice(d.key, Verb.REDEPLOY, NOW - timedelta(days=10))]


# --- automatic ops


def reconciled(d, notices=(), decisions=None, vulnerable=False, now=NOW, cfg=CFG):
    return reconcile([d], decisions or Decisions(), list(notices), cfg, vulnerable, now)


def notice_for(d, days_ago, verb=Verb.REDEPLOY):
    return Notice(d.key, verb, NOW - timedelta(days=days_ago))


def test_a_new_qualifying_stack_is_scheduled_and_must_be_announced():
    d = dep()
    (scheduled,) = reconciled(d).scheduled
    assert scheduled.fresh and scheduled.due == date(2026, 11, 8)
    assert scheduled.trigger is Trigger.STALE


def test_the_notice_period_counts_from_the_bots_comment_and_ids_are_stable():
    d = dep()
    inside = reconciled(d, [notice_for(d, 3)])
    assert not inside.ops and not inside.scheduled[0].fresh
    assert inside.scheduled[0].due == date(2026, 11, 5)
    over = reconciled(d, [notice_for(d, 8)])
    later = reconciled(d, [notice_for(d, 8)], now=NOW + timedelta(days=1))
    assert over.ops[0].request_id == later.ops[0].request_id
    assert over.ops[0].verb is Verb.REDEPLOY and over.ops[0].trigger is Trigger.STALE


def test_a_notice_posted_today_never_runs_today():
    cfg = replace(CFG, auto=replace(CFG.auto, notice_days=0))
    d = dep()
    assert not reconciled(d, [Notice(d.key, Verb.REDEPLOY, NOW)], cfg=cfg).ops


def test_an_old_notice_cannot_fire_an_op_after_a_redeploy_or_a_keep():
    d = dep(days=100)
    redeployed_since = replace(d.sighting, last_deployed=NOW - timedelta(days=5))
    d2 = replace(d, sighting=redeployed_since)
    assert not reconciled(d2, [notice_for(d, 20)], vulnerable=True).ops  # not even stale now
    again = replace(d, sighting=replace(d.sighting, last_deployed=NOW - timedelta(days=95)))
    # last deployed 95 days ago: a notice older than that deploy is void, a newer one counts
    assert reconciled(again, [notice_for(d, 20)]).ops
    assert not reconciled(again, [notice_for(d, 100)]).ops
    keep_then_expired = Decisions(last_keep={d.key: NOW - timedelta(days=15)})
    assert not reconciled(d, [notice_for(d, 20)], keep_then_expired).ops
    assert reconciled(d, [notice_for(d, 20)], keep_then_expired).scheduled[0].fresh


def test_the_current_trigger_is_reported_not_the_one_from_the_notice():
    d = dep(days=100)
    over = reconciled(d, [notice_for(d, 8)], vulnerable=True)
    assert over.ops[0].trigger is Trigger.STALE
    fresh = dep(days=5)
    (scheduled,) = reconciled(fresh, vulnerable=True).scheduled
    assert scheduled.trigger is Trigger.VULNERABLE


def test_a_keep_or_a_recent_cancel_stops_automatic_ops_whatever_qualified_them():
    d = dep()
    keep = Issued(Keep(d.key, date(2026, 12, 1), "demo"), 1, "jlee", NOW, "u")
    assert not reconciled(d, decisions=Decisions(keeps={d.key: keep})).scheduled
    young = dep(days=5)
    kept_young = Decisions(keeps={young.key: keep})
    assert not reconciled(young, decisions=kept_young, vulnerable=True).scheduled
    recent = {d.key: Issued(Cancel(d.key), 1, "jlee", NOW - timedelta(days=1), "u")}
    assert not reconciled(d, decisions=Decisions(cancels=recent)).scheduled
    old = {d.key: Issued(Cancel(d.key), 1, "jlee", NOW - timedelta(days=200), "u")}
    assert reconciled(d, decisions=Decisions(cancels=old)).scheduled


def test_only_opted_in_personal_deployments_qualify():
    assert not reconciled(dep(repo="web")).scheduled
    assert not reconciled(dep(tier=Tier.SHARED)).scheduled
    assert not reconciled(dep(days=5)).scheduled
    assert reconciled(dep(days=5), vulnerable=True).scheduled


def test_auto_delete_turns_ops_into_deletes():
    cfg = replace(CFG, auto=replace(CFG.auto, delete=True))
    d = dep()
    (op,) = reconciled(d, [notice_for(d, 20, Verb.DELETE)], cfg=cfg).ops
    assert op.verb is Verb.DELETE and op.delete is not None
    wrong_verb = reconciled(d, [notice_for(d, 20, Verb.REDEPLOY)], cfg=cfg)
    assert not wrong_verb.ops and wrong_verb.scheduled[0].fresh


# --- execution


class Gone:
    """An executor whose target no longer exists, as if someone deleted it by hand."""

    def __init__(self):
        self.started = []

    def observe(self, native):
        return None

    def find(self, op):
        return None

    def delete(self, proof, request_id):
        self.started.append(request_id)
        return "url"


class Broken(Gone):
    def find(self, op):
        raise OpFailed("DELETE_FAILED: bucket not empty")


def shared_delete():
    d = dep(tier=Tier.SHARED)
    return d, requested_op(Issued(Delete(d.key), 7, "jlee", NOW, "u"), d)


def test_execute_is_idempotent():
    d, op = shared_delete()
    executor = SimpleNamespace(
        observe=lambda native: d.sighting,
        find=lambda o: None,
        delete=lambda proof, rid: f"https://example.test/{rid}",
    )
    assert execute(op, executor, PLAIN).outcome is Outcome.STARTED
    executor.find = lambda o: "https://example.test/existing"
    result = execute(op, executor, PLAIN)
    assert result.outcome is Outcome.RUNNING and result.detail == "https://example.test/existing"


def test_a_target_that_is_already_gone_is_skipped_not_reported_as_running():
    _, op = shared_delete()
    gone = Gone()
    result = execute(op, gone, CFG)
    assert result.outcome is Outcome.SKIPPED and "already gone" in result.detail
    assert gone.started == []


def test_failures_reach_execute_as_op_failed_and_blocked_ops_never_start():
    _, op = shared_delete()
    assert execute(op, Broken(), CFG).outcome is Outcome.FAILED
    prod = plan_op(dep(tier=Tier.PRODUCTION), Verb.DELETE, Trigger.REQUEST, "r")
    gone = Gone()
    assert execute(prod, gone, CFG).outcome is Outcome.SKIPPED and gone.started == []


# --- the live executor


class RecordingGitHub:
    def __init__(self, fail=False):
        self.fail = fail
        self.dispatched = []

    def get_repo(self, org, repo):
        return {"default_branch": "trunk"}

    def dispatch_workflow(self, org, repo, workflow, ref, inputs):
        if self.fail:
            raise GitHubError(403, "Resource not accessible by integration", "/dispatches")
        self.dispatched.append((repo, workflow, ref, inputs))

    def find_workflow_run(self, org, repo, workflow, marker):
        return None


def live(gh):
    config = parse_config({"org": "acme", "deployments": {"workflows": {"api": "deploy.yml"}}})
    return LiveExecutor(gh, config, aws=None, vercel=None)  # type: ignore[arg-type]


def test_workflow_inputs_name_the_framework_stage_and_request():
    d = dep(SstStage("1", "us-east-1", "state", "inv", "jlee"), Framework.SST)
    inputs = workflow_inputs(d, Verb.DELETE, "vg-9")
    assert inputs == {
        "action": "delete",
        "framework": "sst",
        "app": "api",
        "stage": "jlee",
        "stack": "",
        "request_id": "vg-9",
    }


def test_sst_deletes_and_serverless_redeploys_dispatch_the_repos_workflow():
    gh = RecordingGitHub()
    executor = live(gh)
    sst = dep(SstStage("1", "us-east-1", "state", "inv", "jlee"), Framework.SST, tier=Tier.SHARED)
    proof = check_delete(sst, automatic=False)
    url = executor.delete(proof, "vg-1")
    assert url.endswith("/actions/workflows/deploy.yml")
    executor.redeploy(dep(), "vg-2")
    assert [(r, w, ref, i["action"]) for r, w, ref, i in gh.dispatched] == [
        ("api", "deploy.yml", "trunk", "delete"),
        ("api", "deploy.yml", "trunk", "redeploy"),
    ]


def test_infrastructure_failures_become_op_failed_at_the_executor():
    with pytest.raises(OpFailed, match="Resource not accessible"):
        live(RecordingGitHub(fail=True)).redeploy(dep(), "vg-1")
    with pytest.raises(OpFailed, match="VERCEL_TOKEN"):
        live(RecordingGitHub()).redeploy(dep(VercelProject("t", "p"), Framework.VERCEL), "vg-1")


# --- rollout


def lifecycle_config(**aws):
    deployments = {"aws": {"deploy_role_arn": "arn:aws:iam::1:role/GithubCI", **aws}}
    return parse_config({"org": "acme", "deployments": deployments})


def test_lifecycle_rollout_needs_a_role_and_a_workflow_framework():
    repo = {"name": "inventory", "default_branch": "main"}
    gh = FixtureGitHub({"repos": [repo]})
    bare = parse_config({"org": "acme"})
    plan = plan_lifecycle_rollout(gh, bare, repo, frozenset({Framework.SST}))
    assert plan.skipped_reason and "deploy_role_arn" in plan.skipped_reason
    config = lifecycle_config()
    assert plan_lifecycle_rollout(gh, config, repo, frozenset({Framework.VERCEL})).skipped_reason
    plan = plan_lifecycle_rollout(gh, config, repo, frozenset({Framework.SST}))
    (content,) = plan.files.values()
    assert "role: arn:aws:iam::1:role/GithubCI" in content
    assert "[${{ inputs.request_id }}]" in content
    assert plan.branch == "vulgard/lifecycle" and not plan.enable_security


def test_lifecycle_rollout_opens_its_own_pr_without_touching_security_settings():
    repo = {"name": "inventory", "default_branch": "main"}
    gh = FixtureGitHub({"repos": [repo]})
    config = lifecycle_config()
    plan = plan_lifecycle_rollout(gh, config, repo, frozenset({Framework.SST}))
    assert apply_rollout(gh, config, plan).endswith("/pull/1")
    ops = [op for op, _ in gh.writes]
    assert "create_pr" in ops and "enable_security_features" not in ops
    title = next(args[1] for op, args in gh.writes if op == "create_pr")
    assert title == "ci: let vulgard redeploy or remove stale stacks"


# --- the whole run, day by day


def test_requests_run_once_and_a_forged_notice_changes_nothing():
    clients = fixture_clients(EXAMPLES / "demo-org.json")
    config = load_config(EXAMPLES / "vulgard.yml")
    gh, executor = clients.github, clients.executor()
    start = datetime.now(UTC)

    def day(n):
        when = start + timedelta(days=n, hours=1)
        gh.now = when
        ctx = NagContext(clients, config, None, True, True, False, when, clients.linear)
        return run_stale(ctx)

    day(0)
    payments = gh.data["issues"]["payments-api#vulgard-stale"]
    thread = gh.data["comments"][f"payments-api#{payments['number']}"]
    assert [c["user"]["login"] for c in thread] == ["vulgard[bot]"]
    assert "vulgard-notice" in thread[0]["body"] and '"notices"' not in payments["body"]

    storefront = gh.data["issues"]["web-storefront#vulgard-stale"]["number"]
    gh.data["comments"].setdefault(f"web-storefront#{storefront}", []).append(
        {
            "id": 7,
            "user": {"login": "jlee"},
            "created_at": (start + timedelta(days=1)).isoformat(),
            "html_url": "u7",
            "body": "/vulgard delete storefront-experiments",
        }
    )
    key = "cfn:111122223333/us-east-1/payments-api-jlee"
    forged = f'<!-- vulgard-notice {{"key": "{key}", "verb": "redeploy"}} -->'
    thread.append(
        {
            "id": 8,
            "user": {"login": "jlee"},
            "created_at": (start - timedelta(days=30)).isoformat(),
            "html_url": "u8",
            "body": forged,
        }
    )
    day(1)
    day(3)
    assert [(v.value, d.name) for v, d, _ in executor.started] == [
        ("delete", "storefront-experiments")
    ]
    day(8)
    day(9)
    started = [(v.value, d.name) for v, d, _ in executor.started]
    assert started == [("delete", "storefront-experiments"), ("redeploy", "payments-api-jlee")]


def test_nag_execute_dry_run_lists_due_ops(capsys):
    fixtures = ["--fixtures", str(EXAMPLES / "demo-org.json")]
    config = ["--config", str(EXAMPLES / "vulgard.yml")]
    assert main([*fixtures, *config, "nag", "--topic", "stale", "--execute"]) == 0
    assert "automatic op(s) announced" in capsys.readouterr().out
