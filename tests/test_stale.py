from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from vulgard import stale
from vulgard.baseline import Decisions, Delete, Keep, Redeploy, fold, is_satisfied
from vulgard.cli import main
from vulgard.config import LinearOverride, LinearTarget, parse_config
from vulgard.estate import (
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    RepoActivity,
    Sighting,
    Tier,
)
from vulgard.fixtures import FakeLinear, FixtureGitHub
from vulgard.linear import LinearError, sync_linear
from vulgard.nag import track
from vulgard.plan import IssueComment, IssueOp, TrackedIssue
from vulgard.policy import SlaStatus

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
FIXTURE_ARGS = [
    "--fixtures",
    str(EXAMPLES / "demo-org.json"),
    "--config",
    str(EXAMPLES / "vulgard.yml"),
]


def config(**deployments):
    return parse_config(
        {
            "org": "acme",
            "escalation": {"mentions": ["@acme/security"]},
            "linear": {"default_team": "SEC"},
            "deployments": {"enabled": True, "unattributed_repo": "infra", **deployments},
        }
    )


def dep(name="api-dev", repo="api", days=40, tier=Tier.SHARED, person=None, protected=False):
    s = Sighting(
        Framework.SERVERLESS,
        CfnStack("1", "us-east-1", name, "id"),
        "api",
        "dev",
        NOW - timedelta(days=days),
        protected=protected,
    )
    return Deployment(s, repo, Attribution.MANIFEST if repo else Attribution.NONE, tier, person)


def comment(body, author="jlee", hours=1, id=1):
    return IssueComment(id, author, body, NOW - timedelta(hours=hours), f"url{id}")


def decide_with(decisions):
    return lambda repo, found: decisions.get(repo, Decisions())


def evaluate(deployments, activity=(), decisions=None, tracked=("api", "infra"), cfg=None):
    return stale.evaluate(
        cfg or config(),
        list(deployments),
        list(activity),
        decide_with(decisions or {}),
        set(tracked),
        NOW,
    )


def active(repo="api", days=1):
    return RepoActivity(repo, NOW - timedelta(days=days))


# --- baselines


def test_latest_command_per_target_wins_and_cancel_clears():
    d = dep()
    comments = (
        comment("/vulgard keep api-dev until 2026-12-01: demo", hours=3, id=1),
        comment("/vulgard redeploy api-dev", hours=2, id=2),
    )
    got = fold(comments, [d], lambda _: True, NOW, 180)
    assert not got.keeps and isinstance(got.requests[d.key].command, Redeploy)
    got = fold((*comments, comment("/vulgard cancel api-dev", id=3)), [d], lambda _: True, NOW, 180)
    assert not got.keeps and not got.requests and d.key in got.cancels


def test_commands_are_rejected_for_bad_input_permissions_and_production():
    prod = dep("api-prod", tier=Tier.PRODUCTION)
    comments = (
        comment("/vulgard delete api-prod", id=1),
        comment("/vulgard keep api-dev until 2020-01-01: old", id=2),
        comment("/vulgard keep api-dev until 2028-01-01: too long", id=3),
        comment("/vulgard redeploy nope", id=4),
        comment("/vulgard redeploy api-dev", author="intern", id=5),
        comment("/vulgard frobnicate", id=6),
    )
    got = fold(comments, [dep(), prod], lambda user: user != "intern", NOW, 180)
    reasons = [r.reason for r in got.rejected]
    assert len(reasons) == 6 and not got.requests and not got.keeps
    assert "never deletes production" in reasons[0]
    assert "in the past" in reasons[1] and "at most 180 days" in reasons[2]
    assert "no deployment named `nope`" in reasons[3]
    assert "write access" in reasons[4] and "unknown command" in reasons[5]


def test_bot_comments_and_inline_mentions_are_not_commands():
    comments = (
        comment("/vulgard redeploy api-dev", author="vulgard[bot]", id=1),
        comment("try `/vulgard redeploy api-dev` here", id=2),
    )
    assert fold(comments, [dep()], lambda _: True, NOW, 180) == Decisions()


def test_commands_for_deployments_that_are_gone_are_moot_not_rejected():
    comments = (comment("/vulgard delete old-stack"),)
    got = fold(comments, [dep()], lambda _: True, NOW, 180, frozenset({"old-stack"}))
    assert got == Decisions()


def test_keeps_and_actives_expire():
    comments = (
        comment("/vulgard keep api-dev until 2026-11-10: demo", hours=24 * 20, id=1),
        comment("/vulgard active until 2026-11-10: stable", hours=24 * 20, id=2),
    )
    got = fold(comments, [dep()], lambda _: True, NOW, 180)
    assert got.keeps and got.active
    later = fold(comments, [dep()], lambda _: True, NOW + timedelta(days=10), 180)
    assert not later.keeps and later.active is None


def test_requests_are_satisfied_by_the_world():
    d = dep(days=0)
    got = fold((comment("/vulgard redeploy api-dev", hours=2),), [d], lambda _: True, NOW, 180)
    assert is_satisfied(got.requests[d.key], d)
    got = fold((comment("/vulgard delete api-dev"),), [dep()], lambda _: True, NOW, 180)
    assert isinstance(got.requests[dep().key].command, Delete)
    assert is_satisfied(got.requests[dep().key], None)


# --- evaluation


def test_staleness_is_an_sla_from_last_deployed():
    reports = evaluate([dep(days=10), dep("api-qa", days=40), dep("api-old", days=60)])
    findings = {f.name: f for f in reports["api"].findings}
    assert set(findings) == {"api-qa", "api-old"}
    assert findings["api-qa"].status is SlaStatus.DUE_SOON
    assert findings["api-qa"].deadline_days == 4
    assert findings["api-old"].status is SlaStatus.OVERDUE


def test_unattributed_and_untracked_deployments_land_in_the_unattributed_repo():
    reports = evaluate([dep("orphan", repo=None), dep("gone", repo="archived")])
    infra = reports["infra"]
    assert {d.name for d in infra.deployments} == {"orphan", "gone"}
    assert "no repo found" in infra.notes[dep("orphan", repo=None).key]
    assert "doesn't track" in infra.notes[dep("gone", repo="archived").key]


def test_keep_moves_a_finding_out_and_active_silences_inactivity():
    d = dep()
    keep = fold(
        (comment("/vulgard keep api-dev until 2026-12-01: demo next week"),),
        [d],
        lambda _: True,
        NOW,
        180,
    )
    report = evaluate([d], [active(days=200)], {"api": keep})["api"]
    assert [f.name for f in report.kept[0:1]] == ["api-dev"]
    assert [f.name for f in report.findings] == ["repo"]
    marked = fold(
        (comment("/vulgard active until 2027-01-01: stable library"),), [], lambda _: True, NOW, 180
    )
    report = evaluate([], [active(days=200)], {"api": marked})["api"]
    assert not report.findings and not report.needs_tracking


def test_repo_with_no_commits_is_anchored_to_its_creation():
    created = RepoActivity("api", None, NOW - timedelta(days=95))
    (finding,) = evaluate([], [created])["api"].findings
    assert finding.flagged_at == NOW - timedelta(days=5)
    assert finding.deadline == finding.flagged_at + timedelta(days=14)


# --- planning


def test_plan_creates_then_stays_quiet_then_announces_news():
    cfg = config()
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    first = stale.plan_repo(report, cfg, None, NOW)
    assert first.op is IssueOp.CREATE and first.digest
    body = first.render(first.state)
    assert "`/vulgard redeploy api-dev`" in body and "`/vulgard delete api-dev`" in body
    issue = TrackedIssue(1, True, body, "u")
    again = stale.plan_repo(report, cfg, issue, NOW)
    assert again.op is IssueOp.UPDATE and not again.comments and again.digest is None
    more = evaluate([dep(days=40), dep("api-qa", days=35)], cfg=cfg)["api"]
    news = stale.plan_repo(more, cfg, issue, NOW)
    assert "1 item(s) need a baseline" in news.comments[0] and "api-qa" in news.comments[0]


def test_production_is_never_offered_for_deletion_and_personal_pings_the_person():
    cfg = config()
    prod = dep("api-prod", days=40, tier=Tier.PRODUCTION)
    mine = dep("api-jlee", days=40, tier=Tier.PERSONAL, person="@jlee")
    report = evaluate([prod, mine], cfg=cfg)["api"]
    report.owners = ["@acme/api"]
    plan = stale.plan_repo(report, cfg, None, NOW)
    body = plan.render(plan.state)
    assert "`/vulgard delete api-prod`" not in body and "`/vulgard delete api-jlee`" in body
    assert plan.dm == ("@jlee",)


def test_escalates_once_when_well_overdue():
    cfg = config()
    report = evaluate([dep("api-prod", days=60, tier=Tier.PRODUCTION)], cfg=cfg)["api"]
    first = stale.plan_repo(report, cfg, None, NOW)
    assert first.escalation is not None and "@acme/security" in first.comments[-1]
    issue = TrackedIssue(1, True, first.render(first.state), "u")
    assert stale.plan_repo(report, cfg, issue, NOW).escalation is None


def test_closes_when_baselined_and_remembers_it_for_the_leaderboard():
    cfg = config()
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    first = stale.plan_repo(report, cfg, None, NOW)
    issue = TrackedIssue(1, True, first.render(first.state), "u")
    clean = evaluate([dep(days=0)], cfg=cfg)["api"]
    closing = stale.plan_repo(clean, cfg, issue, NOW)
    assert closing.op is IssueOp.CLOSE and closing.comments == [stale.CLOSED]
    assert closing.state.memory.baselined == ((dep().key, "2026-11-01"),)


def test_close_persists_memory_in_the_body():
    cfg = config()
    gh = FixtureGitHub({"repos": [{"name": "api"}]})
    first = stale.plan_repo(evaluate([dep(days=40)], cfg=cfg)["api"], cfg, None, NOW)
    track(gh, None, cfg, [first], {"api": None}, apply=True)
    raw = gh.find_issue("acme", "api", cfg.deployments.label)
    issue = TrackedIssue(raw["number"], True, raw["body"], raw["html_url"])
    closing = stale.plan_repo(evaluate([dep(days=0)], cfg=cfg)["api"], cfg, issue, NOW)
    track(gh, None, cfg, [closing], {"api": issue}, apply=True)
    assert raw["state"] == "closed" and '"baselined": [["cfn:' in raw["body"]


def test_rejected_commands_alone_do_not_keep_the_issue_open():
    cfg = config()
    bad = fold((comment("/vulgard frobnicate"),), [dep(days=0)], lambda _: True, NOW, 180)
    report = evaluate([dep(days=0)], decisions={"api": bad}, cfg=cfg)["api"]
    assert report.rejected and not report.needs_tracking


def test_topic_linear_override_replaces_routed_labels_and_project():
    cfg = config(linear={"labels": ["stale"], "project": "Baselines"})
    target = LinearTarget("SEC", ("vulgard",), None, None)
    assert cfg.deployments.linear.apply(target).labels == ("stale",)
    assert LinearOverride().apply(target) == target
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    plan = stale.plan_repo(report, cfg, None, NOW)
    linear = FakeLinear()
    result = sync_linear(linear, cfg, plan, apply=True)
    fields = linear.issues[result.ref.id]["fields"]
    assert fields["projectId"] == "project:Baselines"
    assert fields["labelIds"] == ["label:stale"]


def test_keep_is_shown_with_who_and_why():
    cfg = config()
    d = dep(days=40)
    keep = fold(
        (comment("/vulgard keep api-dev until 2026-12-01: demo next week"),),
        [d],
        lambda _: True,
        NOW,
        180,
    )
    report = evaluate([d], decisions={"api": keep}, cfg=cfg)["api"]
    assert not report.findings and isinstance(report.kept[0][1].command, Keep)
    assert report.kept[0][1].command.until == date(2026, 12, 1)


# --- CLI


def test_nag_tracks_stale_deployments_from_fixtures(capsys):
    assert main([*FIXTURE_ARGS, "nag", "--topic", "stale"]) == 0
    out = capsys.readouterr().out
    assert "web-storefront: create" in out and "payments-api: create" in out


def test_stale_failure_does_not_stop_the_vulns_run(monkeypatch, capsys):
    def boom(*_, **__):
        raise LinearError("scanner exploded")

    monkeypatch.setattr(stale, "run", boom)
    assert main([*FIXTURE_ARGS, "nag"]) == 1
    captured = capsys.readouterr()
    assert "skipped stale deployments" in captured.err
    assert "create" in captured.out
