from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from vulgard import stale, stale_plan, stale_render, topics
from vulgard.baseline import Decisions, Delete, Keep, Redeploy, fold, pending_requests
from vulgard.cli import main
from vulgard.config import LinearOverride, LinearTarget, parse_config
from vulgard.estate import (
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    ScanError,
    Sighting,
    Tier,
)
from vulgard.fixtures import FakeLinear, FixtureGitHub
from vulgard.github import GitHubError
from vulgard.lifecycle import SANDBOX, Notice, Verb
from vulgard.linear import sync_linear
from vulgard.nag import track
from vulgard.plan import ActionKind, IssueComment, IssueOp, TrackedIssue
from vulgard.policy import SlaStatus
from vulgard.repos import RepoActivity

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


def dep(
    name="api-dev",
    repo="api",
    days=40,
    tier=Tier.SHARED,
    person=None,
    protected=False,
    framework=Framework.SERVERLESS,
):
    s = Sighting(
        framework,
        CfnStack("1", "us-east-1", name, "id"),
        "api",
        "dev",
        NOW - timedelta(days=days),
        protected=protected,
    )
    return Deployment(s, repo, Attribution.MANIFEST if repo else Attribution.NONE, tier, person)


def comment(body, author="jlee", hours=1, id=1):
    return IssueComment(id, author, body, NOW - timedelta(hours=hours), f"url{id}")


def evaluate(
    deployments,
    activity=(),
    decisions=None,
    tracked=("api", "infra"),
    cfg=None,
    notices=(),
    vulnerable=(),
):
    by_repo = decisions or {}
    return stale.evaluate(
        cfg or config(),
        list(deployments),
        list(activity),
        set(tracked),
        NOW,
        lambda repo, found: by_repo.get(repo, Decisions()),
        lambda repo: list(notices),
        frozenset(vulnerable),
    )


def idle(repo="api", days=1):
    return RepoActivity(repo, NOW - timedelta(days=days))


def fold_all(*bodies, author="jlee", deployments=None):
    comments = tuple(comment(b, author, id=i) for i, b in enumerate(bodies, 1))
    return fold(comments, deployments or [dep()], lambda _: True, NOW, 180)


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


def test_keeps_and_actives_expire_but_the_last_keep_is_remembered():
    d = dep()
    comments = (
        comment("/vulgard keep api-dev until 2026-11-10: demo", hours=24 * 20, id=1),
        comment("/vulgard active until 2026-11-10: stable", hours=24 * 20, id=2),
    )
    got = fold(comments, [d], lambda _: True, NOW, 180)
    assert got.keeps and got.active
    later = fold(comments, [d], lambda _: True, NOW + timedelta(days=10), 180)
    assert not later.keeps and later.active is None
    assert later.last_keep[d.key] == NOW - timedelta(hours=24 * 20)


def test_requests_are_done_when_the_world_shows_it():
    fresh = dep(days=0)
    got = fold_all("/vulgard redeploy api-dev", deployments=[fresh])
    assert pending_requests(got, [fresh]) == []
    stale_one = dep()
    got = fold_all("/vulgard delete api-dev", deployments=[stale_one])
    assert [d.name for _, d in pending_requests(got, [stale_one])] == ["api-dev"]
    assert isinstance(got.requests[stale_one.key].command, Delete)
    assert pending_requests(got, []) == []


# --- evaluation


def test_staleness_is_an_sla_from_last_deployed():
    reports = evaluate([dep(days=10), dep("api-qa", days=40), dep("api-old", days=60)])
    findings = {f.name: f for f in reports["api"].findings}
    assert set(findings) == {"api-qa", "api-old"}
    assert findings["api-qa"].sla.status is SlaStatus.DUE_SOON
    assert findings["api-qa"].sla.days_left == 4
    assert findings["api-old"].sla.status is SlaStatus.OVERDUE
    assert [f.name for f in reports["api"].findings] == ["api-old", "api-qa"]


def test_unattributed_and_untracked_deployments_land_in_the_unattributed_repo():
    orphan, gone = dep("orphan", repo=None), dep("gone", repo="archived")
    infra = evaluate([orphan, gone])["infra"]
    assert {d.name for d in infra.deployments} == {"orphan", "gone"}
    assert "no repo found" in infra.notes[orphan.key]
    assert "doesn't track" in infra.notes[gone.key]


def test_keep_moves_a_finding_out_and_active_silences_inactivity():
    d = dep()
    keep = fold_all("/vulgard keep api-dev until 2026-12-01: demo next week", deployments=[d])
    report = evaluate([d], [idle(days=200)], {"api": keep})["api"]
    assert [f.name for f, _ in report.kept] == ["api-dev"]
    assert [f.name for f in report.findings] == ["repo"]
    marked = fold_all("/vulgard active until 2027-01-01: stable library", deployments=[])
    report = evaluate([], [idle(days=200)], {"api": marked})["api"]
    assert not report.findings and not report.needs_tracking


def test_repo_with_no_commits_is_anchored_to_its_creation():
    created = RepoActivity("api", None, NOW - timedelta(days=95))
    finding = evaluate([], [created])["api"].repo_finding
    assert finding.sla.flagged_at == NOW - timedelta(days=5)
    assert finding.sla.deadline == finding.sla.flagged_at + timedelta(days=14)


def test_a_keep_stops_automatic_ops_even_for_a_fresh_stack_in_a_vulnerable_repo():
    cfg = config(people={"jlee": "@jlee"}, auto={"repos": ["api"]})
    mine = dep("api-jlee", days=5, tier=Tier.PERSONAL, person="@jlee")
    assert evaluate([mine], cfg=cfg, vulnerable={"api"})["api"].lifecycle.scheduled
    keep = fold_all("/vulgard keep api-jlee until 2026-12-01: demo", deployments=[mine])
    kept = evaluate([mine], decisions={"api": keep}, cfg=cfg, vulnerable={"api"})["api"]
    assert not kept.lifecycle.scheduled and not kept.lifecycle.ops


# --- planning


def test_plan_creates_then_stays_quiet_then_announces_news():
    cfg = config()
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    first = stale_plan.plan_repo(report, cfg, None, NOW)
    assert first.op is IssueOp.CREATE and first.digest
    body = first.render(first.state)
    assert "`/vulgard redeploy api-dev`" in body and "`/vulgard delete api-dev`" in body
    issue = TrackedIssue(1, True, body, "u")
    again = stale_plan.plan_repo(report, cfg, issue, NOW)
    assert again.op is IssueOp.UPDATE and not again.comments and again.digest is None
    more = evaluate([dep(days=40), dep("api-qa", days=35)], cfg=cfg)["api"]
    news = stale_plan.plan_repo(more, cfg, issue, NOW)
    assert "1 item(s) need a baseline" in news.comments[0] and "api-qa" in news.comments[0]


def test_production_is_never_offered_for_deletion_and_personal_pings_the_person():
    cfg = config()
    prod = dep("api-prod", days=40, tier=Tier.PRODUCTION)
    mine = dep("api-jlee", days=40, tier=Tier.PERSONAL, person="@jlee")
    report = replace(evaluate([prod, mine], cfg=cfg)["api"], owners=["@acme/api"])
    plan = stale_plan.plan_repo(report, cfg, None, NOW)
    body = plan.render(plan.state)
    assert "`/vulgard delete api-prod`" not in body and "`/vulgard delete api-jlee`" in body
    assert plan.dm == ("@jlee",)


def test_escalates_once_when_well_overdue():
    cfg = config()
    report = evaluate([dep("api-prod", days=60, tier=Tier.PRODUCTION)], cfg=cfg)["api"]
    first = stale_plan.plan_repo(report, cfg, None, NOW)
    assert first.escalation is not None and "@acme/security" in first.comments[-1]
    issue = TrackedIssue(1, True, first.render(first.state), "u")
    assert stale_plan.plan_repo(report, cfg, issue, NOW).escalation is None


def test_escalation_waits_for_its_weekday():
    cfg = config()
    report = evaluate([dep("api-prod", days=60, tier=Tier.PRODUCTION)], cfg=cfg)["api"]
    cfg.escalation.weekday = (NOW + timedelta(days=1)).strftime("%A").lower()
    assert stale_plan.plan_repo(report, cfg, None, NOW).escalation is None
    cfg.escalation.weekday = NOW.strftime("%A").lower()
    assert stale_plan.plan_repo(report, cfg, None, NOW).escalation is not None


def test_closes_when_baselined_and_remembers_it_for_the_leaderboard():
    cfg = config()
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    first = stale_plan.plan_repo(report, cfg, None, NOW)
    issue = TrackedIssue(1, True, first.render(first.state), "u")
    clean = evaluate([dep(days=0)], cfg=cfg)["api"]
    closing = stale_plan.plan_repo(clean, cfg, issue, NOW)
    assert closing.op is IssueOp.CLOSE and closing.comments == [stale_plan.CLOSED]
    assert closing.state.memory.baselined == ((dep().key, "2026-11-01"),)


def test_close_persists_memory_in_the_body():
    cfg = config()
    gh = FixtureGitHub({"repos": [{"name": "api"}]})
    first = stale_plan.plan_repo(evaluate([dep(days=40)], cfg=cfg)["api"], cfg, None, NOW)
    track(gh, None, cfg, [first], {"api": None}, apply=True)
    raw = gh.find_issue("acme", "api", cfg.deployments.label)
    issue = TrackedIssue(raw["number"], True, raw["body"], raw["html_url"])
    closing = stale_plan.plan_repo(evaluate([dep(days=0)], cfg=cfg)["api"], cfg, issue, NOW)
    track(gh, None, cfg, [closing], {"api": issue}, apply=True)
    assert raw["state"] == "closed" and '"baselined": [["cfn:' in raw["body"]


def test_rejected_commands_alone_do_not_keep_the_issue_open():
    bad = fold_all("/vulgard frobnicate", deployments=[dep(days=0)])
    report = evaluate([dep(days=0)], decisions={"api": bad})["api"]
    assert report.rejected and not report.needs_tracking


def test_topic_linear_override_replaces_routed_labels_and_project():
    cfg = config(linear={"labels": ["stale"], "project": "Baselines"})
    target = LinearTarget("SEC", ("vulgard",), None, None)
    assert cfg.deployments.linear.apply(target).labels == ("stale",)
    assert LinearOverride().apply(target) == target
    plan = stale_plan.plan_repo(evaluate([dep(days=40)], cfg=cfg)["api"], cfg, None, NOW)
    linear = FakeLinear()
    result = sync_linear(linear, cfg, plan, apply=True)
    fields = linear.issues[result.ref.id]["fields"]
    assert fields["projectId"] == "project:Baselines"
    assert fields["labelIds"] == ["label:stale"]


def test_keep_is_shown_with_who_and_why():
    d = dep(days=40)
    keep = fold_all("/vulgard keep api-dev until 2026-12-01: demo next week", deployments=[d])
    report = evaluate([d], decisions={"api": keep})["api"]
    assert not report.findings and isinstance(report.kept[0][1].command, Keep)
    assert report.kept[0][1].command.until == date(2026, 12, 1)


# --- notices and automatic ops in the issue


def auto_config():
    return config(people={"jlee": "@jlee"}, auto={"repos": ["api"]})


def test_the_notice_comment_carries_hidden_markers_the_next_run_reads_back():
    cfg = auto_config()
    mine = dep("api-jlee", days=100, tier=Tier.PERSONAL, person="@jlee")
    plan = stale_plan.plan_repo(evaluate([mine], cfg=cfg)["api"], cfg, None, NOW)
    notice = next(c for c in plan.comments if "automatically" in c)
    assert f'"key": "{mine.key}"' in notice and "vulgard-notice" in notice
    assert "notices" not in plan.render(plan.state)  # nothing about notices lives in the body


def test_an_automatic_op_that_cannot_run_is_not_shown_as_happening():
    cfg = auto_config()
    native = CfnStack("1", "us-east-1", "amplify-app-jlee-sandbox-1a", "id")
    s = Sighting(Framework.AMPLIFY, native, "app", "sandbox", NOW - timedelta(days=100))
    sandbox = Deployment(s, "api", Attribution.MANIFEST, Tier.PERSONAL, "@jlee")
    notice = Notice(sandbox.key, Verb.REDEPLOY, NOW - timedelta(days=10))
    report = evaluate([sandbox], cfg=cfg, notices=[notice])["api"]
    assert report.lifecycle.ops[0].blocked == SANDBOX
    plan = stale_plan.plan_repo(report, cfg, None, NOW)
    body = plan.render(plan.state)
    assert "can't be redeployed automatically" in body and "is due to be" not in body


def test_seen_names_are_bounded_and_present_ones_always_kept():
    cfg = config()
    memory = stale.StaleMemory(seen=tuple(f"gone-{i:03}" for i in range(250)))
    report = evaluate([dep(days=40)], cfg=cfg)["api"]
    seen = stale_plan._seen(memory, report)
    assert "api-dev" in seen and len(seen) == 1 + stale_plan.MAX_GONE_NAMES


def test_huge_reports_stay_under_the_issue_body_limit():
    cfg = config()
    many = [dep(f"stack-{i:03}", repo=None, days=60) for i in range(300)]
    plan = stale_plan.plan_repo(evaluate(many, cfg=cfg)["infra"], cfg, None, NOW)
    assert len(plan.render(plan.state)) < 60_000
    assert "…and" in plan.render(plan.state)


# --- engine behavior around the topic


class FlakyGitHub(FixtureGitHub):
    def create_issue(self, org, repo, *args, **kwargs):
        if repo == "api":
            raise GitHubError(500, "boom", "/issues")
        return super().create_issue(org, repo, *args, **kwargs)


def test_one_repos_github_failure_does_not_discard_the_others():
    cfg = config()
    both = [dep(days=40), dep("web-dev", repo="web", days=40)]
    reports = evaluate(both, tracked=("api", "web", "infra"), cfg=cfg)
    plans = [stale_plan.plan_repo(reports[repo], cfg, None, NOW) for repo in ("api", "web")]
    gh = FlakyGitHub({"repos": [{"name": "api"}, {"name": "web"}]})
    runs = track(gh, None, cfg, plans, {}, apply=True)
    assert any(a.kind is ActionKind.GITHUB_ERROR for a in runs[0].actions)
    assert runs[0].issue_url is None and runs[1].issue_url and runs[1].issue_number


def test_leaderboard_blocks_rank_teams_by_overdue_baselines():
    cfg = config()
    report = evaluate([dep(days=60)], cfg=cfg)["api"]
    reports = {
        "api": replace(report, owners=["@acme/api"]),
        "web": replace(report, repo="web", owners=["@acme/web"]),
    }
    blocks = stale_render.leaderboard_blocks(reports, [], NOW)
    assert blocks[0]["type"] == "header"
    assert [f["text"] for f in blocks[1]["fields"]] == ["*Need a baseline*\n2", "*Overdue*\n2"]
    ranking = blocks[2]["fields"][0]["text"]
    assert "Most overdue baselines" in ranking and "@acme/api: 1" in ranking


# --- CLI


def test_nag_tracks_stale_deployments_from_fixtures(capsys):
    assert main([*FIXTURE_ARGS, "nag", "--topic", "stale"]) == 0
    out = capsys.readouterr().out
    assert "web-storefront: create" in out and "payments-api: create" in out


def test_report_only_writes_the_summary_and_nothing_else(tmp_path, capsys):
    cfg = tmp_path / "vulgard.yml"
    text = (EXAMPLES / "vulgard.yml").read_text()
    cfg.write_text(text.replace("deployments:\n", "deployments:\n  report_only: true\n", 1))
    summary = tmp_path / "summary.md"
    args = ["--fixtures", str(EXAMPLES / "demo-org.json"), "--config", str(cfg)]
    assert main([*args, "nag", "--topic", "stale", "--slack", "--summary-file", str(summary)]) == 0
    out = capsys.readouterr().out
    assert "report-only: 5 repo(s)" in out and "create" not in out and "slack" not in out
    assert "web-storefront" in summary.read_text()


def test_stale_failure_does_not_stop_the_vulns_run(monkeypatch, capsys):
    def boom(ctx):
        raise ScanError("AWS scan failed: throttled")

    monkeypatch.setattr(topics, "_stale_pass", boom)
    assert main([*FIXTURE_ARGS, "nag"]) == 1
    captured = capsys.readouterr()
    assert "skipped stale deployments" in captured.err
    assert "create" in captured.out
