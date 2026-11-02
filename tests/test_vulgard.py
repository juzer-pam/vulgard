from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from vulgard.cli import collect, main
from vulgard.config import LinearTarget, parse_config, route
from vulgard.enforce import STATUS_CHECK_CONTEXT, plan_enforce
from vulgard.fixtures import FakeLinear, FakeSlack, FixtureGitHub, fixture_clients
from vulgard.plan import ActionKind, IssueOp, LinearRef, TrackedIssue, TrackingState
from vulgard.policy import SlaStatus, evaluate, parse_codeowners_default, summarize_closed
from vulgard.rollout import (
    DEPENDABOT_PATH,
    WORKFLOW_PATH,
    apply_rollout,
    detect_ecosystems,
    plan_rollout,
    render_caller_workflow,
    render_dependabot_config,
)
from vulgard.slack import leaderboard_message, notify_slack, send_leaderboard
from vulgard.vulns import VulnMemory, leaderboard_blocks, nag, plan_repo

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def alert(number: int, repo: str, severity: str, days_ago: int, package: str = "lodash") -> dict:
    return {
        "number": number,
        "repository": {"name": repo},
        "created_at": iso(days_ago),
        "html_url": f"https://github.com/acme/{repo}/security/dependabot/{number}",
        "dependency": {"package": {"ecosystem": "npm", "name": package}, "manifest_path": "p.json"},
        "security_advisory": {"ghsa_id": f"GHSA-{number}", "summary": "bad", "severity": severity},
        "security_vulnerability": {
            "package": {"ecosystem": "npm", "name": package},
            "first_patched_version": {"identifier": "9.9.9"},
        },
    }


def pr(number: int, repo: str, title: str, days_ago: int, ci: str | None = None) -> dict:
    return {
        "number": number,
        "title": title,
        "html_url": f"https://github.com/acme/{repo}/pull/{number}",
        "repository_url": f"https://api.github.com/repos/acme/{repo}",
        "created_at": iso(days_ago),
        "ci_state": ci,
        "mergeable": "MERGEABLE",
    }


@pytest.fixture
def config():
    return parse_config(
        {"org": "acme", "escalation": {"mentions": ["@acme/security"], "after_days_overdue": 7}}
    )


def test_sla_status_by_severity(config):
    reports = evaluate(
        config,
        [
            alert(1, "api", "critical", 8),  # 7d SLA -> 1 day overdue
            alert(2, "api", "high", 27),  # 30d SLA -> 3 days left -> due soon
            alert(3, "api", "medium", 10),  # fine
            alert(4, "other", "critical", 100),  # repo not selected
        ],
        [],
        ["api"],
        NOW,
    )
    by_num = {a.number: a for a in reports["api"].alerts}
    assert set(by_num) == {1, 2, 3}
    assert by_num[1].status == SlaStatus.OVERDUE and by_num[1].days_left == -1
    assert by_num[2].status == SlaStatus.DUE_SOON
    assert by_num[3].status == SlaStatus.OK
    assert [a.number for a in reports["api"].alerts] == [1, 2, 3]


def test_alert_linked_to_dependabot_fix_pr(config):
    reports = evaluate(
        config,
        [alert(1, "api", "high", 1, package="axios")],
        [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 1)],
        ["api"],
        NOW,
    )
    assert reports["api"].alerts[0].fix_pr.number == 9


def test_codeowners_catch_all_last_rule_wins():
    text = "* @a\n/docs/ @docs  # docs\n*  @team/x @b\n"
    assert parse_codeowners_default(text) == ["@team/x", "@b"]


def test_unknown_config_keys_rejected():
    with pytest.raises(ValueError, match="Unknown keys"):
        parse_config({"org": "acme", "escalation": {"menshuns": []}})


def repo_report(config, alerts, prs=(), now=NOW, kev=frozenset()):
    report = evaluate(config, alerts, list(prs), ["api"], now, kev=kev)["api"]
    report.owners = ["@acme/api"]
    return report


def plan(config, alerts, issue=None, prs=(), now=NOW, kev=frozenset()):
    return plan_repo(repo_report(config, alerts, prs, now, kev), config, issue, now)


def body(p, config=None, now=NOW):
    return p.render(p.state)


def issue_after(p, config, now=NOW, open=True):
    return TrackedIssue(5, open, body(p), "https://github.com/acme/api/issues/5")


def vuln_state(body):
    return TrackingState.from_body(body, VulnMemory)


def test_first_run_creates_issue_and_escalates_old_critical(config):
    p = plan(config, [alert(1, "api", "critical", 20)])
    assert [a.kind for a in p.actions()] == ["create", "escalate"]
    assert "@acme/api" in body(p, config)
    assert len(p.comments) == 1 and "@acme/security" in p.comments[0]
    state = vuln_state(body(p, config))
    assert state.memory.overdue == (1,) and state.memory.escalated == (1,)


def test_tracking_state_round_trips_through_issue_body(config):
    p = plan(config, [alert(1, "api", "critical", 20)])
    assert vuln_state(body(p, config)) == p.state
    assert vuln_state("no state here") == TrackingState(VulnMemory())


def test_no_repeat_pings_until_reminder_interval(config):
    alerts = [alert(1, "api", "critical", 20)]
    first = plan(config, alerts)

    # Next day: nothing new, so no comment and no re-escalation.
    p = plan(config, alerts, issue_after(first, config), now=NOW + timedelta(days=1))
    assert p.comments == [] and not p.pinged
    assert "comment" not in {a.kind for a in p.actions()}

    # A week later: periodic reminder.
    p = plan(config, alerts, issue_after(p, config), now=NOW + timedelta(days=7))
    assert len(p.comments) == 1 and "Reminder" in p.comments[0]
    assert p.comment_detail == "periodic reminder"


def test_newly_overdue_alert_triggers_comment(config):
    first = plan(config, [alert(1, "api", "high", 25)])
    later = NOW + timedelta(days=6)
    p = plan(config, [alert(1, "api", "high", 25)], issue_after(first, config), now=later)
    assert "comment" in {a.kind for a in p.actions()}
    assert "just went past their fix deadline" in p.comments[0]
    assert p.comment_detail.startswith("1 newly overdue")


def test_stale_dependabot_pr_alone_keeps_issue_open(config):
    p = plan(config, [], prs=[pr(3, "api", "Bump x from 1 to 2", 30)])
    assert p.op == IssueOp.CREATE
    assert "stale" in body(p, config)


def test_closed_issue_is_reopened_not_recreated(config):
    first = plan(config, [alert(1, "api", "critical", 20)])
    closed = issue_after(first, config, open=False)
    p = plan(config, [alert(2, "api", "high", 1)], closed)
    assert p.op == IssueOp.REOPEN and p.actions()[0].kind == "reopen"
    assert "Reopened" in p.comments[0] and "@acme/api" in p.comments[0] and p.pinged
    assert plan(config, [], closed).op == IssueOp.NONE


def test_engine_reopens_the_closed_issue_in_place():
    config = example_config()
    gh, kev = demo()
    gh.data["issues"]["payments-api"] = {"number": 3, "body": "old", "state": "closed"}
    nag(gh, config, collect(gh, config, kev=kev), apply=True)
    writes = [(op, args) for op, args in gh.writes if args[0] == "payments-api"]
    assert not any(op == "create_issue" for op, _ in writes)
    assert gh.data["issues"]["payments-api"]["state"] == "open"
    assert "old" not in gh.data["issues"]["payments-api"]["body"]


def test_clean_repo_closes_issue(config):
    p = plan(config, [], issue=TrackedIssue(5, True, "x", ""))
    assert [a.kind for a in p.actions()] == ["close"]
    assert p.op == IssueOp.CLOSE and "resolved" in p.comments[0]


def test_green_fix_pr_pings_owners_once(config):
    alerts = [alert(1, "api", "high", 10, package="axios")]
    pending = [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 3, ci="PENDING")]
    first = plan(config, alerts, prs=pending)
    assert "Ready to merge" not in body(first, config) and "CI running" in body(first, config)

    # CI goes green: owners get one comment naming the alert it fixes.
    green = [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 4, ci="SUCCESS")]
    p = plan(config, alerts, issue_after(first, config), prs=green)
    assert "1 newly ready" in p.comment_detail and p.pinged
    assert len(p.comments) == 1 and "@acme/api" in p.comments[0]
    assert "only waiting on a review" in p.comments[0] and "fixes high `axios`" in p.comments[0]
    assert "✅ Ready to merge (1)" in body(p, config)

    # Still green the next day: no repeat ping.
    tomorrow = NOW + timedelta(days=1)
    p = plan(config, alerts, issue_after(p, config), prs=green, now=tomorrow)
    assert p.comment_detail is None and p.comments == []


def test_conflicting_or_draft_prs_are_not_ready(config):
    conflicting = pr(9, "api", "Bump a from 1 to 2", 5, ci="SUCCESS")
    conflicting["mergeable"] = "CONFLICTING"
    draft = pr(10, "api", "Bump b from 1 to 2", 5, ci="SUCCESS")
    draft["draft"] = True
    fresh = pr(11, "api", "Bump c from 1 to 2", 0, ci="SUCCESS")
    report = evaluate(config, [], [conflicting, draft, fresh], ["api"], NOW)["api"]
    assert report.ready_prs == []


def test_known_exploited_cve_gets_short_sla_and_escalates_immediately(config):
    exploited = alert(1, "api", "medium", 4)
    exploited["security_advisory"]["cve_id"] = "CVE-2024-0001"
    p = plan(config, [exploited], kev=frozenset({"CVE-2024-0001"}))
    a = repo_report(config, [exploited], kev=frozenset({"CVE-2024-0001"})).alerts[0]
    assert a.known_exploited and a.days_left == -1 and a.status == SlaStatus.OVERDUE
    assert p.escalation is not None and p.escalation.detail == "1 alert(s)"
    assert "actively exploited" in body(p, config)

    config.kev.enabled = False
    a = repo_report(config, [exploited], kev=frozenset({"CVE-2024-0001"})).alerts[0]
    assert not a.known_exploited and a.status == SlaStatus.OK


def test_exception_hides_alert_until_it_expires():
    exception = {"package": "lodash", "repo": "api", "reason": "unused", "expires": "2026-12-01"}
    config = parse_config({"org": "acme", "exceptions": [exception]})
    p = plan(config, [alert(1, "api", "critical", 20)])
    report = repo_report(config, [alert(1, "api", "critical", 20)])
    assert report.alerts == [] and len(report.accepted) == 1
    assert p.op == IssueOp.NONE

    later = NOW + timedelta(days=31)
    report = evaluate(config, [alert(1, "api", "critical", 20)], [], ["api"], later)["api"]
    assert [a.number for a in report.alerts] == [1] and report.accepted == []


def test_exception_requires_reason_and_expiry():
    with pytest.raises(ValueError, match="reason"):
        parse_config({"org": "acme", "exceptions": [{"package": "lodash", "reason": "x"}]})
    with pytest.raises(ValueError, match="advisory"):
        parse_config({"org": "acme", "exceptions": [{"reason": "x", "expires": "2027-01-01"}]})


def example_config():
    return parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))


def demo():
    clients = fixture_clients(EXAMPLES / "demo-org.json")
    return clients.github, clients.kev()


def test_nag_apply_against_fixture():
    config = example_config()
    gh, kev = demo()
    reports = collect(gh, config, kev=kev)
    assert "sandbox-experiments" not in reports  # excluded
    assert "legacy-billing" not in reports  # archived
    assert reports["web-storefront"].owners == ["@acme/frontend", "@jlee"]  # from CODEOWNERS
    assert reports["payments-api"].owners == ["@acme/payments"]  # from config
    assert [a.package for a in reports["web-storefront"].accepted] == ["nanoid"]
    assert reports["payments-api"].known_exploited[0].package == "jsonwebtoken"

    nag(gh, config, reports, apply=True)
    ops = [(op, args[0]) for op, args in gh.writes]
    assert ("create_issue", "payments-api") in ops
    assert ("update_issue", "inventory-service") in ops  # closed
    assert gh.data["issues"]["inventory-service"]["state"] == "closed"
    assert gh.data["issues"]["web-storefront"]["assignees"] == ["jlee"]

    # Second run right away is idempotent: no new issues or comments.
    gh.writes.clear()
    nag(gh, config, collect(gh, config, kev=kev), apply=True)
    assert not [w for w in gh.writes if w[0] in ("create_issue", "comment_issue")]


def test_linear_issue_lifecycle():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    linear = FakeLinear()

    def run():
        reports = collect(gh, config)
        return {r.repo: r for r in nag(gh, config, reports, apply=True, linear=linear)}

    runs = run()
    created = {}
    for op, (ident, fields) in linear.writes:
        if op == "create_issue":
            created[fields["title"].split(":")[0]] = (ident, fields)
    # Routed by owner, defaulting to SEC; priority and due date come from the worst alert.
    payments_ident, payments = created["payments-api"]
    assert payments_ident.startswith("PAY-")
    assert payments["labelIds"] == ["label:vulgard", "label:security", "label:Critical"]
    assert payments["projectId"] == "project:Security debt"
    assert payments["stateId"] == "PAY:triage"
    pipeline_ident, pipeline = created["data-pipeline"]
    assert pipeline_ident.startswith("SEC-")
    assert pipeline["labelIds"] == ["label:vulgard"]
    assert "projectId" not in pipeline and "stateId" not in pipeline
    assert pipeline["priority"] == 2 and "dueDate" in pipeline
    assert created["web-storefront"][1]["assigneeId"] == "user:jlee@acme.com"
    # The Linear link is persisted in the GitHub issue so later runs find it.
    ref = vuln_state(gh.data["issues"]["payments-api"]["body"]).linear
    assert ref.identifier == created["payments-api"][0]
    assert ("attach_url", (ref.id, runs["payments-api"].issue_url)) in linear.writes
    # The GitHub issue is written once on creation, with the Linear link already in it.
    payments_writes = [(op, args) for op, args in gh.writes if args[0] == "payments-api"]
    assert [op for op, _ in payments_writes] == ["ensure_label", "create_issue", "comment_issue"]
    assert ref.url in payments_writes[1][1][2]

    # Unchanged second run: no Linear writes.
    linear.writes.clear()
    run()
    assert linear.writes == []

    # Someone closes the Linear issue while alerts remain: vulgard reopens it into the
    # configured state.
    linear.issues[ref.id]["state"] = {"type": "completed"}
    runs = run()
    assert linear.issues[ref.id]["state"]["type"] == "triage"
    assert any("Reopened" in text for op, (_, text) in linear.writes if op == "comment")
    assert "linear-update" in {a.kind for a in runs["payments-api"].actions}

    # The critical alert is fixed: the severity label moves from Critical to High.
    gh.data["alerts"] = [
        a
        for a in gh.data["alerts"]
        if (a["repository"]["name"], a["number"]) != ("payments-api", 12)
    ]
    run()
    labels = [n["id"] for n in linear.issues[ref.id]["labels"]["nodes"]]
    assert labels == ["label:vulgard", "label:security", "label:High"]

    # Alerts resolved: GitHub issue closes and so does the Linear issue.
    alerts = gh.data["alerts"]
    gh.data["alerts"] = [a for a in alerts if a["repository"]["name"] != "payments-api"]
    gh.data["dependabot_prs"] = []
    run()
    assert linear.issues[ref.id]["state"]["type"] == "completed"


def test_linear_targets_merge_route_overrides_with_defaults():
    linear = parse_config(
        {
            "org": "acme",
            "linear": {
                "default_team": "SEC",
                "labels": ["vulgard", "security"],
                "state": "Backlog",
                "teams": {"web-*": "WEB", "@acme/payments": {"team": "PAY", "labels": []}},
            },
        }
    ).linear
    web = LinearTarget("WEB", ("vulgard", "security"), None, "Backlog")
    assert linear.target("web-app", []) == web
    assert linear.target("api", ["@acme/payments"]) == LinearTarget("PAY", (), None, "Backlog")
    assert linear.target("api", []).team == "SEC"
    with pytest.raises(ValueError, match="mapping with 'team'"):
        parse_config({"org": "acme", "linear": {"teams": {"x": {"labels": ["a"]}}}})
    with pytest.raises(ValueError, match="Unknown severities"):
        parse_config({"org": "acme", "linear": {"severity_labels": {"urgent": "P0"}}})
    with pytest.raises(ValueError, match="linear.labels"):
        parse_config({"org": "acme", "linear": {"label": "vulgard"}})


def test_linear_escalation_is_commented_when_the_issue_is_created():
    config = example_config()
    gh, kev = demo()
    linear = FakeLinear()
    nag(gh, config, collect(gh, config, kev=kev), apply=True, linear=linear)
    payments = next(i for i in linear.issues.values() if i["title"].startswith("payments-api:"))
    comments = [text for op, (issue_id, text) in linear.writes if issue_id == payments["id"]]
    assert any("Escalating" in str(text) for text in comments)


def test_linear_ignores_a_ref_pointing_at_another_repos_issue():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    linear = FakeLinear()
    victim = linear.create_issue({"teamId": "team-OPS", "title": "unrelated: keep out"})
    ref = LinearRef(victim["id"], victim["identifier"], victim["url"])
    forged = TrackingState(VulnMemory(), linear=ref)
    gh.data["issues"]["payments-api"] = {"number": 7, "body": forged.to_comment()}
    linear.writes.clear()

    nag(gh, config, collect(gh, config), apply=True, linear=linear)
    touched = [args[0] for op, args in linear.writes if op != "create_issue"]
    assert victim["id"] not in touched
    assert victim["fields"]["title"] == "unrelated: keep out"
    ref = vuln_state(gh.data["issues"]["payments-api"]["body"]).linear
    assert ref.id != victim["id"]


def test_slack_routes_to_team_channels_dms_and_escalation():
    config = example_config()
    gh, kev = demo()
    runs = nag(gh, config, collect(gh, config, kev=kev), apply=False)
    slack = FakeSlack()
    notify_slack(slack, config, runs, apply=True)
    by_target = {target: text for target, text in slack.messages}

    assert "payments-api" in by_target["#payments-eng"]  # owner -> channel
    assert "1 Dependabot PR(s) ready to merge" in by_target["#payments-eng"]
    assert "web-storefront" in by_target["#frontend"]
    assert "data-pipeline" in by_target["#eng-alerts"]  # default channel
    assert "<@U012JLEE>" in by_target["#frontend"]  # GitHub handle -> Slack mention
    assert "web-storefront" in by_target["U012JLEE"]  # DM to the individual owner
    escalation = by_target["#security-escalations"]
    assert escalation.startswith("<!subteam^S01SECURITY>") and "payments-api" in escalation


def test_weekly_summary_flags_unexplained_dismissals():
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    since = datetime.now(UTC) - timedelta(days=7)
    repos = {"payments-api", "data-pipeline"}
    closed = summarize_closed(gh.list_closed_alerts("acme", since), repos, since)
    assert closed.fixed == {"payments-api": 1}
    assert [(d.repo, d.by) for d in closed.unexplained] == [("data-pipeline", "mchen")]

    config = example_config()
    text, blocks = leaderboard_message(leaderboard_blocks(config, collect(gh, config), closed))
    rendered = json.dumps(blocks, ensure_ascii=False)
    assert "1 fixed" in rendered and "no justification" in rendered and "mchen" in rendered
    assert "Most fixed this week" in rendered and "🥇 @acme/payments: 1" in rendered
    assert "Most overdue" in rendered and "<@" not in text  # names teams without pinging


def test_leaderboard_goes_to_the_org_default_channel():
    config = example_config()
    slack = FakeSlack()
    action = send_leaderboard(slack, None, config, "hi", [], apply=True)
    assert action.kind == ActionKind.SLACK and slack.messages[0][0] == "#eng-alerts"
    config.slack.default_channel = None
    assert send_leaderboard(slack, None, config, "hi", [], True).kind == ActionKind.SLACK_SKIP


def test_channel_routing_matches_repo_globs_before_owners():
    mapping = {"payments-*": "#payments", "@acme/frontend": "#frontend"}
    assert route(mapping, "payments-api", ["@acme/frontend"], "#eng") == "#payments"
    assert route(mapping, "web", ["@acme/frontend"], "#eng") == "#frontend"
    assert route(mapping, "data", [], "#eng") == "#eng"


def test_detect_ecosystems_skips_vendored_dirs():
    paths = [
        "package.json",
        "web/package.json",
        "node_modules/left-pad/package.json",
        "svc/go.mod",
        "Dockerfile",
        ".github/workflows/ci.yml",
        "App/App.csproj",
    ]
    assert detect_ecosystems(paths) == {
        "docker": ["/"],
        "github-actions": ["/"],
        "gomod": ["/svc"],
        "npm": ["/", "/web"],
        "nuget": ["/App"],
    }


def test_dependabot_config_groups_updates():
    cfg = yaml.safe_load(render_dependabot_config({"npm": ["/", "/web"], "pip": ["/"]}, "weekly"))
    npm, pip = cfg["updates"]
    assert npm["directories"] == ["/", "/web"] and pip["directory"] == "/"
    assert npm["groups"]["minor-and-patch"]["update-types"] == ["minor", "patch"]
    assert npm["groups"]["security"]["applies-to"] == "security-updates"


def test_caller_workflow_is_valid_yaml_and_auto_merge_is_opt_in(config):
    jobs = yaml.safe_load(render_caller_workflow(config, "api"))["jobs"]
    assert jobs["guard"]["uses"] == "acme/vulgard/.github/workflows/guard.yml@main"
    assert "automerge" not in jobs  # off unless the repo opts in
    config.rollout.auto_merge = ["web-*"]
    assert "automerge" not in yaml.safe_load(render_caller_workflow(config, "api"))["jobs"]
    jobs = yaml.safe_load(render_caller_workflow(config, "web-app"))["jobs"]
    assert jobs["automerge"]["uses"].endswith("/automerge.yml@main")


def test_auto_merge_rejects_the_old_boolean_form():
    with pytest.raises(ValueError, match="list of repos"):
        parse_config({"org": "acme", "rollout": {"auto_merge": True}})


def test_rollout_refreshes_managed_workflow_but_not_hand_written_ones():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    repos = {r["name"]: r for r in gh.list_repos("acme")}
    files = gh.data["files"]["inventory-service"]
    files[WORKFLOW_PATH] = "# Managed by vulgard (acme/vulgard). old\nname: vulgard\n"
    plan = plan_rollout(gh, config, repos["inventory-service"])
    assert plan.files == {WORKFLOW_PATH: render_caller_workflow(config, "inventory-service")}
    files[WORKFLOW_PATH] = plan.files[WORKFLOW_PATH]
    assert plan_rollout(gh, config, repos["inventory-service"]).skipped_reason == "up to date"


def test_rollout_enables_repo_auto_merge_only_when_opted_in():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    repos = {r["name"]: r for r in gh.list_repos("acme")}
    for name in ("payments-api", "web-storefront"):
        apply_rollout(gh, config, plan_rollout(gh, config, repos[name]))
    calls = [args for op, args in gh.writes if op == "enable_security_features"]
    assert calls == [("payments-api", True), ("web-storefront", False)]


def test_rollout_plan_only_adds_missing_files():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    repos = {r["name"]: r for r in gh.list_repos("acme")}
    assert set(plan_rollout(gh, config, repos["payments-api"]).files) == {
        DEPENDABOT_PATH,
        WORKFLOW_PATH,
    }
    assert set(plan_rollout(gh, config, repos["web-storefront"]).files) == {WORKFLOW_PATH}
    assert plan_rollout(gh, config, repos["inventory-service"]).skipped_reason


def test_enforce_status_check_targets_enrolled_repos_only():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    p = plan_enforce(gh, config, "status-check", gh.list_repos("acme"))
    assert p.enrolled == ["inventory-service"]
    rule = p.ruleset["rules"][0]
    assert rule["parameters"]["required_status_checks"] == [{"context": STATUS_CHECK_CONTEXT}]
    assert p.ruleset["conditions"]["repository_name"]["include"] == ["inventory-service"]


def test_enforce_workflow_mode_uses_repo_id():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    p = plan_enforce(gh, config, "workflow", gh.list_repos("acme"))
    wf = p.ruleset["rules"][0]["parameters"]["workflows"][0]
    assert wf["repository_id"] == 107
    assert "vulgard" in p.ruleset["conditions"]["repository_name"]["exclude"]


def test_cli_nag_redact_hides_repo_names(capsys, tmp_path):
    summary = tmp_path / "summary.md"
    fixtures = ["--fixtures", str(EXAMPLES / "demo-org.json")]
    main(["--config", str(EXAMPLES / "vulgard.yml"), *fixtures, "nag", "--redact",
          "--summary-file", str(summary)])
    out = capsys.readouterr().out
    assert "create: " in out and "action(s) across" in out
    assert "payments-api" not in out and not summary.exists()


def test_cli_report_json(capsys):
    code = main(
        [
            "--config",
            str(EXAMPLES / "vulgard.yml"),
            "--fixtures",
            str(EXAMPLES / "demo-org.json"),
            "report",
            "--format",
            "json",
        ]
    )
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["payments-api"]["alerts"][0]["severity"] == "critical"
