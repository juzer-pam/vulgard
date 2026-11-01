from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from vulgard.cli import collect, main
from vulgard.config import parse_config
from vulgard.enforce import STATUS_CHECK_CONTEXT, plan_enforce
from vulgard.fixtures import FakeLinear, FakeSlack, FixtureGitHub
from vulgard.nag import nag, plan_repo, read_state
from vulgard.policy import SlaStatus, evaluate, parse_codeowners_default, summarize_closed
from vulgard.rollout import (
    DEPENDABOT_PATH,
    WORKFLOW_PATH,
    detect_ecosystems,
    plan_rollout,
    render_caller_workflow,
    render_dependabot_config,
)
from vulgard.slack import digest_message, notify_slack

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


def plan(config, alerts, issue=None, prs=(), now=NOW, kev=frozenset()):
    report = evaluate(config, alerts, list(prs), ["api"], now, kev=kev)["api"]
    report.owners = ["@acme/api"]
    return plan_repo(report, config, issue, now)


def test_first_run_creates_issue_and_escalates_old_critical(config):
    p = plan(config, [alert(1, "api", "critical", 20)])
    assert [a.kind for a in p.actions] == ["create", "escalate"]
    assert "@acme/api" in p.body
    assert len(p.comments) == 1 and "@acme/security" in p.comments[0]
    state = read_state(p.body)
    assert state["overdue"] == [1] and state["escalated"] == [1]


def test_no_repeat_pings_until_reminder_interval(config):
    alerts = [alert(1, "api", "critical", 20)]
    first = plan(config, alerts)
    issue = {"number": 5, "body": first.body}

    # Next day: nothing new, so no comment and no re-escalation.
    p = plan(config, alerts, issue, now=NOW + timedelta(days=1))
    assert p.comments == [] and not p.pinged
    assert "comment" not in {a.kind for a in p.actions}

    # A week later: periodic reminder.
    issue = {"number": 5, "body": p.body}
    p = plan(config, alerts, issue, now=NOW + timedelta(days=7))
    assert len(p.comments) == 1 and "Reminder" in p.comments[0]
    assert p.reminder


def test_newly_overdue_alert_triggers_comment(config):
    first = plan(config, [alert(1, "api", "high", 25)])
    issue = {"number": 5, "body": first.body}
    p = plan(config, [alert(1, "api", "high", 25)], issue, now=NOW + timedelta(days=6))
    assert "comment" in {a.kind for a in p.actions}
    assert "just went past their fix deadline" in p.comments[0]
    assert [a.number for a in p.newly_overdue] == [1]


def test_stale_dependabot_pr_alone_keeps_issue_open(config):
    p = plan(config, [], prs=[pr(3, "api", "Bump x from 1 to 2", 30)])
    assert p.actions[0].kind == "create"
    assert "stale" in p.body


def test_clean_repo_closes_issue(config):
    p = plan(config, [], issue={"number": 5, "body": "x"})
    assert [a.kind for a in p.actions] == ["close"]
    assert p.body is None and p.closing and "resolved" in p.comments[0]


def test_green_fix_pr_pings_owners_once(config):
    alerts = [alert(1, "api", "high", 10, package="axios")]
    pending = [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 3, ci="PENDING")]
    first = plan(config, alerts, prs=pending)
    assert "Ready to merge" not in first.body and "CI running" in first.body

    # CI goes green: owners get one comment naming the alert it fixes.
    green = [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 4, ci="SUCCESS")]
    p = plan(config, alerts, {"number": 5, "body": first.body}, prs=green)
    assert [x.number for x in p.newly_ready] == [9] and p.pinged
    assert len(p.comments) == 1 and "@acme/api" in p.comments[0]
    assert "only waiting on a review" in p.comments[0] and "fixes high `axios`" in p.comments[0]
    assert "✅ Ready to merge (1)" in p.body

    # Still green the next day: no repeat ping.
    tomorrow = NOW + timedelta(days=1)
    p = plan(config, alerts, {"number": 5, "body": p.body}, prs=green, now=tomorrow)
    assert p.newly_ready == [] and p.comments == []


def test_conflicting_or_draft_prs_are_not_ready(config):
    conflicting = pr(9, "api", "Bump a from 1 to 2", 5, ci="SUCCESS")
    conflicting["mergeable"] = "CONFLICTING"
    draft = pr(10, "api", "Bump b from 1 to 2", 5, ci="SUCCESS")
    draft["draft"] = True
    fresh = pr(11, "api", "Bump c from 1 to 2", 0, ci="SUCCESS")
    report = evaluate(config, [], [conflicting, draft, fresh], ["api"], NOW)["api"]
    assert report.ready_prs(config.ready_pr_days) == []


def test_known_exploited_cve_gets_short_sla_and_escalates_immediately(config):
    exploited = alert(1, "api", "medium", 4)
    exploited["security_advisory"]["cve_id"] = "CVE-2024-0001"
    p = plan(config, [exploited], kev=frozenset({"CVE-2024-0001"}))
    a = p.report.alerts[0]
    assert a.known_exploited and a.days_left == -1 and a.status == SlaStatus.OVERDUE
    assert [x.number for x in p.escalate] == [1]
    assert "actively exploited" in p.body

    config.kev.enabled = False
    a = plan(config, [exploited], kev=frozenset({"CVE-2024-0001"})).report.alerts[0]
    assert not a.known_exploited and a.status == SlaStatus.OK


def test_exception_hides_alert_until_it_expires():
    exception = {"package": "lodash", "repo": "api", "reason": "unused", "expires": "2026-12-01"}
    config = parse_config({"org": "acme", "exceptions": [exception]})
    p = plan(config, [alert(1, "api", "critical", 20)])
    assert p.report.alerts == [] and len(p.report.accepted) == 1
    assert p.actions[0].kind == "noop"

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


def test_nag_apply_against_fixture():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    reports = collect(gh, config, kev=gh.known_exploited())
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
    nag(gh, config, collect(gh, config, kev=gh.known_exploited()), apply=True)
    assert not [w for w in gh.writes if w[0] in ("create_issue", "comment_issue")]


def test_linear_issue_lifecycle():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    linear = FakeLinear()

    def run():
        reports = collect(gh, config)
        return {p.repo: p for p in nag(gh, config, reports, apply=True, linear=linear)}

    plans = run()
    created = {}
    for op, (ident, fields) in linear.writes:
        if op == "create_issue":
            created[fields["title"].split(":")[0]] = (ident, fields)
    # Routed by owner, defaulting to SEC; priority and due date come from the worst alert.
    assert created["payments-api"][0].startswith("PAY-")
    pipeline_ident, pipeline = created["data-pipeline"]
    assert pipeline_ident.startswith("SEC-")
    assert pipeline["priority"] == 2 and "dueDate" in pipeline
    assert created["web-storefront"][1]["assigneeId"] == "user:jlee@acme.com"
    # The Linear link is persisted in the GitHub issue so later runs find it.
    ref = read_state(gh.data["issues"]["payments-api"]["body"])["linear"]
    assert ref["identifier"] == created["payments-api"][0]
    assert ("attach_url", (ref["id"], plans["payments-api"].issue_url)) in linear.writes

    # Unchanged second run: no Linear writes.
    linear.writes.clear()
    run()
    assert linear.writes == []

    # Someone closes the Linear issue while alerts remain: vulgard reopens it.
    linear.issues[ref["id"]]["state"] = {"type": "completed"}
    plans = run()
    assert linear.issues[ref["id"]]["state"]["type"] == "unstarted"
    assert any("Reopened" in body for op, (_, body) in linear.writes if op == "comment")
    assert "linear-update" in {a.kind for a in plans["payments-api"].actions}

    # Alerts resolved: GitHub issue closes and so does the Linear issue.
    alerts = gh.data["alerts"]
    gh.data["alerts"] = [a for a in alerts if a["repository"]["name"] != "payments-api"]
    gh.data["dependabot_prs"] = []
    run()
    assert linear.issues[ref["id"]]["state"]["type"] == "completed"


def test_slack_routes_to_team_channels_dms_and_escalation():
    config = example_config()
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    plans = nag(gh, config, collect(gh, config, kev=gh.known_exploited()), apply=False)
    slack = FakeSlack()
    notify_slack(slack, config, plans, apply=True)
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
    text, blocks = digest_message(config, collect(gh, config), closed)
    rendered = json.dumps(blocks)
    assert "1 fixed" in rendered and "no justification" in rendered and "mchen" in rendered


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


def test_caller_workflow_is_valid_yaml(config):
    wf = yaml.safe_load(render_caller_workflow(config))
    jobs = wf["jobs"]
    assert jobs["dependency-review"]["uses"].startswith("acme/vulgard/")
    assert "dependabot-automerge" in jobs
    config.rollout.auto_merge = False
    assert "dependabot-automerge" not in yaml.safe_load(render_caller_workflow(config))["jobs"]


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
