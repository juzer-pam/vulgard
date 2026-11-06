from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from vulgard.cli import main
from vulgard.clients import Clients
from vulgard.config import parse_config
from vulgard.estate import ScanError
from vulgard.fixtures import (
    FakeLinear,
    FakeSlack,
    FixtureExecutor,
    FixtureGitHub,
    FixtureInspector,
    FixtureScanner,
)
from vulgard.inspector_sla import TITLE, UNATTRIBUTED_TITLE
from vulgard.plan import ActionKind, Topic
from vulgard.slack import notify_slack
from vulgard.topics import NagContext, run_inspector, run_vulns
from vulgard.vulns import INSPECTOR_TRACKS, OUT_OF_SCOPE

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
LABEL = "vulgard-inspector"
FIXTURE_ARGS = [
    "--fixtures",
    str(EXAMPLES / "demo-org.json"),
    "--config",
    str(EXAMPLES / "vulgard.yml"),
]


def finding(repo, package="axios", severity="HIGH", resource=None):
    name = resource or f"{repo or 'orphan'}-handler"
    return {
        "findingArn": f"arn:aws:inspector2:us-east-1:000000000000:finding/{name}-{package}",
        "severity": severity,
        "type": "PACKAGE_VULNERABILITY",
        "firstObservedAt": "2026-10-01T00:00:00Z",
        "fixAvailable": "YES",
        "exploitAvailable": "NO",
        "title": f"CVE-2024-0001 - {package}",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-2024-0001",
            "vulnerablePackages": [
                {
                    "name": package,
                    "version": "1.0.0",
                    "packageManager": "NODE",
                    "fixedInVersion": "1.0.1",
                }
            ],
        },
        "resources": [
            {
                "type": "AWS_LAMBDA_FUNCTION",
                "id": f"arn:aws:lambda:us-east-1:000000000000:function:{name}",
                "region": "us-east-1",
                "tags": {"vulgard:repo": repo} if repo else {},
                "details": {"awsLambdaFunction": {"functionName": name}},
            }
        ],
    }


def org(*findings, repos=(("api", "private"), ("site", "public"))):
    return {
        "repos": [
            {"name": name, "private": seen == "private", "visibility": seen}
            for name, seen in repos
        ],
        "aws": {"inspector": {"findings": list(findings)}},
    }


def config(**linear):
    return parse_config(
        {
            "org": "acme",
            "escalation": {"mentions": ["@acme/security"]},
            "slack": {"default_channel": "#eng"},
            "linear": {"default_team": "SEC", **linear},
            "inspector": {"enabled": True},
        }
    )


class Org:
    """One org across runs: GitHub issues and Linear issues persist, findings can change."""

    def __init__(self, data, cfg=None):
        self.gh = FixtureGitHub(data, NOW)
        self.linear = FakeLinear()
        self.slack = FakeSlack()
        self.config = cfg or config()
        self.inspector_reads = 0
        self.inspector_down = False

    @property
    def findings(self):
        return self.gh.data["aws"]["inspector"]["findings"]

    def context(self, days=0, apply=True, linear=True, only=None, topics=()):
        gh = self.gh
        clients = Clients(
            github=gh,
            linear=self.linear,
            slack=self.slack,
            slack_webhook=None,
            kev=frozenset,
            scanners=lambda: [FixtureScanner(gh.data)],
            executor=lambda: FixtureExecutor(gh.data),
            inspector=self.read_inspector,
        )
        now = NOW + timedelta(days=days)
        client = self.linear if linear else None
        return NagContext(clients, self.config, only, apply, False, False, now, client, topics)

    def read_inspector(self):
        self.inspector_reads += 1
        if self.inspector_down:
            raise ScanError("Inspector is down")
        return FixtureInspector(self.gh.data)

    def run(self, days=0, apply=True, linear=True, only=None):
        return run_inspector(self.context(days, apply, linear, only))

    def github_issue(self, repo):
        return self.gh.data.get("issues", {}).get(f"{repo}#{LABEL}")

    def linear_issue(self, title):
        return next((i for i in self.linear.issues.values() if i["title"] == title), None)

    def sub_issue(self, repo):
        return self.linear_issue(f"{repo}: {TITLE}")


def kinds(result):
    return [a.kind for run in result.runs for a in run.actions] + [a.kind for a in result.actions]


# --- where items are written


def test_a_private_repo_gets_a_github_issue_and_a_linear_sub_issue():
    world = Org(org(finding("api")))
    world.run()
    issue = world.github_issue("api")
    assert issue["state"] == "open" and "`axios`" in issue["body"]
    assert "api-handler" in issue["body"]
    sub = world.sub_issue("api")
    assert sub is not None and "`axios`" in sub["description"]
    assert sub["parent"] == {"id": world.linear_issue(TITLE)["id"]}


def test_a_public_repo_gets_no_github_issue_but_gets_its_linear_sub_issue():
    world = Org(org(finding("site")))
    result = world.run()
    assert world.github_issue("site") is None
    assert not [w for w in world.gh.writes if w[0] in ("create_issue", "comment_issue")]
    assert "`axios`" in world.sub_issue("site")["description"]
    assert ActionKind.CREATE not in kinds(result)


def test_a_repo_of_unknown_visibility_is_treated_as_public():
    data = org(finding("api"))
    data["repos"] = [{"name": "api"}]
    world = Org(data)
    world.run()
    assert world.github_issue("api") is None and world.sub_issue("api") is not None


def test_findings_attributed_to_an_excluded_repo_are_dropped():
    data = org(
        finding("api"),
        finding("legacy-app"),
        repos=(("api", "private"), ("legacy-app", "private")),
    )
    world = Org(data, replace(config(), exclude=["legacy-*"]))
    result = world.run()
    assert world.github_issue("api") is not None and world.sub_issue("api") is not None
    assert world.github_issue("legacy-app") is None and world.sub_issue("legacy-app") is None
    assert {run.repo for run in result.runs} == {"api"}
    assert result.repos == {"api"}


# --- which repos the vulns topic leaves to Inspector

BOTH = (Topic.VULNS, Topic.INSPECTOR)
SCOPE_REPOS = (
    ("docs-site", "private"),
    ("svc-in", "private"),
    ("svc-out", "private"),
    ("legacy-app", "private"),
)


def alert(number, repo):
    return {
        "number": number,
        "repository": {"name": repo},
        "created_at": "2026-10-20T00:00:00+00:00",
        "html_url": f"https://github.com/acme/{repo}/security/dependabot/{number}",
        "dependency": {"package": {"ecosystem": "npm", "name": "lodash"}, "manifest_path": "p"},
        "security_advisory": {"ghsa_id": f"GHSA-{number}", "summary": "bad", "severity": "high"},
        "security_vulnerability": {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "first_patched_version": {"identifier": "9.9.9"},
        },
    }


def scoped_org(*findings, **overrides):
    """docs-site: in include, no findings. svc-in: in include, has findings. svc-out: outside
    include, has findings. legacy-app: excluded, has findings. Each has an open alert."""
    data = org(*findings, repos=SCOPE_REPOS)
    data["alerts"] = [alert(n, name) for n, (name, _) in enumerate(SCOPE_REPOS, 1)]
    scope = {"include": ["docs-*", "svc-in", "legacy-*"], "exclude": ["legacy-*"], **overrides}
    return Org(data, replace(config(), **scope))


def scope_findings():
    return [finding("svc-in"), finding("svc-out"), finding("legacy-app")]


def tracked_issues(world):
    return sorted(world.gh.data.get("issues", {}))


def test_each_repo_is_tracked_by_one_topic_by_include_exclude_and_findings():
    world = scoped_org(*scope_findings())
    ctx = world.context(topics=BOTH)
    run_vulns(ctx)
    run_inspector(ctx)
    assert tracked_issues(world) == [
        "docs-site",  # in include, no findings: vulns
        f"svc-in#{LABEL}",  # in include, has findings: Inspector only
        f"svc-out#{LABEL}",  # outside include, has findings: Inspector only
    ]


def test_the_vulns_topic_keeps_every_include_repo_when_inspector_is_not_in_the_run():
    world = scoped_org(*scope_findings())
    run_vulns(world.context(topics=(Topic.VULNS,)))
    assert tracked_issues(world) == ["docs-site", "svc-in"]
    assert world.inspector_reads == 0


def test_the_inspector_report_is_built_once_for_a_run():
    world = scoped_org(*scope_findings())
    ctx = world.context(topics=BOTH)
    run_vulns(ctx)
    run_inspector(ctx)
    assert world.inspector_reads == 1


def test_inspector_report_only_leaves_the_repos_to_the_vulns_topic():
    world = scoped_org(*scope_findings(), inspector=replace(config().inspector, report_only=True))
    ctx = world.context(topics=BOTH)
    run_vulns(ctx)
    run_inspector(ctx)
    assert tracked_issues(world) == ["docs-site", "svc-in"]


def test_repo_narrows_the_vulns_topic_and_inspector_together():
    world = scoped_org(*scope_findings())
    ctx = world.context(topics=BOTH, only=["svc-in", "docs-site"])
    run_vulns(ctx)
    run_inspector(ctx)
    assert tracked_issues(world) == ["docs-site", f"svc-in#{LABEL}"]


def test_the_vulns_topic_is_skipped_when_inspector_cannot_say_which_repos_it_tracks(capsys):
    world = scoped_org(*scope_findings())
    world.inspector_down = True
    ctx = world.context(topics=BOTH)
    vulns, inspector = run_vulns(ctx), run_inspector(ctx)
    assert vulns.failed and inspector.failed
    assert tracked_issues(world) == [] and world.inspector_reads == 1
    assert "skipped vulnerable dependencies" in capsys.readouterr().err


# --- closing the vulns issues of repos that moved


def vulns_before_the_move():
    """The vulns topic alone has opened docs-site and svc-in, with a Linear issue each."""
    world = scoped_org(*scope_findings())
    run_vulns(world.context(topics=(Topic.VULNS,)))
    assert world.gh.data["issues"]["svc-in"]["state"] == "open"
    return world


def issue_comments(world, repo):
    return [args[2] for op, args in world.gh.writes if op == "comment_issue" and args[0] == repo]


def linear_comments(world, title):
    issue_id = world.linear_issue(title)["id"]
    return [
        body for op, (target, body) in world.linear.writes if op == "comment" and target == issue_id
    ]


def test_a_repo_inspector_now_tracks_has_its_open_vulns_issue_closed():
    world = vulns_before_the_move()
    result = run_vulns(world.context(topics=BOTH))
    issue = world.gh.data["issues"]["svc-in"]
    assert issue["state"] == "closed" and issue_comments(world, "svc-in") == [INSPECTOR_TRACKS]
    title = f"svc-in: {config().issue.title}"
    assert world.linear_issue(title)["state"]["type"] == "completed"
    assert linear_comments(world, title) == [INSPECTOR_TRACKS]
    assert world.gh.data["issues"]["docs-site"]["state"] == "open"
    assert [(r.repo, a.kind) for r in result.runs for a in r.actions if a.kind == "close"] == [
        ("svc-in", ActionKind.CLOSE)
    ]


def test_a_repo_that_left_include_has_its_open_vulns_issue_closed():
    world = vulns_before_the_move()
    world.config = replace(world.config, include=["svc-in"])
    run_vulns(world.context(topics=BOTH))
    assert world.gh.data["issues"]["docs-site"]["state"] == "closed"
    assert issue_comments(world, "docs-site") == [OUT_OF_SCOPE]
    assert linear_comments(world, f"docs-site: {config().issue.title}") == [OUT_OF_SCOPE]
    assert issue_comments(world, "svc-in") == [INSPECTOR_TRACKS]


def test_a_dry_run_only_reports_the_issues_it_would_close():
    world = vulns_before_the_move()
    writes, linear_writes = len(world.gh.writes), len(world.linear.writes)
    result = run_vulns(world.context(topics=BOTH, apply=False))
    kinds_for_svc_in = {a.kind for r in result.runs for a in r.actions if a.repo == "svc-in"}
    assert kinds_for_svc_in == {ActionKind.CLOSE, ActionKind.LINEAR_CLOSE}
    assert world.gh.data["issues"]["svc-in"]["state"] == "open"
    assert (len(world.gh.writes), len(world.linear.writes)) == (writes, linear_writes)


def test_nothing_closes_unless_inspector_runs_and_writes_tickets():
    world = vulns_before_the_move()
    world.config = replace(world.config, include=["svc-in"])
    run_vulns(world.context(topics=(Topic.VULNS,)))
    reporting = replace(world.config.inspector, report_only=True)
    world.config = replace(world.config, inspector=reporting)
    run_vulns(world.context(topics=BOTH))
    assert {i["state"] for i in world.gh.data["issues"].values()} == {"open"}


def test_excluded_repos_keep_their_open_vulns_issue():
    world = vulns_before_the_move()
    world.gh.data["issues"]["legacy-app"] = {"number": 9, "state": "open", "body": "old"}
    run_vulns(world.context(topics=BOTH))
    assert world.gh.data["issues"]["legacy-app"] == {"number": 9, "state": "open", "body": "old"}


def test_the_fixture_run_closes_the_demo_issue_inspector_took_over(capsys):
    assert main([*FIXTURE_ARGS, "nag", "--topic", "vulns", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    assert "inventory-service: close (tracked by Inspector)" in out
    assert "web-storefront: create (1 alert(s))" in out
    assert "payments-api: create (3 alert(s))" not in out
    assert main([*FIXTURE_ARGS, "nag", "--topic", "vulns", "--topic", "inspector", "--redact"]) == 0
    assert capsys.readouterr().out == "[dry-run] nag finished.\n"


def test_two_repos_routed_to_one_team_share_one_parent():
    world = Org(org(finding("api"), finding("site")))
    world.run()
    parents = [i for i in world.linear.issues.values() if i["title"] == TITLE]
    assert len(parents) == 1 and parents[0]["team"]["key"] == "SEC"
    children = world.linear.sub_issues(parents[0]["id"])
    assert sorted(c["title"] for c in children) == [f"api: {TITLE}", f"site: {TITLE}"]
    assert "| api | 1 | 0 |" in parents[0]["description"]
    assert "| site | 1 | 0 |" in parents[0]["description"]


def test_repos_in_different_teams_get_a_parent_each():
    world = Org(org(finding("api"), finding("site")), config(teams={"site": "WEB"}))
    world.run()
    parents = {i["team"]["key"]: i for i in world.linear.issues.values() if i["title"] == TITLE}
    assert set(parents) == {"SEC", "WEB"}
    assert world.sub_issue("site")["parent"] == {"id": parents["WEB"]["id"]}


def test_findings_with_no_repo_make_one_default_team_issue_and_nothing_on_github():
    world = Org(org(finding(None, "braces"), finding(None, "minimist", resource="other")))
    world.run()
    assert not world.gh.writes
    issue = world.linear_issue(UNATTRIBUTED_TITLE)
    assert issue["team"]["key"] == "SEC"
    assert "### No repo or deployment tags (2)" in issue["description"]
    assert "`orphan-handler`" in issue["description"] and "`other`" in issue["description"]


def test_the_issue_for_findings_with_no_repo_updates_and_closes_when_empty():
    world = Org(org(finding(None, "braces")))
    world.run()
    world.findings.append(finding(None, "minimist", resource="other"))
    world.run()
    assert "`minimist`" in world.linear_issue(UNATTRIBUTED_TITLE)["description"]
    world.findings.clear()
    world.run()
    assert world.linear_issue(UNATTRIBUTED_TITLE)["state"]["type"] == "completed"


# --- deadlines


def listed_line(body, package):
    return next(line for line in body.splitlines() if f"`{package}`" in line)


def heading_over(body, package):
    lines = body.splitlines()
    at = lines.index(listed_line(body, package))
    return next(line for line in reversed(lines[:at]) if line.startswith("###"))


def test_a_deadline_counts_from_the_first_run_that_listed_the_item():
    world = Org(org(finding("api")))
    world.run()
    assert "due in 30d" in listed_line(world.github_issue("api")["body"], "axios")
    world.run(days=10)
    assert "due in 20d" in listed_line(world.github_issue("api")["body"], "axios")
    assert world.sub_issue("api")["fields"]["dueDate"] == "2026-12-02"


def test_a_status_change_does_not_reset_the_deadline():
    world = Org(org(finding("api")))
    world.run()
    assert "a person has to look" in heading_over(world.github_issue("api")["body"], "axios")
    purl = {"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}
    other = {"name": "left-pad", "versionInfo": "1.3.0", "externalRefs": [purl]}
    world.gh.data["sboms"] = {"api": {"sbom": {"packages": [other]}}}
    world.run(days=10)
    body = world.github_issue("api")["body"]
    assert heading_over(body, "axios") == "### Fixed on the default branch: redeploy (1)"
    assert "due in 20d" in listed_line(body, "axios")


def test_an_item_added_later_gets_its_own_clock():
    world = Org(org(finding("api")))
    world.run()
    world.findings.append(finding("api", "lodash"))
    world.run(days=10)
    body = world.github_issue("api")["body"]
    assert "due in 20d" in listed_line(body, "axios")
    assert "due in 30d" in listed_line(body, "lodash")
    comments = [w[1][2] for w in world.gh.writes if w[0] == "comment_issue"]
    assert any("`lodash`" in c for c in comments)


def test_a_well_overdue_item_escalates_once():
    world = Org(org(finding("api")))
    world.run()
    escalated = world.run(days=40)
    assert ActionKind.ESCALATE in kinds(escalated)
    comments = [w[1][2] for w in world.gh.writes if w[0] == "comment_issue"]
    assert any(c.startswith("@acme/security Escalating") for c in comments)
    linear_comments = [w[1][1] for w in world.linear.writes if w[0] == "comment"]
    assert any(c.startswith("Escalating") for c in linear_comments)
    assert "10d overdue" in listed_line(world.github_issue("api")["body"], "axios")
    assert ActionKind.ESCALATE not in kinds(world.run(days=41))


def test_an_overdue_item_goes_to_the_escalation_channel():
    cfg = config()
    cfg.slack.escalation_channel = "#security"
    world = Org(org(finding("api")), cfg)
    world.run()
    result = world.run(days=40)
    notify_slack(world.slack, cfg, result.runs, apply=True)
    assert "#security" in [channel for channel, _ in world.slack.messages]


# --- closing


def test_the_last_item_clearing_closes_the_issue_and_the_sub_issue():
    world = Org(org(finding("api"), finding("site")))
    world.run()
    world.findings.clear()
    result = world.run(days=1)
    assert world.github_issue("api")["state"] == "closed"
    assert world.sub_issue("api")["state"]["type"] == "completed"
    assert world.sub_issue("site")["state"]["type"] == "completed"
    assert world.linear_issue(TITLE)["state"]["type"] == "completed"
    assert ActionKind.CLOSE in kinds(result)


def test_a_closed_issue_restarts_the_clock_when_items_return():
    world = Org(org(finding("api")))
    world.run()
    world.findings.clear()
    world.run(days=5)
    world.findings.append(finding("api"))
    world.run(days=10)
    assert world.github_issue("api")["state"] == "open"
    assert "due in 30d" in listed_line(world.github_issue("api")["body"], "axios")


# --- Slack


def test_slack_lines_link_the_linear_sub_issue_and_count_what_items_need():
    world = Org(org(finding("api"), finding("site")))
    result = world.run()
    notify_slack(world.slack, world.config, result.runs, apply=True)
    channel, _ = world.slack.messages[0]
    text = "\n".join(b["text"]["text"] for b in world.slack.blocks[0] if "text" in b)
    assert channel == "#eng"
    for repo in ("api", "site"):
        url = world.sub_issue(repo)["url"]
        assert f"<{url}|{repo}>" in text
    assert "1 package(s) (1 high)" in text and "for a person to check" not in text


# --- scope, report-only and dry runs


def test_a_repo_scoped_run_never_writes_parents_or_the_no_repo_issue():
    world = Org(org(finding("api"), finding(None, "braces")))
    world.run(only=["api"])
    assert world.linear_issue(TITLE) is None and world.linear_issue(UNATTRIBUTED_TITLE) is None
    assert world.sub_issue("api") is not None


def test_a_dry_run_writes_nothing():
    world = Org(org(finding("api"), finding("site"), finding(None, "braces")))
    result = world.run(apply=False)
    assert not world.gh.writes and not world.linear.issues
    assert ActionKind.LINEAR_CREATE in kinds(result)


def test_without_linear_public_repos_are_skipped(capsys):
    world = Org(org(finding("api"), finding("site")))
    world.run(linear=False)
    assert world.github_issue("api") is not None
    assert "Skipping 1 repo(s) that are tracked in Linear only" in capsys.readouterr().err


def example_config(tmp_path, **inspector):
    raw = yaml.safe_load((EXAMPLES / "vulgard.yml").read_text())
    raw["inspector"] = {**raw.get("inspector", {}), **inspector}
    path = tmp_path / "vulgard.yml"
    path.write_text(yaml.safe_dump(raw))
    return ["--fixtures", str(EXAMPLES / "demo-org.json"), "--config", str(path)]


def test_report_only_writes_nothing_but_the_summary(tmp_path, capsys):
    summary = tmp_path / "summary.md"
    args = example_config(tmp_path, report_only=True)
    nag = ["nag", "--topic", "inspector", "--linear", "--slack", "--apply"]
    assert main([*args, *nag, "--summary-file", str(summary)]) == 0
    out = capsys.readouterr().out
    assert "report-only: 3 repo(s) have fix items" in out
    assert "0 action(s)" in out
    assert "| payments-api | GitHub, Linear | 3 |" in summary.read_text()
    assert main([*args, *nag, "--redact"]) == 0
    assert capsys.readouterr().out == "Inspector findings are report-only.\nnag finished.\n"


def test_a_disabled_topic_is_skipped_and_cannot_be_asked_for(tmp_path, capsys):
    args = example_config(tmp_path, enabled=False)
    assert main([*args, "nag", "--topic", "inspector"]) == 1
    assert "--topic inspector needs inspector.enabled" in capsys.readouterr().err
    assert main([*args, "nag", "--linear"]) == 0
    assert "No repo:" not in capsys.readouterr().out


def test_the_fixture_run_tracks_the_demo_findings(capsys):
    assert main([*FIXTURE_ARGS, "nag", "--topic", "inspector", "--linear", "--slack"]) == 0
    out = capsys.readouterr().out
    assert "payments-api: create (3 item(s))" in out
    assert "inventory-service: linear-create" in out
    assert "inventory-service: create" not in out
    assert f"linear: linear-create ({UNATTRIBUTED_TITLE} in team SEC)" in out


def test_redacted_output_has_no_names_or_counts(capsys):
    nag = ["nag", "--topic", "inspector", "--linear", "--slack", "--redact"]
    assert main([*FIXTURE_ARGS, *nag]) == 0
    assert capsys.readouterr().out == "[dry-run] nag finished.\n"
