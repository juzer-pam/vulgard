from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.stub import Stubber

from vulgard.aws import AwsInspector, sight_finding
from vulgard.cli import main
from vulgard.config import SEVERITIES, InspectorConfig, parse_config
from vulgard.estate import (
    AmplifyBranch,
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    ScanError,
    Sighting,
    SstStage,
    Tier,
    VercelProject,
)
from vulgard.fixtures import FakeLinear, FixtureInspector
from vulgard.inspector import (
    NO_TRACKING,
    Attributed,
    Coverage,
    CoverageMatch,
    Finding,
    InspectorResource,
    Reason,
    ResourceType,
    Tracking,
    Unattributed,
    Via,
    build_report,
    build_tracking,
    cover,
    group_findings,
)
from vulgard.linear import LinearIssue
from vulgard.policy import Alert, DependabotPR, RepoReport

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
STACK = "aws:cloudformation:stack-name"
FIXTURE_ARGS = [
    "--fixtures",
    str(EXAMPLES / "demo-org.json"),
    "--config",
    str(EXAMPLES / "vulgard.yml"),
]


def function(name="api-dev-handler", tags=None):
    return InspectorResource(
        ResourceType.LAMBDA, f"arn:aws:lambda:::function:{name}", name, "us-east-1", tags or {}
    )


def instance(tags=None):
    return InspectorResource(ResourceType.EC2, "i-0abc", "i-0abc", "us-east-1", tags or {})


def image(repository):
    return InspectorResource(
        ResourceType.ECR_IMAGE,
        f"arn:aws:ecr:::repository/{repository}/sha256:0",
        repository,
        "us-east-1",
        {},
    )


def make_finding(on, vulnerability_id="CVE-2024-0001", package="axios", **fields):
    values = {
        "arn": f"{on.id}/{vulnerability_id}/{package}",
        "vulnerability_id": vulnerability_id,
        "severity": "high",
        "package": package,
        "package_manager": "NODE",
        "installed_version": "1.0.0",
        "fixed_in": "1.0.1",
        "fix_available": True,
        "exploit_available": False,
        "first_observed": NOW,
        "title": f"{vulnerability_id} - {package}",
        "resource": on,
        **fields,
    }
    return Finding(**values)


def deployment(native, repo):
    sighting = Sighting(Framework.SERVERLESS, native, "app", "stage", NOW)
    how = Attribution.MANIFEST if repo else Attribution.NONE
    return Deployment(sighting, repo, how, Tier.SHARED, None)


API_DEV = deployment(CfnStack("1", "us-east-1", "api-dev", "id"), "api")
INVENTORY = deployment(SstStage("1", "us-east-1", "bucket", "inventory", "prod"), "inventory")
STOREFRONT = deployment(AmplifyBranch("1", "us-east-1", "d1abc", "main", "site"), "storefront")
LEGACY = deployment(CfnStack("1", "us-east-1", "legacy-staging", "id"), None)
DOCS = deployment(VercelProject("team", "docs-site", "docs"), "docs")
DEPLOYMENTS = [API_DEV, INVENTORY, STOREFRONT, LEGACY, DOCS]


# --- attribution

ATTRIBUTION_CASES = [
    pytest.param(
        function(tags={STACK: "api-dev"}),
        Attributed("api", Via.DEPLOYMENT, "api-dev"),
        id="cloudformation-stack-tag",
    ),
    pytest.param(
        function(tags={"sst:app": "inventory", "sst:stage": "prod"}),
        Attributed("inventory", Via.DEPLOYMENT, "inventory/prod"),
        id="sst-app-and-stage-tags",
    ),
    pytest.param(
        function(tags={"amplify:app-id": "d1abc", "amplify:branch-name": "main"}),
        Attributed("storefront", Via.DEPLOYMENT, "site/main"),
        id="amplify-app-and-branch-tags",
    ),
    pytest.param(
        instance(tags={STACK: "api-dev"}),
        Attributed("api", Via.DEPLOYMENT, "api-dev"),
        id="ec2-instance",
    ),
    pytest.param(
        image("serverless-api-dev"),
        Attributed("api", Via.DEPLOYMENT, "api-dev"),
        id="serverless-ecr-repository-names-the-stack",
    ),
    pytest.param(
        function(tags={STACK: "api-dev", "sst:app": "inventory", "sst:stage": "prod"}),
        Attributed("api", Via.DEPLOYMENT, "api-dev"),
        id="first-candidate-found-wins",
    ),
    pytest.param(
        function(tags={STACK: "gone", "sst:app": "inventory", "sst:stage": "prod"}),
        Attributed("inventory", Via.DEPLOYMENT, "inventory/prod"),
        id="later-candidate-when-the-first-is-not-found",
    ),
    pytest.param(
        function(tags={STACK: "api-dev", "github:repo": "https://github.com/acme/payments.git"}),
        Attributed("payments", Via.TAG),
        id="repo-tag-beats-deployment",
    ),
    pytest.param(
        function(tags={STACK: "legacy-staging"}),
        Unattributed(Reason.DEPLOYMENT_UNATTRIBUTED),
        id="deployment-without-a-repo",
    ),
    pytest.param(
        function(tags={STACK: "gone"}),
        Unattributed(Reason.DEPLOYMENT_NOT_FOUND),
        id="stack-not-in-the-estate",
    ),
    pytest.param(
        function(tags={STACK: "docs-site"}),
        Unattributed(Reason.DEPLOYMENT_NOT_FOUND),
        id="vercel-projects-are-not-looked-up",
    ),
    pytest.param(
        image("serverless-gone-dev"),
        Unattributed(Reason.DEPLOYMENT_NOT_FOUND),
        id="serverless-ecr-repository-without-a-stack",
    ),
    pytest.param(
        image("sst-asset"),
        Unattributed(Reason.SHARED_ASSET_REPOSITORY),
        id="sst-asset-repository",
    ),
    pytest.param(
        image("cdk-hnb659fds-container-assets-111122223333-us-east-1"),
        Unattributed(Reason.SHARED_ASSET_REPOSITORY),
        id="cdk-asset-repository",
    ),
    pytest.param(function(), Unattributed(Reason.NO_DEPLOYMENT_TAGS), id="no-tags"),
    pytest.param(
        function(tags={"sst:app": "inventory"}),
        Unattributed(Reason.NO_DEPLOYMENT_TAGS),
        id="sst-app-without-a-stage",
    ),
]


@pytest.mark.parametrize(("on", "expected"), ATTRIBUTION_CASES)
def test_attribution_rules(on, expected):
    finding = make_finding(on)
    report = build_report([finding], DEPLOYMENTS, InspectorConfig(), None, {})
    assert report.attributions == {finding.arn: expected}
    if isinstance(expected, Attributed):
        placed = report.by_repo[expected.repo]
    else:
        placed = report.unattributed[expected.reason]
    assert [group.findings for group in placed] == [(finding,)]


def test_a_stack_name_in_two_regions_attributes_to_the_resource_region():
    west = deployment(CfnStack("1", "us-west-2", "api-dev", "id-west"), "api-west")
    resource = InspectorResource(
        ResourceType.LAMBDA, "arn:west", "api-dev-handler", "us-west-2", {STACK: "api-dev"}
    )
    finding = make_finding(resource)
    report = build_report([finding], [API_DEV, west], InspectorConfig(), None, {})
    assert report.attributions[finding.arn].repo == "api-west"


def test_via_counts_how_findings_were_attributed():
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b", {"repo": "payments"})),
        make_finding(function("c", {"Repo": "payments"})),
    ]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), None, {})
    assert report.via == Counter({Via.DEPLOYMENT: 1, Via.TAG: 2})


# --- grouping, severity, ignore and scope


def test_findings_group_by_vulnerability_and_package_worst_first():
    first, second = function("fn-a", {STACK: "api-dev"}), function("fn-b", {STACK: "api-dev"})
    found = [
        make_finding(first, "CVE-1", severity="high", exploit_available=False, fixed_in=None),
        make_finding(second, "CVE-1", severity="critical", exploit_available=True, fixed_in="2.0"),
        make_finding(first, "CVE-2"),
        make_finding(second, "CVE-2"),
        make_finding(first, "CVE-3"),
        make_finding(second, "CVE-3", package="lodash"),
    ]
    groups = build_report(found, DEPLOYMENTS, InspectorConfig(), None, {}).by_repo["api"]
    assert [
        (group.vulnerability_id, group.package, group.severity, group.resources)
        for group in groups
    ] == [
        ("CVE-1", "axios", "critical", ["fn-a", "fn-b"]),
        ("CVE-2", "axios", "high", ["fn-a", "fn-b"]),
        ("CVE-3", "axios", "high", ["fn-a"]),
        ("CVE-3", "lodash", "high", ["fn-b"]),
    ]
    assert (groups[0].exploit_available, groups[0].fixed_in) == (True, "2.0")
    assert (groups[1].exploit_available, groups[1].fixed_in) == (False, "1.0.1")


@pytest.mark.parametrize(
    ("minimum", "kept"),
    [
        ("critical", ["critical"]),
        ("medium", ["critical", "high", "medium"]),
        ("low", ["critical", "high", "medium", "low"]),
    ],
)
def test_min_severity_keeps_that_severity_and_worse(minimum, kept):
    on = function(tags={STACK: "api-dev"})
    found = [make_finding(on, f"CVE-{severity}", severity=severity) for severity in SEVERITIES]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(min_severity=minimum), None, {})
    assert [group.severity for group in report.by_repo["api"]] == kept


def test_ignore_drops_findings_by_resource_name_or_stack_tag():
    kept = function("worker", {STACK: "api-dev"})
    by_name = function("scratch-handler", {STACK: "api-dev"})
    by_stack = function("handler", {STACK: "scratch-stack"})
    found = [make_finding(on) for on in (kept, by_name, by_stack)]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(ignore=["scratch-*"]), None, {})
    assert [group.resources for group in report.by_repo["api"]] == [["worker"]]
    assert report.unattributed == {} and len(report.attributions) == 1


def test_only_keeps_those_repos_and_drops_the_unattributed():
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b", {"sst:app": "inventory", "sst:stage": "prod"})),
        make_finding(function("c")),
    ]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), {"inventory"}, {})
    assert list(report.by_repo) == ["inventory"]
    assert report.unattributed == {}
    assert len(report.attributions) == 1


# --- coverage


def alert(cve="CVE-2024-0001", ghsa="GHSA-aaaa-bbbb-cccc", package="axios", repo="api", number=1):
    return Alert.from_api(
        {
            "number": number,
            "repository": {"name": repo},
            "created_at": "2026-10-01T00:00:00Z",
            "html_url": f"https://github.com/acme/{repo}/security/dependabot/{number}",
            "dependency": {"package": {"name": package, "ecosystem": "npm"}},
            "security_advisory": {"ghsa_id": ghsa, "cve_id": cve, "severity": "high"},
        }
    )


def bump(package="axios", repo="api", number=7):
    return DependabotPR.from_api(
        {
            "number": number,
            "title": f"Bump {package} from 1.0.0 to 1.0.1",
            "html_url": f"https://github.com/acme/{repo}/pull/{number}",
            "repository_url": f"https://api.github.com/repos/acme/{repo}",
            "created_at": "2026-10-20T00:00:00Z",
        }
    )


def issue(title="Patch api images", identifier="SEC-1"):
    return LinearIssue(identifier, title, f"https://linear.app/acme/issue/{identifier}")


def tracking(open_alerts=(), fixed_alerts=(), prs=(), linear_issues=()):
    return Tracking(tuple(open_alerts), tuple(fixed_alerts), tuple(prs), tuple(linear_issues))


def a_group(vulnerability_id="CVE-2024-0001", package="axios", package_manager="NODE"):
    on = function(tags={STACK: "api-dev"})
    finding = make_finding(on, vulnerability_id, package, package_manager=package_manager)
    return group_findings([finding], NO_TRACKING)[0]


STATUS_CASES = [
    pytest.param(tracking(open_alerts=[alert()]), "NODE", Coverage.DEPENDABOT_ALERT, id="alert"),
    pytest.param(
        tracking(prs=[bump()]), "NODE", Coverage.DEPENDABOT_PR, id="pr-bumping-the-package"
    ),
    pytest.param(
        tracking(fixed_alerts=[alert()]), "NODE", Coverage.FIXED_NOT_DEPLOYED, id="fixed-alert"
    ),
    pytest.param(
        tracking(linear_issues=[issue()]), "NODE", Coverage.LINEAR_ISSUE, id="linear-issue"
    ),
    pytest.param(NO_TRACKING, "OS", Coverage.UNTRACKED_OS_PACKAGE, id="os-package"),
    pytest.param(NO_TRACKING, "NODE", Coverage.UNTRACKED, id="application-package"),
    pytest.param(
        tracking(
            open_alerts=[alert(cve="CVE-2024-9999", ghsa="GHSA-zzzz-zzzz-zzzz")],
            prs=[bump(package="lodash")],
            fixed_alerts=[alert(cve="CVE-2024-8888", ghsa="GHSA-yyyy-yyyy-yyyy")],
        ),
        "NODE",
        Coverage.UNTRACKED,
        id="alerts-and-prs-for-something-else",
    ),
]


@pytest.mark.parametrize(("known", "package_manager", "expected"), STATUS_CASES)
def test_cover_gives_each_group_one_status(known, package_manager, expected):
    group = a_group(package_manager=package_manager)
    assert cover(group, known).status is expected


def test_an_open_alert_links_the_pull_request_that_fixes_it():
    fix = bump()
    flagged = alert()
    flagged.fix_pr = fix
    match = cover(a_group(), tracking(open_alerts=[flagged], prs=[fix]))
    assert (match.status, match.alert, match.pr) == (Coverage.DEPENDABOT_ALERT, flagged, fix)


def test_a_pull_request_without_an_alert_is_the_match_when_no_alert_names_the_vulnerability():
    fix = bump()
    match = cover(a_group(), tracking(prs=[fix]))
    assert (match.status, match.alert, match.pr) == (Coverage.DEPENDABOT_PR, None, fix)


def test_an_open_alert_wins_over_a_fixed_alert_for_the_same_vulnerability():
    open_one, fixed_one = alert(number=2), alert(number=1)
    match = cover(a_group(), tracking(open_alerts=[open_one], fixed_alerts=[fixed_one]))
    assert (match.status, match.alert) == (Coverage.DEPENDABOT_ALERT, open_one)


def test_a_fixed_alert_beats_a_linear_issue():
    fixed_one = alert()
    match = cover(a_group(), tracking(fixed_alerts=[fixed_one], linear_issues=[issue()]))
    assert (match.status, match.alert) == (Coverage.FIXED_NOT_DEPLOYED, fixed_one)


def test_a_ghsa_vulnerability_id_matches_an_alert_by_its_ghsa_id_ignoring_case():
    ghsa_only = alert(cve=None, ghsa="GHSA-AAAA-bbbb-cccc")
    match = cover(a_group("ghsa-aaaa-BBBB-cccc"), tracking(open_alerts=[ghsa_only]))
    assert (match.status, match.alert) == (Coverage.DEPENDABOT_ALERT, ghsa_only)


def test_a_linear_issue_covers_every_group_nothing_stronger_covers():
    found = [issue("Patch api images", "SEC-1"), issue("api container audit", "SEC-2")]
    match = cover(a_group(package_manager="OS"), tracking(linear_issues=found))
    assert (match.status, match.linear_issues) == (Coverage.LINEAR_ISSUE, tuple(found))


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(lambda: CoverageMatch(Coverage.UNTRACKED, alert=alert()), id="alert"),
        pytest.param(lambda: CoverageMatch(Coverage.DEPENDABOT_ALERT), id="missing-alert"),
        pytest.param(lambda: CoverageMatch(Coverage.DEPENDABOT_PR), id="missing-pr"),
        pytest.param(lambda: CoverageMatch(Coverage.UNTRACKED, pr=bump()), id="pr"),
        pytest.param(lambda: CoverageMatch(Coverage.LINEAR_ISSUE), id="missing-issues"),
        pytest.param(
            lambda: CoverageMatch(Coverage.UNTRACKED, linear_issues=(issue(),)), id="issues"
        ),
    ],
)
def test_a_coverage_match_only_carries_what_its_status_has(bad):
    with pytest.raises(AssertionError):
        bad()


def test_a_linear_issue_naming_a_longer_repo_does_not_cover_the_shorter_one():
    reports = {"payments": RepoReport("payments"), "payments-api": RepoReport("payments-api")}
    titles = [
        issue("Patch payments-api images", "SEC-1"),
        issue("Audit payments, then rotate keys", "SEC-2"),
        issue("Upgrade (payments-api-v2)", "SEC-3"),
    ]
    got = build_tracking(reports, [], titles)
    assert [i.identifier for i in got["payments"].linear_issues] == ["SEC-2"]
    assert [i.identifier for i in got["payments-api"].linear_issues] == ["SEC-1"]


def test_a_linear_title_names_the_repo_in_any_case_and_before_a_full_stop():
    reports = {"payments-api": RepoReport("payments-api")}
    titles = [
        issue("Patch Payments-API images", "SEC-1"),
        issue("Remediate payments-api.", "SEC-2"),
    ]
    got = build_tracking(reports, [], titles)
    assert [i.identifier for i in got["payments-api"].linear_issues] == ["SEC-1", "SEC-2"]


def test_an_alert_accepted_under_exceptions_still_covers_its_vulnerability():
    accepted = alert()
    report = RepoReport("api", accepted=[accepted])
    got = build_tracking({"api": report}, [], [])
    assert got["api"].open_alerts == (accepted,)


def test_build_tracking_keeps_open_alerts_prs_and_fixed_alerts_per_repo():
    open_one, fix = alert(), bump()
    report = RepoReport("api", alerts=[open_one], dependabot_prs=[fix])
    elsewhere = alert(repo="web", number=3)
    fixed_one = alert(repo="api", number=4)
    got = build_tracking({"api": report, "web": RepoReport("web")}, [fixed_one, elsewhere], [])
    assert got["api"] == tracking([open_one], [fixed_one], [fix])
    assert got["web"] == tracking(fixed_alerts=[elsewhere])


def test_linear_ignores_issues_without_a_configured_label_and_closed_ones():
    def existing(identifier, state, label):
        return {
            "identifier": identifier,
            "title": identifier.lower(),
            "url": f"u-{identifier}",
            "state": state,
            "labels": [label],
        }

    issues = [
        existing("SEC-1", "doing", "security"),
        existing("SEC-2", "todo", "infra"),
        existing("SEC-3", "done", "security"),
        existing("SEC-4", "wontdo", "security"),
    ]
    found = FakeLinear(issues).open_issues_with_labels(["security", "vulnerability"])
    assert found == [LinearIssue("SEC-1", "sec-1", "u-SEC-1")]


def test_build_report_covers_each_group_by_its_repo_and_only_untracks_the_unattributed():
    matching = alert()
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b"), "CVE-2024-0002", package_manager="OS"),
        make_finding(function("c"), "CVE-2024-0001"),
    ]
    known = {"api": tracking(open_alerts=[matching], linear_issues=[issue()])}
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), None, known)
    assert [group.coverage.status for group in report.by_repo["api"]] == [Coverage.DEPENDABOT_ALERT]
    unattributed = report.unattributed[Reason.NO_DEPLOYMENT_TAGS]
    assert {group.vulnerability_id: group.coverage.status for group in unattributed} == {
        "CVE-2024-0001": Coverage.UNTRACKED,
        "CVE-2024-0002": Coverage.UNTRACKED_OS_PACKAGE,
    }
    assert report.coverage == Counter(
        {Coverage.DEPENDABOT_ALERT: 1, Coverage.UNTRACKED: 1, Coverage.UNTRACKED_OS_PACKAGE: 1}
    )


# --- parser

LAMBDA_RESOURCE = {
    "type": "AWS_LAMBDA_FUNCTION",
    "id": "arn:aws:lambda:us-east-1:111122223333:function:api-dev-handler",
    "region": "us-east-1",
    "tags": {STACK: "api-dev"},
    "details": {
        "awsLambdaFunction": {
            "functionName": "api-dev-handler",
            "runtime": "nodejs20.x",
            "codeSha256": "sha",
            "version": "$LATEST",
            "executionRoleArn": "arn:aws:iam::111122223333:role/handler",
        }
    },
}


def vulnerable_package(**fields):
    return {
        "name": "axios",
        "version": "0.21.4",
        "packageManager": "NODE",
        "fixedInVersion": "1.6.0",
        "filePath": "/var/task/node_modules/axios/package.json",
        **fields,
    }


def raw_finding(severity="HIGH", packages=None, **fields):
    return {
        "awsAccountId": "111122223333",
        "description": "A vulnerability",
        "findingArn": "arn:aws:inspector2:us-east-1:111122223333:finding/one",
        "firstObservedAt": NOW,
        "lastObservedAt": NOW,
        "remediation": {"recommendation": {"text": "Upgrade"}},
        "severity": severity,
        "status": "ACTIVE",
        "type": "PACKAGE_VULNERABILITY",
        "title": "CVE-2024-0001 - axios",
        "fixAvailable": "YES",
        "exploitAvailable": "NO",
        "packageVulnerabilityDetails": {
            "source": "NVD",
            "vulnerabilityId": "CVE-2024-0001",
            "vulnerablePackages": packages or [vulnerable_package()],
        },
        "resources": [LAMBDA_RESOURCE],
        **fields,
    }


def test_sight_finding_reads_a_lambda_finding():
    got = sight_finding(raw_finding(firstObservedAt="2026-11-01T12:00:00Z", exploitAvailable="YES"))
    assert got == Finding(
        arn="arn:aws:inspector2:us-east-1:111122223333:finding/one",
        vulnerability_id="CVE-2024-0001",
        severity="high",
        package="axios",
        package_manager="NODE",
        installed_version="0.21.4",
        fixed_in="1.6.0",
        fix_available=True,
        exploit_available=True,
        first_observed=NOW,
        title="CVE-2024-0001 - axios",
        resource=InspectorResource(
            ResourceType.LAMBDA,
            "arn:aws:lambda:us-east-1:111122223333:function:api-dev-handler",
            "api-dev-handler",
            "us-east-1",
            {STACK: "api-dev"},
        ),
    )


def test_sight_finding_names_ecr_images_by_repository_and_ec2_instances_by_id():
    ecr = {
        "type": "AWS_ECR_CONTAINER_IMAGE",
        "id": "arn:aws:ecr:us-east-1:111122223333:repository/sst-asset/sha256:0",
        "region": "us-east-1",
        "details": {
            "awsEcrContainerImage": {
                "repositoryName": "sst-asset",
                "imageHash": "sha256:0",
                "registry": "111122223333",
            }
        },
    }
    ec2 = {
        "type": "AWS_EC2_INSTANCE",
        "id": "i-0abc",
        "region": "us-east-1",
        "tags": {STACK: "api-dev"},
        "details": {"awsEc2Instance": {"type": "t3.small"}},
    }
    got_ecr = sight_finding(raw_finding(resources=[ecr]))
    got_ec2 = sight_finding(raw_finding(resources=[ec2]))
    assert (got_ecr.resource.type, got_ecr.resource.name) == (ResourceType.ECR_IMAGE, "sst-asset")
    assert dict(got_ecr.resource.tags) == {}
    assert (got_ec2.resource.type, got_ec2.resource.name) == (ResourceType.EC2, "i-0abc")
    assert dict(got_ec2.resource.tags) == {STACK: "api-dev"}


WITHOUT_FIXED_VERSION = {
    field: value for field, value in vulnerable_package().items() if field != "fixedInVersion"
}


@pytest.mark.parametrize(
    ("package", "fix", "fixed_in", "fix_available"),
    [
        (vulnerable_package(), "YES", "1.6.0", True),
        (vulnerable_package(fixedInVersion="NotAvailable"), "NO", None, False),
        (WITHOUT_FIXED_VERSION, "PARTIAL", None, True),
    ],
)
def test_sight_finding_reads_fix_availability(package, fix, fixed_in, fix_available):
    got = sight_finding(raw_finding(packages=[package], fixAvailable=fix))
    assert (got.fixed_in, got.fix_available) == (fixed_in, fix_available)


def test_sight_finding_keeps_only_the_first_vulnerable_package():
    packages = [vulnerable_package(name="first"), vulnerable_package(name="second")]
    assert sight_finding(raw_finding(packages=packages)).package == "first"


@pytest.mark.parametrize("severity", ["INFORMATIONAL", "UNTRIAGED"])
def test_sight_finding_drops_severities_outside_the_report(severity):
    assert sight_finding(raw_finding(severity=severity)) is None


def test_sight_finding_drops_unknown_resource_types():
    unknown = {**LAMBDA_RESOURCE, "type": "CODE_REPOSITORY"}
    assert sight_finding(raw_finding(resources=[unknown])) is None


@pytest.mark.parametrize("finding_type", ["NETWORK_REACHABILITY", "CODE_VULNERABILITY"])
def test_sight_finding_drops_findings_that_are_not_package_vulnerabilities(finding_type):
    raw = raw_finding(type=finding_type)
    del raw["packageVulnerabilityDetails"]
    assert sight_finding(raw) is None


# --- live source


class StubSession:
    def __init__(self, client):
        self._client = client

    def client(self, service, region_name):
        assert (service, region_name) == ("inspector2", "us-east-1")
        return self._client


def inspector_client():
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1"
    )
    return session.client("inspector2")


def test_aws_inspector_filters_by_severity_and_follows_pages():
    request = {
        "filterCriteria": {
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
            "severity": [
                {"comparison": "EQUALS", "value": "CRITICAL"},
                {"comparison": "EQUALS", "value": "HIGH"},
            ],
            "resourceType": [
                {"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"},
                {"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"},
                {"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"},
            ],
        },
        "maxResults": 100,
    }
    first = raw_finding()
    second = raw_finding(severity="CRITICAL", findingArn="arn:aws:inspector2:::finding/two")
    client = inspector_client()
    with Stubber(client) as stubber:
        stubber.add_response("list_findings", {"findings": [first], "nextToken": "page-2"}, request)
        stubber.add_response(
            "list_findings", {"findings": [second]}, {**request, "nextToken": "page-2"}
        )
        found = AwsInspector(StubSession(client), ["us-east-1"], "high").findings()
        stubber.assert_no_pending_responses()
    assert [(finding.arn, finding.severity) for finding in found] == [
        (first["findingArn"], "high"),
        (second["findingArn"], "critical"),
    ]


def test_aws_inspector_wraps_aws_errors_in_scan_error():
    client = inspector_client()
    with Stubber(client) as stubber:
        stubber.add_client_error("list_findings", "AccessDeniedException")
        with pytest.raises(ScanError, match="Inspector scan failed"):
            AwsInspector(StubSession(client), ["us-east-1"], "high").findings()


# --- config


def test_inspector_config_defaults_and_validation():
    config = parse_config({"org": "acme"}).inspector
    assert config == InspectorConfig(["us-east-1"], "high", [], [])
    labelled = parse_config({"org": "acme", "inspector": {"linear_labels": ["security"]}})
    assert labelled.inspector == InspectorConfig(linear_labels=["security"])
    with pytest.raises(ValueError, match="inspector.min_severity must be one of"):
        parse_config({"org": "acme", "inspector": {"min_severity": "urgent"}})
    with pytest.raises(ValueError, match="Unknown keys in 'inspector': enabled"):
        parse_config({"org": "acme", "inspector": {"enabled": True}})


# --- CLI


def example_config(tmp_path, inspector=None):
    config = yaml.safe_load((EXAMPLES / "vulgard.yml").read_text())
    config["inspector"] = {**config.get("inspector", {}), **(inspector or {})}
    path = tmp_path / "vulgard.yml"
    path.write_text(yaml.safe_dump(config))
    return path


def report_json(tmp_path, capsys, inspector=None, *extra):
    config = example_config(tmp_path, inspector)
    fixtures = ["--fixtures", str(EXAMPLES / "demo-org.json"), "--config", str(config)]
    assert main([*fixtures, "report", "--topic", "inspector", "--format", "json", *extra]) == 0
    return json.loads(capsys.readouterr().out)


def vulnerabilities(groups):
    return [(group["vulnerability_id"], group["resources"]) for group in groups]


def test_report_attributes_the_demo_findings_to_repos(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    assert report["via"] == {"tag": 0, "deployment": 7}
    assert {repo: vulnerabilities(groups) for repo, groups in report["repos"].items()} == {
        "inventory-service": [
            ("CVE-2023-26115", ["inventory-production-ReorderFunction"]),
            ("CVE-2024-21534", ["inventory-production-ReorderFunction"]),
            ("CVE-2024-45296", ["inventory-production-ReorderFunction"]),
        ],
        "payments-api": [
            (
                "CVE-2022-23539",
                ["payments-api-production-authorize", "payments-api-production-refund"],
            ),
            ("CVE-2023-45857", ["payments-api-dev-createOrder"]),
            ("CVE-2024-25062", ["serverless-payments-api-production"]),
        ],
    }
    unattributed = report["unattributed"]
    assert {reason: vulnerabilities(groups) for reason, groups in unattributed.items()} == {
        "shared_asset_repository": [("CVE-2024-21538", ["sst-asset"])],
        "no_deployment_tags": [("CVE-2024-4068", ["orphan-handler"])],
    }


def test_report_json_says_how_each_finding_was_attributed(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    jsonwebtoken = report["repos"]["payments-api"][0]
    assert (jsonwebtoken["severity"], jsonwebtoken["exploit_available"]) == ("critical", True)
    assert (jsonwebtoken["fix_available"], jsonwebtoken["fixed_in"]) == (True, "9.0.0")
    attributions = {
        (finding["resource"]["name"], finding["via"], finding["deployment"])
        for finding in jsonwebtoken["findings"]
    }
    assert attributions == {
        ("payments-api-production-authorize", "deployment", "payments-api-production"),
        ("payments-api-production-refund", "deployment", "payments-api-production"),
    }
    unattributed = report["unattributed"]["no_deployment_tags"][0]["findings"][0]
    assert "via" not in unattributed and unattributed["resource"]["tags"] == {}


def test_report_drops_findings_below_min_severity_and_informational_ones(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    seen = {group["vulnerability_id"] for groups in report["repos"].values() for group in groups}
    assert not {"CVE-2021-23566", "CVE-2023-26136"} & seen


def test_min_severity_low_adds_the_low_finding_but_never_the_informational_one(tmp_path, capsys):
    report = report_json(tmp_path, capsys, {"min_severity": "low"})
    seen = {group["vulnerability_id"] for groups in report["repos"].values() for group in groups}
    assert "CVE-2021-23566" in seen and "CVE-2023-26136" not in seen
    assert report["repos"]["payments-api"][-1]["severity"] == "low"


def test_inspector_ignore_config_drops_matching_resources(tmp_path, capsys):
    report = report_json(tmp_path, capsys, {"ignore": ["payments-api-production-*"]})
    seen = {group["vulnerability_id"] for groups in report["repos"].values() for group in groups}
    assert "CVE-2022-23539" not in seen and "CVE-2023-45857" in seen


def test_repo_scope_keeps_only_that_repo(tmp_path, capsys):
    report = report_json(tmp_path, capsys, None, "--repo", "inventory-service")
    assert list(report["repos"]) == ["inventory-service"]
    assert report["unattributed"] == {}
    assert report["via"] == {"tag": 0, "deployment": 3}


def test_report_table_lists_repos_worst_first_then_the_unattributed(capsys):
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    rows = [line.split() for line in out.splitlines()]
    assert ["payments-api", "1", "2", "0", "0", "1", "3", "4"] in rows
    assert ["inventory-service", "0", "3", "0", "0", "0", "3", "1"] in rows
    assert ["unattributed:", "shared_asset_repository", "0", "1", "0", "0", "0", "1", "1"] in rows
    assert ["unattributed:", "no_deployment_tags", "0", "1", "0", "0", "0", "1", "1"] in rows
    order = [out.index(name) for name in ("payments-api", "inventory-service", "unattributed")]
    assert order == sorted(order)
    assert "9 finding(s) in 8 group(s) at high or above" in out


def test_report_table_says_so_when_nothing_matches(capsys):
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector", "--repo", "nope"]) == 0
    assert capsys.readouterr().out.strip() == "No Inspector findings at high or above."


def test_nag_has_no_inspector_topic(capsys):
    with pytest.raises(SystemExit) as stopped:
        main([*FIXTURE_ARGS, "nag", "--topic", "inspector"])
    assert stopped.value.code == 2
    assert "invalid choice: 'inspector'" in capsys.readouterr().err


def test_a_failing_inspector_scan_is_a_one_line_error(monkeypatch, capsys):
    def throttled(self):
        raise ScanError("Inspector scan failed: throttled")

    monkeypatch.setattr(FixtureInspector, "findings", throttled)
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector"]) == 1
    assert capsys.readouterr().err == "error: Inspector scan failed: throttled\n"


def test_report_json_gives_every_demo_status_with_what_covers_it(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    assert report["coverage"] == {
        "dependabot_alert": 2,
        "dependabot_pr": 1,
        "fixed_not_deployed": 1,
        "linear_issue": 1,
        "untracked_os_package": 1,
        "untracked": 2,
    }
    groups = {
        group["vulnerability_id"]: group
        for found in [*report["repos"].values(), *report["unattributed"].values()]
        for group in found
    }
    assert groups["CVE-2022-23539"]["alert"] == {
        "number": 12,
        "state": "open",
        "url": "https://github.com/acme/payments-api/security/dependabot/12",
    }
    assert groups["CVE-2022-23539"]["pr"] == {
        "number": 88,
        "url": "https://github.com/acme/payments-api/pull/88",
    }
    assert groups["CVE-2023-26115"]["coverage"] == "fixed_not_deployed"
    assert groups["CVE-2023-26115"]["alert"]["state"] == "fixed"
    assert groups["CVE-2024-21534"]["coverage"] == "dependabot_pr"
    assert groups["CVE-2024-45296"]["linear_issues"] == [
        {"identifier": "SEC-201", "url": "https://linear.app/acme/issue/SEC-201"}
    ]
    assert groups["CVE-2024-25062"]["coverage"] == "untracked_os_package"
    assert groups["CVE-2024-4068"]["coverage"] == "untracked"
    assert groups["CVE-2024-4068"]["linear_issues"] == []


def test_report_table_counts_groups_by_coverage_status(capsys):
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    rows = [line.split() for line in out.splitlines()]
    assert ["repo", *(status.value for status in Coverage)] in rows
    assert ["payments-api", "2", "0", "0", "0", "1", "0"] in rows
    assert ["inventory-service", "0", "1", "1", "1", "0", "0"] in rows
    assert ["unattributed:", "no_deployment_tags", "0", "0", "0", "0", "0", "1"] in rows
    assert "Linear issues were not checked" not in out


def test_without_linear_labels_the_table_says_linear_was_not_checked(tmp_path, capsys):
    config = example_config(tmp_path, {"linear_labels": []})
    fixtures = ["--fixtures", str(EXAMPLES / "demo-org.json"), "--config", str(config)]
    assert main([*fixtures, "report", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    assert "Linear issues were not checked" in out
    assert ["inventory-service", "0", "1", "1", "0", "0", "1"] in [
        line.split() for line in out.splitlines()
    ]
