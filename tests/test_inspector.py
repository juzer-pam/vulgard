from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.stub import Stubber

from vulgard.aws import (
    AwsInspector,
    latest_revisions,
    sight_finding,
    sight_lambda_runner,
    sight_task_definition_runners,
)
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
from vulgard.fixtures import FixtureInspector
from vulgard.inspector import (
    Attributed,
    Finding,
    FixItem,
    FixStatus,
    ImageRef,
    ImageRunner,
    InspectorResource,
    Reason,
    ResourceType,
    RunnerKind,
    Unattributed,
    Via,
    branch_dependencies,
    build_report,
    fix_items,
    parse_image,
)
from vulgard.policy import DependabotPR

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


def shared_image(repository="sst-asset", digest="sha256:aa", image_tags=()):
    return InspectorResource(
        ResourceType.ECR_IMAGE,
        f"arn:aws:ecr:::repository/{repository}/{digest}",
        repository,
        "us-east-1",
        {},
        digest,
        image_tags,
    )


def lambda_runner(name="worker", tags=None, repository="sst-asset", digest="sha256:aa"):
    return ImageRunner(
        RunnerKind.LAMBDA,
        name,
        "us-east-1",
        ImageRef("us-east-1", repository, digest, None),
        tags or {},
    )


def task_runner(family="web", tags=None, repository="sst-asset", digest=None, tag="v1"):
    return ImageRunner(
        RunnerKind.ECS_TASK_DEFINITION,
        family,
        "us-east-1",
        ImageRef("us-east-1", repository, digest, None if digest else tag),
        tags or {},
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
    report = build_report([finding], DEPLOYMENTS, InspectorConfig(), None, {}, {})
    assert report.attributions == {finding.arn: expected}
    if isinstance(expected, Attributed):
        placed = report.by_repo[expected.repo]
    else:
        placed = report.unattributed[expected.reason]
    assert [item.findings for item in placed] == [(finding,)]


def test_a_stack_name_in_two_regions_attributes_to_the_resource_region():
    west = deployment(CfnStack("1", "us-west-2", "api-dev", "id-west"), "api-west")
    resource = InspectorResource(
        ResourceType.LAMBDA, "arn:west", "api-dev-handler", "us-west-2", {STACK: "api-dev"}
    )
    finding = make_finding(resource)
    report = build_report([finding], [API_DEV, west], InspectorConfig(), None, {}, {})
    assert report.attributions[finding.arn].repo == "api-west"


def test_via_counts_how_findings_were_attributed():
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b", {"repo": "payments"})),
        make_finding(function("c", {"Repo": "payments"})),
    ]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), None, {}, {})
    assert report.via == Counter({Via.DEPLOYMENT: 1, Via.TAG: 2})


# --- fix items, severity, ignore and scope

API_FUNCTIONS = [function(f"fn-{name}", {STACK: "api-dev"}) for name in "abc"]


def test_findings_of_one_package_are_one_item_across_vulnerabilities_and_resources():
    first, second, third = API_FUNCTIONS
    found = [
        make_finding(first, "CVE-1", severity="high", fixed_in="1.9.0"),
        make_finding(second, "CVE-1", severity="high", fixed_in="1.9.0"),
        make_finding(
            third, "CVE-2", severity="critical", exploit_available=True, fixed_in="1.10.0"
        ),
        make_finding(first, "CVE-3", package="lodash"),
    ]
    items = build_report(found, DEPLOYMENTS, InspectorConfig(), None, {}, {}).by_repo["api"]
    assert [
        (item.package, item.ecosystem, item.severity, item.fixed_in, item.exploit_available)
        for item in items
    ] == [("axios", "npm", "critical", "1.10.0", True), ("lodash", "npm", "high", "1.0.1", False)]
    assert items[0].vulnerability_ids == ["CVE-1", "CVE-2"]
    assert items[0].resources == ["fn-a", "fn-b", "fn-c"]
    assert len(items[0].findings) == 3


def test_a_finding_without_a_fixed_version_makes_the_required_version_unknown():
    first, second, _ = API_FUNCTIONS
    found = [
        make_finding(first, "CVE-1", fixed_in="1.0.1"),
        make_finding(second, "CVE-2", fixed_in=None),
    ]
    assert fix_items(found, (), None)[0].fixed_in is None


def test_items_are_sorted_by_severity_then_exploit_then_resources_then_package():
    first, second, _ = API_FUNCTIONS
    found = [
        make_finding(first, package="aaa"),
        make_finding(first, package="bbb", exploit_available=True),
        make_finding(first, package="ccc"),
        make_finding(second, package="ccc"),
        make_finding(first, package="zzz", severity="critical"),
    ]
    assert [item.package for item in fix_items(found, (), None)] == ["zzz", "bbb", "ccc", "aaa"]


def test_an_os_package_and_an_application_package_of_one_name_are_separate_items():
    found = [
        make_finding(API_FUNCTIONS[0], package="openssl", package_manager="OS"),
        make_finding(API_FUNCTIONS[0], package="openssl", package_manager="NODE"),
    ]
    assert {item.ecosystem: item.status for item in fix_items(found, (), None)} == {
        None: FixStatus.NEEDS_OS_UPDATE,
        "npm": FixStatus.UNKNOWN,
    }


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
    found = [
        make_finding(on, f"CVE-{severity}", f"pkg-{severity}", severity=severity)
        for severity in SEVERITIES
    ]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(min_severity=minimum), None, {}, {})
    assert [item.severity for item in report.by_repo["api"]] == kept


def test_ignore_drops_findings_by_resource_name_or_stack_tag():
    kept = function("worker", {STACK: "api-dev"})
    by_name = function("scratch-handler", {STACK: "api-dev"})
    by_stack = function("handler", {STACK: "scratch-stack"})
    found = [make_finding(on) for on in (kept, by_name, by_stack)]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(ignore=["scratch-*"]), None, {}, {})
    assert [item.resources for item in report.by_repo["api"]] == [["worker"]]
    assert report.unattributed == {} and len(report.attributions) == 1


def test_only_keeps_those_repos_and_drops_the_unattributed():
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b", {"sst:app": "inventory", "sst:stage": "prod"})),
        make_finding(function("c")),
    ]
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), {"inventory"}, {}, {})
    assert list(report.by_repo) == ["inventory"]
    assert report.unattributed == {}
    assert len(report.attributions) == 1


# --- attribution through what runs an image


def attributed_through(on, *runners):
    finding = make_finding(on)
    report = build_report([finding], DEPLOYMENTS, InspectorConfig(), None, {}, {}, runners)
    return report.attributions[finding.arn]


def test_an_image_a_lambda_function_runs_takes_the_functions_repo_tag():
    runner = lambda_runner(tags={"github:repo": "acme/payments"})
    assert attributed_through(shared_image(), runner) == Attributed(
        "payments", Via.TAG, runner=runner
    )


def test_an_image_a_lambda_function_runs_takes_the_repo_of_the_functions_stack():
    runner = lambda_runner(tags={STACK: "api-dev"})
    assert attributed_through(shared_image(), runner) == Attributed(
        "api", Via.DEPLOYMENT, "api-dev", runner
    )


def test_an_image_in_a_cdk_repository_takes_the_repo_of_the_runner_found_by_sst_tags():
    repository = "cdk-hnb659fds-container-assets-111122223333-us-east-1"
    tags = {"sst:app": "inventory", "sst:stage": "prod"}
    runner = lambda_runner(tags=tags, repository=repository)
    assert attributed_through(shared_image(repository), runner) == Attributed(
        "inventory", Via.DEPLOYMENT, "inventory/prod", runner
    )


def test_an_image_a_task_definition_names_by_digest_takes_that_services_repo():
    runner = task_runner(tags={STACK: "api-dev"}, digest="sha256:aa")
    assert attributed_through(shared_image(digest="sha256:aa"), runner) == Attributed(
        "api", Via.DEPLOYMENT, "api-dev", runner
    )


def test_an_image_a_task_definition_names_by_tag_is_found_by_any_of_its_tags():
    runner = task_runner(tags={"vulgard:repo": "worker-repo"}, tag="d41d8")
    on = shared_image(digest="sha256:bb", image_tags=("other", "d41d8"))
    assert attributed_through(on, runner) == Attributed("worker-repo", Via.TAG, runner=runner)


def test_an_image_nothing_runs_stays_in_the_shared_asset_repository():
    runners = [
        lambda_runner(tags={STACK: "api-dev"}, digest="sha256:other"),
        task_runner(tags={STACK: "api-dev"}, tag="other"),
        lambda_runner(tags={STACK: "api-dev"}, repository="cdk-assets"),
    ]
    on = shared_image(digest="sha256:aa", image_tags=("v2",))
    assert attributed_through(on, *runners) == Unattributed(Reason.SHARED_ASSET_REPOSITORY)
    assert attributed_through(on) == Unattributed(Reason.SHARED_ASSET_REPOSITORY)


def test_a_runner_in_another_region_does_not_run_the_image():
    elsewhere = ImageRunner(
        RunnerKind.LAMBDA,
        "worker",
        "eu-west-1",
        ImageRef("eu-west-1", "sst-asset", "sha256:aa", None),
        {STACK: "api-dev"},
    )
    assert attributed_through(shared_image(), elsewhere) == Unattributed(
        Reason.SHARED_ASSET_REPOSITORY
    )


def test_an_image_in_a_repository_that_is_not_shared_is_not_traced():
    runner = lambda_runner(tags={STACK: "api-dev"}, repository="my-service")
    assert attributed_through(shared_image("my-service"), runner) == Unattributed(
        Reason.NO_DEPLOYMENT_TAGS
    )


def test_a_runner_that_names_no_repo_is_ignored_when_another_does():
    nameless = lambda_runner("a-untagged")
    unknown = lambda_runner("b-gone", {STACK: "gone"})
    unowned = lambda_runner("c-legacy", {STACK: "legacy-staging"})
    named = lambda_runner("d-api", {STACK: "api-dev"})
    assert attributed_through(shared_image(), nameless, unknown, unowned, named) == Attributed(
        "api", Via.DEPLOYMENT, "api-dev", named
    )
    assert attributed_through(shared_image(), nameless, unknown, unowned) == Unattributed(
        Reason.SHARED_ASSET_REPOSITORY
    )


def test_runners_in_different_repos_leave_the_image_unattributed():
    in_api = lambda_runner("a", {STACK: "api-dev"})
    in_inventory = task_runner(
        "b", {"sst:app": "inventory", "sst:stage": "prod"}, digest="sha256:aa"
    )
    assert attributed_through(shared_image(), in_api, in_inventory) == Unattributed(
        Reason.RUNNERS_IN_SEVERAL_REPOS
    )


def test_runners_in_one_repo_report_the_first_by_kind_then_name():
    function_b = lambda_runner("b", {STACK: "api-dev"})
    function_a = lambda_runner("a", {"github:repo": "api"})
    task = task_runner("z", {STACK: "api-dev"}, digest="sha256:aa")
    assert attributed_through(shared_image(), function_b, function_a) == Attributed(
        "api", Via.TAG, runner=function_a
    )
    assert attributed_through(shared_image(), function_b, function_a, task) == Attributed(
        "api", Via.DEPLOYMENT, "api-dev", task
    )


def test_a_runner_is_only_used_for_images_in_shared_repositories():
    runner = lambda_runner(tags={STACK: "api-dev"})
    on = function(tags={"sst:app": "inventory", "sst:stage": "prod"})
    got = attributed_through(on, runner)
    assert got == Attributed("inventory", Via.DEPLOYMENT, "inventory/prod")


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (
            "111122223333.dkr.ecr.us-east-1.amazonaws.com/sst-asset@sha256:ab12",
            ImageRef("us-east-1", "sst-asset", "sha256:ab12", None),
        ),
        (
            "111122223333.dkr.ecr.eu-west-1.amazonaws.com/team/app:v1",
            ImageRef("eu-west-1", "team/app", None, "v1"),
        ),
        (
            "111122223333.dkr.ecr.us-east-1.amazonaws.com/app",
            ImageRef("us-east-1", "app", None, "latest"),
        ),
        (
            "111122223333.dkr.ecr.us-east-1.amazonaws.com/app:v1@sha256:ab12",
            ImageRef("us-east-1", "app", "sha256:ab12", None),
        ),
        ("public.ecr.aws/nginx/nginx:1.27", None),
        ("nginx:latest", None),
        ("", None),
    ],
)
def test_parse_image_reads_ecr_images_and_ignores_the_rest(uri, expected):
    assert parse_image(uri) == expected


# --- fix status

GROUPED_BODY = """Bumps the npm_and_yarn group with 2 updates in the / directory:

| Package | From | To |
| --- | --- | --- |
| [axios](https://github.com/axios/axios) | `1.0.0` | `1.6.0` |
| [@babel/traverse](https://github.com/babel/babel) | `7.22.0` | `7.23.2` |

Updates `axios` from 1.0.0 to 1.6.0
"""


def bump(package="axios", to="1.0.1", number=7, repo="api", body=""):
    return DependabotPR.from_api(
        {
            "number": number,
            "title": f"Bump {package} from 1.0.0 to {to}",
            "html_url": f"https://github.com/acme/{repo}/pull/{number}",
            "repository_url": f"https://api.github.com/repos/acme/{repo}",
            "created_at": "2026-10-20T00:00:00Z",
            "body": body,
        }
    )


def grouped(body, number=8, repo="api"):
    pr = bump(number=number, repo=repo, body=body)
    pr.title = "Bump the npm group with 2 updates"
    return pr


def sbom(*packages):
    """An SPDX dependency graph: the repo itself, then (purl type, name, version) packages."""
    return {
        "sbom": {
            "packages": [
                {"name": "com.github.acme/api", "versionInfo": "main"},
                *(
                    {
                        "name": name,
                        "versionInfo": version,
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": f"pkg:{kind}/x@{version}"}
                        ],
                    }
                    for kind, name, version in packages
                ),
            ]
        }
    }


def test_branch_dependencies_reads_purl_types_and_skips_packages_without_one():
    got = branch_dependencies(sbom(("npm", "@acme/ui", "1.2.3"), ("maven", "org.x:core", "2.0")))
    assert got.versions == {
        ("npm", "@acme/ui"): frozenset({"1.2.3"}),
        ("maven", "org.x:core"): frozenset({"2.0"}),
    }
    assert got.ecosystems == {"npm", "maven"}


AXIOS_OLD = ("npm", "axios", "0.21.4")
MANAGERS = {"python-dateutil": "PYTHON", "log4j-core": "JAVA"}

STATUS_CASES = [
    pytest.param(
        [("npm", "react", "18.0.0")], "axios", "1.0.1", [], FixStatus.NEEDS_DEPLOY, id="gone"
    ),
    pytest.param(
        [("npm", "react", "18.0.0")], "axios", None, [], FixStatus.NEEDS_DEPLOY, id="gone-no-fix"
    ),
    pytest.param(
        [("npm", "axios", "1.20.0")], "axios", "1.0.1", [], FixStatus.NEEDS_DEPLOY, id="past-fix"
    ),
    pytest.param(
        [("npm", "axios", "1.0.1")], "axios", "1.0.1", [], FixStatus.NEEDS_DEPLOY, id="at-fix"
    ),
    pytest.param(
        [("npm", "axios", "2")], "axios", "2.0.0", [], FixStatus.NEEDS_DEPLOY,
        id="at-fix-written-shorter",
    ),
    pytest.param(
        [("npm", "axios", "1.20.0"), ("npm", "axios", "1.0.1")],
        "axios", "1.0.1", [], FixStatus.NEEDS_DEPLOY, id="every-copy-at-or-past-fix",
    ),
    pytest.param(
        [("pypi", "Python_Dateutil", "2.9.0")],
        "python-dateutil", "2.8.1", [], FixStatus.NEEDS_DEPLOY, id="pypi-names-normalize",
    ),
    pytest.param(
        [("npm", "axios", "1.20.0"), AXIOS_OLD], "axios", "1.0.1", [], FixStatus.NEEDS_FIX,
        id="an-old-copy-remains",
    ),
    pytest.param([AXIOS_OLD], "axios", "1.0.1", [], FixStatus.NEEDS_FIX, id="vulnerable-no-pr"),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [bump(package="lodash")], FixStatus.NEEDS_FIX,
        id="a-pr-for-another-package",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [bump(to="0.22.0")], FixStatus.NEEDS_FIX,
        id="a-pr-to-a-lower-version",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [bump(to="1.0.1")], FixStatus.NEEDS_PR_MERGE,
        id="pr-to-the-fixed-version",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [bump(to="2.0.0")], FixStatus.NEEDS_PR_MERGE,
        id="pr-past-the-fixed-version",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [grouped(GROUPED_BODY)], FixStatus.NEEDS_PR_MERGE,
        id="grouped-pr-through-its-table",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [grouped("Removes `axios`\n")], FixStatus.NEEDS_PR_MERGE,
        id="pr-removing-the-package",
    ),
    pytest.param(
        None, "axios", "1.0.1", [bump(to="1.0.1")], FixStatus.NEEDS_PR_MERGE,
        id="pr-without-a-dependency-graph",
    ),
    pytest.param(None, "axios", "1.0.1", [], FixStatus.UNKNOWN, id="no-dependency-graph"),
    pytest.param(
        [("npm", "react", "18.0.0")], "log4j-core", "2.17.1", [], FixStatus.UNKNOWN,
        id="ecosystem-not-on-branch",
    ),
    pytest.param(
        [("npm", "axios", "2.0.0")], "axios", None, [], FixStatus.UNKNOWN, id="no-fixed-version"
    ),
    pytest.param(
        [AXIOS_OLD], "axios", None, [bump(to="1.0.1")], FixStatus.UNKNOWN,
        id="no-fixed-version-and-a-pr-that-only-bumps",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", None, [grouped("Removes `axios`\n")], FixStatus.NEEDS_PR_MERGE,
        id="no-fixed-version-and-a-pr-that-removes",
    ),
    pytest.param(
        [("npm", "axios", "latest")], "axios", "1.0.1", [], FixStatus.UNKNOWN,
        id="unparsable-branch-version",
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "unspecified", [], FixStatus.UNKNOWN, id="unparsable-fixed-version"
    ),
    pytest.param(
        [AXIOS_OLD], "axios", "1.0.1", [bump(to="main")], FixStatus.UNKNOWN,
        id="unparsable-pr-target",
    ),
]


def item_for(graph, package, fixed_in, prs, manager="NODE"):
    finding = make_finding(
        API_FUNCTIONS[0], package=package, package_manager=manager, fixed_in=fixed_in
    )
    branch = branch_dependencies(sbom(*graph)) if graph is not None else None
    (item,) = fix_items([finding], prs, branch)
    return item


@pytest.mark.parametrize(("graph", "package", "fixed_in", "prs", "expected"), STATUS_CASES)
def test_each_fix_item_gets_the_first_status_that_holds(graph, package, fixed_in, prs, expected):
    manager = MANAGERS.get(package, "NODE")
    assert item_for(graph, package, fixed_in, prs, manager).status is expected


def test_an_os_package_needs_an_os_update_whatever_the_branch_has():
    item = item_for([("npm", "openssl", "1.0.0")], "openssl", "3.0.9", [bump("openssl")], "OS")
    assert (item.status, item.ecosystem, item.main_versions, item.pr) == (
        FixStatus.NEEDS_OS_UPDATE,
        None,
        frozenset(),
        None,
    )


def test_main_versions_are_what_the_default_branch_has_and_empty_when_gone():
    old = item_for([AXIOS_OLD, ("npm", "axios", "1.20.0")], "axios", "1.0.1", [])
    assert (old.status, old.main_versions) == (FixStatus.NEEDS_FIX, {"0.21.4", "1.20.0"})
    past = item_for([("npm", "axios", "1.20.0")], "axios", "1.0.1", [])
    assert (past.status, past.main_versions) == (FixStatus.NEEDS_DEPLOY, {"1.20.0"})
    gone = item_for([("npm", "react", "18.0.0")], "axios", "1.0.1", [])
    assert (gone.status, gone.main_versions) == (FixStatus.NEEDS_DEPLOY, frozenset())


def test_a_pr_needing_merge_is_the_lowest_numbered_one_that_fixes_the_item():
    weak, strong, other = bump(to="0.22.0", number=3), bump(number=9), bump(number=5)
    item = item_for([AXIOS_OLD], "axios", "1.0.1", [strong, weak, other])
    assert (item.status, item.pr) == (FixStatus.NEEDS_PR_MERGE, other)
    assert item.pr_target == "1.0.1"


def test_a_pr_that_removes_the_package_has_no_target():
    item = item_for([AXIOS_OLD], "axios", "1.0.1", [grouped("Removes `axios`\n")])
    assert (item.status, item.pr_target) == (FixStatus.NEEDS_PR_MERGE, None)


def test_build_report_gives_each_repo_its_own_pull_requests_and_dependencies():
    found = [
        make_finding(function("a", {STACK: "api-dev"})),
        make_finding(function("b", {"sst:app": "inventory", "sst:stage": "prod"})),
    ]
    prs = {"api": [bump()], "inventory": [bump(repo="inventory", to="0.1.0")]}
    branches = {"inventory": branch_dependencies(sbom(("npm", "axios", "1.0.1")))}
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), None, prs, branches)
    assert report.by_repo["api"][0].status is FixStatus.NEEDS_PR_MERGE
    assert report.by_repo["inventory"][0].status is FixStatus.NEEDS_DEPLOY
    assert report.status == Counter({FixStatus.NEEDS_PR_MERGE: 1, FixStatus.NEEDS_DEPLOY: 1})


def test_unattributed_items_have_no_repo_to_look_in_so_only_need_an_os_update_or_are_unknown():
    found = [
        make_finding(function("a"), package="axios"),
        make_finding(function("b"), "CVE-2024-0002", package="openssl", package_manager="OS"),
    ]
    prs = {"api": [bump()]}
    branches = {"api": branch_dependencies(sbom(("npm", "react", "18.0.0")))}
    report = build_report(found, DEPLOYMENTS, InspectorConfig(), None, prs, branches)
    unattributed = report.unattributed[Reason.NO_DEPLOYMENT_TAGS]
    statuses = {item.package: item.status for item in unattributed}
    assert statuses == {"axios": FixStatus.UNKNOWN, "openssl": FixStatus.NEEDS_OS_UPDATE}


def a_fix_item(status, pr):
    return FixItem("axios", "npm", "high", "1.0.1", (), status, frozenset(), pr)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(lambda: a_fix_item(FixStatus.NEEDS_PR_MERGE, None), id="merge-without-a-pr"),
        *(
            pytest.param(lambda status=status: a_fix_item(status, bump()), id=f"{status}-with-a-pr")
            for status in FixStatus
            if status is not FixStatus.NEEDS_PR_MERGE
        ),
    ],
)
def test_a_fix_item_has_a_pr_exactly_when_it_needs_one_merged(bad):
    with pytest.raises(AssertionError):
        bad()


def test_a_fix_item_that_needs_a_merge_carries_its_pr():
    pr = bump()
    assert a_fix_item(FixStatus.NEEDS_PR_MERGE, pr).pr is pr


# --- Dependabot pull request updates


def test_updates_read_the_target_from_a_single_package_title():
    pr = bump("lodash", to="4.17.21")
    pr.title = "Bump Lodash from 4.17.20 to 4.17.21 in /app"
    assert pr.updates == {"lodash": "4.17.21"}


def test_updates_read_a_grouped_pr_from_its_table_and_update_lines():
    assert grouped(GROUPED_BODY).updates == {"axios": "1.6.0", "@babel/traverse": "7.23.2"}


def test_updates_read_removals_as_no_target():
    body = "Removes [zod](https://x).\n\nRemoves `zod`\n\nUpdates `next` from 13.4.4 to 13.5.11\n"
    pr = bump(body=body)
    pr.title = "Bump zod and next in /frontend"
    assert pr.updates == {"zod": None, "next": "13.5.11"}


def test_updates_ignore_a_table_inside_release_notes():
    body = (
        "Bumps [lodash](https://x) from 4.17.20 to 4.17.21.\n"
        "<details>\n<summary>Release notes</summary>\n"
        "| [minimist](https://x) | `1.2.5` | `1.2.6` |\n</details>\n"
    )
    assert bump("lodash", to="4.17.21", body=body).updates == {"lodash": "4.17.21"}


def test_updates_lowercase_names_and_packages_are_the_same_names():
    pr = grouped("| [Pillow](https://x) | `9.0.0` | `10.0.1` |\n")
    assert pr.updates == {"pillow": "10.0.1"}
    assert pr.packages == {"pillow"}


def test_a_body_that_only_mentions_a_package_updates_nothing():
    assert grouped("Release notes: fixes a bug reported against `lodash`.\n").updates == {}


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


def test_sight_finding_keeps_the_digest_and_tags_of_an_ecr_image():
    ecr = {
        "type": "AWS_ECR_CONTAINER_IMAGE",
        "id": "arn:aws:ecr:us-east-1:111122223333:repository/sst-asset/sha256:0",
        "region": "us-east-1",
        "details": {
            "awsEcrContainerImage": {
                "repositoryName": "sst-asset",
                "imageHash": "sha256:0",
                "imageTags": ["abc", "def"],
            }
        },
    }
    untagged = {**ecr, "details": {"awsEcrContainerImage": {"repositoryName": "sst-asset"}}}
    got = sight_finding(raw_finding(resources=[ecr])).resource
    assert (got.image_digest, got.image_tags) == ("sha256:0", ("abc", "def"))
    got = sight_finding(raw_finding(resources=[untagged])).resource
    assert (got.image_digest, got.image_tags) == (None, ())
    assert sight_finding(raw_finding()).resource.image_digest is None


REGISTRY = "111122223333.dkr.ecr.us-east-1.amazonaws.com"


def get_function(name="worker", package_type="Image", resolved=None, tags=None):
    response = {
        "Configuration": {"FunctionName": name, "PackageType": package_type},
        "Code": {
            "RepositoryType": "ECR",
            "ImageUri": f"{REGISTRY}/sst-asset:abc",
            "ResolvedImageUri": resolved or f"{REGISTRY}/sst-asset@sha256:aa",
        },
    }
    return {**response, "Tags": tags} if tags is not None else response


def describe_task_definition(family="web", images=(), tags=None):
    return {
        "taskDefinition": {
            "family": family,
            "containerDefinitions": [
                {"name": f"container-{i}", "image": image} for i, image in enumerate(images)
            ],
        },
        "tags": [{"key": key, "value": value} for key, value in (tags or {}).items()],
    }


def test_sight_lambda_runner_reads_the_resolved_digest_and_tags():
    got = sight_lambda_runner(get_function(tags={STACK: "api-dev"}), "us-east-1")
    assert got == lambda_runner("worker", {STACK: "api-dev"})


def test_sight_lambda_runner_has_no_tags_when_the_response_has_none():
    assert sight_lambda_runner(get_function(), "us-east-1") == lambda_runner("worker", {})


def test_sight_lambda_runner_skips_zip_functions_and_images_outside_ecr():
    assert sight_lambda_runner(get_function(package_type="Zip"), "us-east-1") is None
    elsewhere = get_function(resolved="docker.io/app@sha256:aa")
    assert sight_lambda_runner(elsewhere, "us-east-1") is None


def test_sight_task_definition_runners_make_one_runner_per_ecr_image():
    response = describe_task_definition(
        images=[
            f"{REGISTRY}/sst-asset:abc",
            f"{REGISTRY}/sst-asset@sha256:aa",
            "public.ecr.aws/nginx/nginx:1.27",
        ],
        tags={STACK: "api-dev"},
    )
    assert sight_task_definition_runners(response, "us-east-1") == [
        task_runner("web", {STACK: "api-dev"}, tag="abc"),
        task_runner("web", {STACK: "api-dev"}, digest="sha256:aa"),
    ]


def test_latest_revisions_keeps_the_highest_revision_of_each_family():
    arns = [
        "arn:aws:ecs:us-east-1:111122223333:task-definition/web:9",
        "arn:aws:ecs:us-east-1:111122223333:task-definition/web:10",
        "arn:aws:ecs:us-east-1:111122223333:task-definition/api:2",
        "arn:aws:ecs:us-east-1:111122223333:task-definition/web:3",
    ]
    assert latest_revisions(arns) == [arns[1], arns[2]]


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


class StubClients:
    def __init__(self, **clients):
        self._clients = clients

    def client(self, service, region_name):
        assert region_name == "us-east-1"
        return self._clients[service]


def client_for(service):
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1"
    )
    return session.client(service)


def test_aws_inspector_reads_runners_from_lambda_and_ecs():
    lambda_client, ecs_client = client_for("lambda"), client_for("ecs")
    family = "arn:aws:ecs:us-east-1:111122223333:task-definition/web"
    configuration = {"FunctionName": "worker", "PackageType": "Image"}
    zipped = {"FunctionName": "plain", "PackageType": "Zip"}
    with Stubber(lambda_client) as lambda_stub, Stubber(ecs_client) as ecs_stub:
        lambda_stub.add_response(
            "list_functions", {"Functions": [configuration], "NextMarker": "page-2"}, {}
        )
        lambda_stub.add_response("list_functions", {"Functions": [zipped]}, {"Marker": "page-2"})
        lambda_stub.add_response(
            "get_function",
            {**get_function(tags={STACK: "api-dev"}), "Configuration": configuration},
            {"FunctionName": "worker"},
        )
        ecs_stub.add_response(
            "list_task_definitions",
            {"taskDefinitionArns": [f"{family}:1"], "nextToken": "page-2"},
            {"status": "ACTIVE"},
        )
        ecs_stub.add_response(
            "list_task_definitions",
            {"taskDefinitionArns": [f"{family}:2"]},
            {"status": "ACTIVE", "nextToken": "page-2"},
        )
        ecs_stub.add_response(
            "describe_task_definition",
            describe_task_definition("web", [f"{REGISTRY}/sst-asset:abc"], {STACK: "api-dev"}),
            {"taskDefinition": f"{family}:2", "include": ["TAGS"]},
        )
        session = StubClients(**{"lambda": lambda_client, "ecs": ecs_client})
        found = AwsInspector(session, ["us-east-1"], "high").runners()
        lambda_stub.assert_no_pending_responses()
        ecs_stub.assert_no_pending_responses()
    assert found == [
        lambda_runner("worker", {STACK: "api-dev"}),
        task_runner("web", {STACK: "api-dev"}, tag="abc"),
    ]


def test_aws_inspector_wraps_runner_errors_in_scan_error():
    lambda_client = client_for("lambda")
    with Stubber(lambda_client) as stubber:
        stubber.add_client_error("list_functions", "ThrottlingException")
        session = StubClients(**{"lambda": lambda_client})
        with pytest.raises(ScanError, match="Image runner scan failed"):
            AwsInspector(session, ["us-east-1"], "high").runners()


def test_a_role_without_runner_permissions_warns_and_still_reads_the_rest(capsys):
    lambda_client, ecs_client = client_for("lambda"), client_for("ecs")
    family = "arn:aws:ecs:us-east-1:111122223333:task-definition/web"
    with Stubber(lambda_client) as lambda_stub, Stubber(ecs_client) as ecs_stub:
        lambda_stub.add_client_error("list_functions", "AccessDeniedException")
        ecs_stub.add_response(
            "list_task_definitions", {"taskDefinitionArns": [f"{family}:1"]}, {"status": "ACTIVE"}
        )
        ecs_stub.add_response(
            "describe_task_definition",
            describe_task_definition("web", [f"{REGISTRY}/sst-asset:abc"], {STACK: "api-dev"}),
            {"taskDefinition": f"{family}:1", "include": ["TAGS"]},
        )
        session = StubClients(**{"lambda": lambda_client, "ecs": ecs_client})
        found = AwsInspector(session, ["us-east-1"], "high").runners()
    assert found == [task_runner("web", {STACK: "api-dev"}, tag="abc")]
    assert "can't trace shared-repository images" in capsys.readouterr().err


def test_aws_inspector_wraps_aws_errors_in_scan_error():
    client = inspector_client()
    with Stubber(client) as stubber:
        stubber.add_client_error("list_findings", "AccessDeniedException")
        with pytest.raises(ScanError, match="Inspector scan failed"):
            AwsInspector(StubSession(client), ["us-east-1"], "high").findings()


# --- config


def test_inspector_config_defaults_and_validation():
    config = parse_config({"org": "acme"}).inspector
    assert config == InspectorConfig(["us-east-1"], "high", [])
    with pytest.raises(ValueError, match="inspector.min_severity must be one of"):
        parse_config({"org": "acme", "inspector": {"min_severity": "urgent"}})
    with pytest.raises(ValueError, match="Unknown keys in 'inspector': enabled"):
        parse_config({"org": "acme", "inspector": {"enabled": True}})
    with pytest.raises(ValueError, match="Unknown keys in 'inspector': linear_labels"):
        parse_config({"org": "acme", "inspector": {"linear_labels": ["security"]}})


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


def packages(items):
    return [(item["package"], item["resources"]) for item in items]


def vulnerability_ids(report):
    return {
        vulnerability_id
        for items in report["repos"].values()
        for item in items
        for vulnerability_id in item["vulnerability_ids"]
    }


def test_report_attributes_the_demo_findings_to_repos(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    assert report["via"] == {"tag": 0, "deployment": 10}
    assert {repo: packages(items) for repo, items in report["repos"].items()} == {
        "data-pipeline": [("minimatch", ["cdk-hnb659fds-container-assets-111122223333-us-east-1"])],
        "inventory-service": [
            ("cross-spawn", ["sst-asset"]),
            ("eslint", ["inventory-production-ReorderFunction"]),
            ("follow-redirects", ["inventory-production-ReorderFunction"]),
            ("path-to-regexp", ["inventory-production-ReorderFunction"]),
            ("word-wrap", ["inventory-production-ReorderFunction"]),
        ],
        "payments-api": [
            (
                "jsonwebtoken",
                ["payments-api-production-authorize", "payments-api-production-refund"],
            ),
            ("axios", ["payments-api-dev-createOrder"]),
            ("libxml2", ["serverless-payments-api-production"]),
        ],
    }
    unattributed = report["unattributed"]
    assert {reason: packages(items) for reason, items in unattributed.items()} == {
        "shared_asset_repository": [("ws", ["sst-asset"])],
        "no_deployment_tags": [("braces", ["orphan-handler"])],
    }


def test_report_json_says_how_each_finding_was_attributed(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    jsonwebtoken = report["repos"]["payments-api"][0]
    assert (jsonwebtoken["severity"], jsonwebtoken["exploit_available"]) == ("critical", True)
    assert (jsonwebtoken["package"], jsonwebtoken["fixed_in"]) == ("jsonwebtoken", "9.0.0")
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
    assert not {"CVE-2021-23566", "CVE-2023-26136"} & vulnerability_ids(report)


def test_min_severity_low_adds_the_low_finding_but_never_the_informational_one(tmp_path, capsys):
    report = report_json(tmp_path, capsys, {"min_severity": "low"})
    seen = vulnerability_ids(report)
    assert "CVE-2021-23566" in seen and "CVE-2023-26136" not in seen
    assert report["repos"]["payments-api"][-1]["severity"] == "low"


def test_inspector_ignore_config_drops_matching_resources(tmp_path, capsys):
    report = report_json(tmp_path, capsys, {"ignore": ["payments-api-production-*"]})
    seen = vulnerability_ids(report)
    assert "CVE-2022-23539" not in seen and "CVE-2023-45857" in seen


def test_repo_scope_keeps_only_that_repo(tmp_path, capsys):
    report = report_json(tmp_path, capsys, None, "--repo", "inventory-service")
    assert list(report["repos"]) == ["inventory-service"]
    assert report["unattributed"] == {}
    assert report["via"] == {"tag": 0, "deployment": 5}


def test_report_table_lists_repos_worst_first_then_the_unattributed(capsys):
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    rows = [line.split() for line in out.splitlines()]
    assert ["payments-api", "1", "2", "0", "0", "3", "1", "4"] in rows
    assert ["inventory-service", "0", "5", "0", "0", "5", "0", "2"] in rows
    assert ["data-pipeline", "0", "1", "0", "0", "1", "0", "1"] in rows
    assert ["unattributed:", "shared_asset_repository", "0", "1", "0", "0", "1", "0", "1"] in rows
    assert ["unattributed:", "no_deployment_tags", "0", "1", "0", "0", "1", "0", "1"] in rows
    names = ("payments-api", "inventory-service", "data-pipeline", "unattributed")
    order = [out.index(name) for name in names]
    assert order == sorted(order)
    assert "12 finding(s) in 11 fix item(s) at high or above" in out


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


def demo_items(report):
    return {
        item["package"]: item
        for found in [*report["repos"].values(), *report["unattributed"].values()]
        for item in found
    }


def test_report_json_gives_every_demo_status(tmp_path, capsys):
    report = report_json(tmp_path, capsys)
    assert report["status"] == {
        "needs_deploy": 3,
        "needs_pr_merge": 2,
        "needs_fix": 1,
        "needs_os_update": 1,
        "unknown": 4,
    }
    assert set(report["status"]) == {status.value for status in FixStatus}
    statuses = {package: item["status"] for package, item in demo_items(report).items()}
    assert statuses == {
        "jsonwebtoken": "needs_pr_merge",
        "eslint": "needs_pr_merge",
        "follow-redirects": "needs_deploy",
        "word-wrap": "needs_deploy",
        "path-to-regexp": "needs_fix",
        "libxml2": "needs_os_update",
        "axios": "unknown",
        "cross-spawn": "needs_deploy",
        "minimatch": "unknown",
        "ws": "unknown",
        "braces": "unknown",
    }


def test_report_json_items_say_what_the_branch_has_and_which_pr_fixes_them(tmp_path, capsys):
    items = demo_items(report_json(tmp_path, capsys))
    assert items["jsonwebtoken"]["pr"] == {
        "number": 88,
        "url": "https://github.com/acme/payments-api/pull/88",
        "target": "9.0.0",
    }
    assert items["eslint"]["pr"]["number"] == 19
    assert (items["eslint"]["main_versions"], items["eslint"]["fixed_in"]) == (["8.56.0"], "8.57.0")
    assert (items["follow-redirects"]["main_versions"], items["follow-redirects"]["pr"]) == (
        ["1.15.9"],
        None,
    )
    assert items["word-wrap"]["main_versions"] == []
    assert items["path-to-regexp"]["main_versions"] == ["0.1.7"]
    assert (items["libxml2"]["ecosystem"], items["libxml2"]["fixed_in"]) == (
        None,
        "2.10.4-1.amzn2023.0.8",
    )
    assert items["jsonwebtoken"]["vulnerability_ids"] == ["CVE-2022-23539"]
    assert items["jsonwebtoken"]["exploit_available"] is True


def test_report_table_counts_items_by_status(capsys):
    assert main([*FIXTURE_ARGS, "report", "--topic", "inspector"]) == 0
    out = capsys.readouterr().out
    rows = [line.split() for line in out.splitlines()]
    assert "Fix status: items by what they need." in out
    assert ["repo", *(status.value for status in FixStatus)] in rows
    assert ["payments-api", "0", "1", "0", "1", "1"] in rows
    assert ["inventory-service", "3", "1", "1", "0", "0"] in rows
    assert ["data-pipeline", "0", "0", "0", "0", "1"] in rows
    assert ["unattributed:", "shared_asset_repository", "0", "0", "0", "0", "1"] in rows
    assert ["unattributed:", "no_deployment_tags", "0", "0", "0", "0", "1"] in rows


def test_report_attributes_demo_images_through_the_lambda_or_task_definition_that_runs_them(
    tmp_path, capsys
):
    items = demo_items(report_json(tmp_path, capsys))
    cross_spawn, minimatch = items["cross-spawn"]["findings"][0], items["minimatch"]["findings"][0]
    assert (cross_spawn["via"], cross_spawn["deployment"]) == ("deployment", "inventory/production")
    assert cross_spawn["runner"] == {"kind": "lambda", "name": "inventory-production-ImageWorker"}
    assert (minimatch["via"], minimatch["deployment"]) == ("deployment", "DataPipelineProduction")
    assert minimatch["runner"] == {"kind": "ecs_task_definition", "name": "data-pipeline-worker"}
    assert "runner" not in items["ws"]["findings"][0]
    assert items["eslint"]["findings"][0]["runner"] is None


def test_the_runners_are_only_read_when_an_image_is_in_a_shared_repository(
    tmp_path, capsys, monkeypatch
):
    demo = json.loads((EXAMPLES / "demo-org.json").read_text())
    inspector = demo["aws"]["inspector"]
    inspector["findings"] = [
        finding
        for finding in inspector["findings"]
        if finding["resources"][0]["type"] != "AWS_ECR_CONTAINER_IMAGE"
        or "repository/serverless-" in finding["resources"][0]["id"]
    ]
    fixtures = tmp_path / "demo-org.json"
    fixtures.write_text(json.dumps(demo))

    def unexpected(self):
        raise AssertionError("runners were read")

    monkeypatch.setattr(FixtureInspector, "runners", unexpected)
    args = ["--fixtures", str(fixtures), "--config", str(EXAMPLES / "vulgard.yml")]
    assert main([*args, "report", "--topic", "inspector", "--format", "json"]) == 0
    assert "shared_asset_repository" not in json.loads(capsys.readouterr().out)["unattributed"]
