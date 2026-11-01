from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulgard.aws import sight_amplify_branch, sight_cfn_stack, sight_sst_objects
from vulgard.cli import main
from vulgard.config import DeploymentsConfig, load_config, parse_config
from vulgard.estate import (
    Attribution,
    CfnStack,
    Deployment,
    Framework,
    RepoIndex,
    Sighting,
    Tier,
    build_index,
    classify,
    discover,
    last_human_commit,
    manifest_identity,
)
from vulgard.fixtures import FixtureGitHub, fixture_clients
from vulgard.vercel import sight_vercel_project

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, tzinfo=UTC)
EMPTY = RepoIndex(frozenset(), {}, {})


def sighting(name="api-dev", app="api", stage="dev", **kw):
    return Sighting(
        Framework.SERVERLESS, CfnStack("1", "us-east-1", name, "id"), app, stage, NOW, **kw
    )


def cfg(**kw):
    return DeploymentsConfig(people={"jlee": "@jlee"}, **kw)


def test_personal_only_on_positive_evidence():
    assert classify(sighting(stage="jlee"), EMPTY, cfg()).tier is Tier.PERSONAL
    assert classify(sighting(stage="jlee"), EMPTY, cfg()).person == "@jlee"
    assert classify(sighting(stage="qa2"), EMPTY, cfg()).tier is Tier.SHARED
    assert classify(sighting(stage="dev"), EMPTY, cfg()).tier is Tier.SHARED


def test_production_anywhere_in_the_name_or_tags_wins():
    name = "PamKnowledgeProduction"
    cdk = Sighting(Framework.CDK, CfnStack("1", "r", name, "id"), name, None, NOW)
    assert classify(cdk, EMPTY, cfg()).tier is Tier.PRODUCTION
    tagged = sighting(stage="jlee", tags={"STAGE": "prod"})
    assert classify(tagged, EMPTY, cfg()).tier is Tier.PRODUCTION
    assert classify(sighting(protected=True, stage="jlee"), EMPTY, cfg()).tier is Tier.PRODUCTION


def test_deployment_invariants_are_enforced():
    with pytest.raises(AssertionError):
        Deployment(sighting(), "api", Attribution.NONE, Tier.PERSONAL, None)
    with pytest.raises(AssertionError):
        Deployment(sighting(protected=True), "api", Attribution.NONE, Tier.SHARED, None)


def test_attribution_order_config_then_tag_then_platform_then_manifest():
    index = RepoIndex(frozenset({"api"}), {(Framework.SERVERLESS, "api"): "api"}, {})
    assert classify(sighting(), index, cfg()).attributed_by is Attribution.MANIFEST
    hinted = sighting(repo_hint="https://github.com/acme/api-v2.git")
    assert classify(hinted, index, cfg()).repo == "api-v2"
    tagged = sighting(tags={"repository": "acme/infra"}, repo_hint="acme/api-v2")
    assert classify(tagged, index, cfg()).repo == "infra"
    override = cfg(attribution={"api-*": "billing"})
    assert classify(tagged, index, override).attributed_by is Attribution.CONFIG
    assert classify(sighting(), index, cfg(ignore=["api"])) is None


def test_ambiguous_manifest_identity_attributes_nothing():
    gh = FixtureGitHub(
        {
            "trees": {"a": ["serverless.yml"], "b": ["svc/serverless.yml"]},
            "files": {
                "a": {"serverless.yml": "service: shared-template\n"},
                "b": {"svc/serverless.yml": "service: shared-template\n"},
            },
        }
    )
    config = parse_config({"org": "acme"})
    index = build_index(gh, config, [{"name": "a"}, {"name": "b"}])
    assert index.by_identity[(Framework.SERVERLESS, "shared-template")] is None
    assert index.frameworks["a"] == {Framework.SERVERLESS}


def test_manifest_identity_parsers():
    assert manifest_identity(Framework.SERVERLESS, "service:\n  name: legacy\n") == "legacy"
    assert manifest_identity(Framework.SERVERLESS, "service: ${env:NAME}\n") is None
    sst = 'export default $config({ app(input) { return { name: "inv", home: "aws" } } })'
    assert manifest_identity(Framework.SST, sst) == "inv"


def test_cloudformation_parser_skips_what_isnt_a_deployment():
    base = {"StackId": "id", "StackStatus": "UPDATE_COMPLETE", "CreationTime": NOW}
    assert sight_cfn_stack({**base, "StackName": "CDKToolkit"}, "1", "r") is None
    assert sight_cfn_stack({**base, "StackName": "x", "ParentId": "p"}, "1", "r") is None
    assert sight_cfn_stack({**base, "StackName": "hand-made"}, "1", "r") is None
    assert sight_cfn_stack({**base, "StackName": "amplify-d1-main-branch-abc"}, "1", "r") is None
    sandbox = sight_cfn_stack({**base, "StackName": "amplify-shop-jlee-sandbox-9f"}, "1", "r")
    assert sandbox.person_hint == "jlee" and sandbox.app == "shop"
    sls = sight_cfn_stack(
        {
            **base,
            "StackName": "orders-api-jlee",
            "StackStatus": "UPDATE_IN_PROGRESS",
            "Outputs": [{"OutputKey": "ServerlessDeploymentBucketName", "OutputValue": "bkt"}],
        },
        "1",
        "r",
    )
    assert (sls.app, sls.stage, sls.in_progress) == ("orders-api", "jlee", True)
    assert sls.native.deployment_bucket == "bkt"


def test_sst_state_objects_and_locks():
    objects = [
        {"Key": "app/inv/jlee.json", "LastModified": NOW},
        {"Key": "app/inv/prod.json", "LastModified": NOW},
        {"Key": "lock/inv/jlee.json", "LastModified": NOW},
        {"Key": "app/inv/jlee/history.json", "LastModified": NOW},
    ]
    found = {s.stage: s for s in sight_sst_objects(objects, "bkt", "1", "r")}
    assert set(found) == {"jlee", "prod"}
    assert found["jlee"].in_progress and not found["prod"].in_progress


def test_amplify_production_branch_and_vercel_custom_domain_are_protected():
    app = {"appId": "d1", "name": "site", "productionBranch": {"branchName": "live"}}
    branch = {"branchName": "live", "createTime": "2026-01-01T00:00:00Z"}
    assert sight_amplify_branch(app, branch, None, "1", "r").protected
    feature = {"branchName": "feature", "createTime": "2026-01-01T00:00:00Z"}
    assert not sight_amplify_branch(app, feature, None, "1", "r").protected
    prod = {"createdAt": 1767225600000, "alias": ["docs.acme.com"]}
    project = {"id": "p", "name": "docs", "targets": {"production": prod}}
    assert sight_vercel_project(project, "t").protected
    assert sight_vercel_project({"id": "p", "name": "x", "targets": {}}, "t") is None


def test_bot_commits_dont_count_as_activity():
    def commit(date, login):
        return {"commit": {"committer": {"date": date}}, "author": {"login": login}}

    commits = [commit("2026-10-30T00:00:00Z", "dependabot[bot]"), commit("2026-06-01T00:00Z", "a")]
    assert last_human_commit(commits) == datetime(2026, 6, 1, tzinfo=UTC)
    only_bots = [commit("2026-10-30T00:00:00Z", "x[bot]"), commit("2026-03-01T00:00Z", "y[bot]")]
    assert last_human_commit(only_bots) == datetime(2026, 3, 1, tzinfo=UTC)


def test_deployments_config_validation():
    with pytest.raises(ValueError, match="unattributed_repo"):
        parse_config({"org": "acme", "deployments": {"enabled": True}})
    with pytest.raises(ValueError, match="both production and shared"):
        DeploymentsConfig(production_stages=["prod"], shared_stages=["prod"])
    with pytest.raises(ValueError, match="start with @"):
        DeploymentsConfig(people={"jlee": "jlee"})
    with pytest.raises(ValueError, match="Unknown keys in 'auto'"):
        DeploymentsConfig(auto={"repoz": []})


def test_fixture_estate_end_to_end(capsys):
    config = load_config(EXAMPLES / "vulgard.yml")
    clients = fixture_clients(EXAMPLES / "demo-org.json")
    repos = [r for r in clients.github.list_repos("acme") if not r.get("archived")]
    index = build_index(clients.github, config, repos)
    found = {d.name: d for d in discover(clients.scanners(), index, config.deployments)}
    assert "CDKToolkit" not in found and "hand-made-vpc" not in found
    assert found["payments-api-jlee"].tier is Tier.PERSONAL
    assert found["DataPipelineProduction"].tier is Tier.PRODUCTION
    assert found["inventory/jlee"].repo == "inventory-service"
    assert found["legacy-reports-staging"].repo is None
    assert found["storefront-docs"].tier is Tier.PRODUCTION

    args = [
        "--fixtures", str(EXAMPLES / "demo-org.json"),
        "--config", str(EXAMPLES / "vulgard.yml"),
    ]
    assert main([*args, "report", "--topic", "stale"]) == 0
    out = capsys.readouterr().out
    assert "payments-api-jlee" in out and "payments-api-dev" not in out
    assert "data-pipeline" in out.split("no human commits")[1]
