"""AWS scanners. boto3 lives here and nowhere else.

The `sight_*` functions are pure: they turn one API response shape into a `Sighting`, so the
fixture scanner and the live scanners share every rule.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from .estate import AmplifyBranch, CfnStack, Framework, Sighting, SstStage
from .policy import parse_time

SST_BOOTSTRAP = "/sst/bootstrap"
SST_STATE_RE = re.compile(r"^app/(?P<app>[^/]+)/(?P<stage>[^/]+)\.json$")
SST_LOCK_RE = re.compile(r"^lock/(?P<app>[^/]+)/(?P<stage>[^/]+)\.json$")
AMPLIFY_SANDBOX_RE = re.compile(r"^amplify-(?P<app>.+)-(?P<user>[^-]+)-sandbox-[0-9a-f]+$")
SKIP_PREFIXES = ("CDKToolkit", "SSTBootstrap", "StackSet-", "aws-sam-cli-managed")
AMPLIFY_RUNNING = ("PENDING", "PROVISIONING", "RUNNING", "CANCELLING")


def _time(value: Any) -> datetime:
    return value if isinstance(value, datetime) else parse_time(str(value))


def sight_cfn_stack(stack: dict[str, Any], account: str, region: str) -> Sighting | None:
    """One DescribeStacks entry -> Sighting, or None if it isn't a deployment vulgard tracks.

    Amplify Hosting branch stacks are skipped: the Amplify branch sighting covers them.
    """
    name = stack["StackName"]
    status = stack.get("StackStatus", "")
    if stack.get("ParentId") or status == "DELETE_COMPLETE" or name.startswith(SKIP_PREFIXES):
        return None
    tags = {t["Key"]: t["Value"] for t in stack.get("Tags") or []}
    outputs = {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs") or []}
    params = {p["ParameterKey"] for p in stack.get("Parameters") or []}
    native = CfnStack(account, region, name, stack["StackId"])
    common = {
        "last_deployed": _time(stack.get("LastUpdatedTime") or stack["CreationTime"]),
        "tags": tags,
        "protected": bool(stack.get("EnableTerminationProtection")),
        "in_progress": status.endswith("_IN_PROGRESS"),
    }
    if sandbox := AMPLIFY_SANDBOX_RE.match(name):
        return Sighting(
            Framework.AMPLIFY,
            native,
            sandbox["app"],
            "sandbox",
            person_hint=sandbox["user"],
            **common,
        )
    if name.startswith("amplify-"):
        return None
    if bucket := outputs.get("ServerlessDeploymentBucketName"):
        service, _, stage = name.rpartition("-")
        return Sighting(
            Framework.SERVERLESS,
            CfnStack(account, region, name, stack["StackId"], bucket),
            tags.get("SERVICE") or service or name,
            tags.get("STAGE") or stage or None,
            **common,
        )
    if "BootstrapVersion" in params:
        return Sighting(Framework.CDK, native, name, None, **common)
    return None


def sight_sst_objects(
    objects: Iterable[dict[str, Any]], bucket: str, account: str, region: str
) -> list[Sighting]:
    """S3 objects of the SST state bucket -> one sighting per app/<app>/<stage>.json.

    The state object is rewritten on every deploy, so its LastModified is the deploy time.
    A lock/<app>/<stage>.json object means a deploy or remove is running.
    """
    objects = list(objects)
    locked = {(m["app"], m["stage"]) for o in objects if (m := SST_LOCK_RE.match(o["Key"]))}
    out = []
    for o in objects:
        m = SST_STATE_RE.match(o["Key"])
        if not m:
            continue
        app, stage = m["app"], m["stage"]
        out.append(
            Sighting(
                Framework.SST,
                SstStage(account, region, bucket, app, stage),
                app,
                stage,
                _time(o["LastModified"]),
                in_progress=(app, stage) in locked,
            )
        )
    return out


def sight_amplify_branch(
    app: dict[str, Any],
    branch: dict[str, Any],
    job: dict[str, Any] | None,
    account: str,
    region: str,
) -> Sighting:
    """An Amplify Hosting branch. Its production branch is protected."""
    name = branch["branchName"]
    production = (app.get("productionBranch") or {}).get("branchName") == name
    last = (job.get("endTime") or job.get("startTime")) if job else None
    return Sighting(
        Framework.AMPLIFY,
        AmplifyBranch(account, region, app["appId"], name),
        app["name"],
        name,
        _time(last or branch.get("updateTime") or branch["createTime"]),
        tags=app.get("tags") or {},
        repo_hint=app.get("repository"),
        protected=production or branch.get("stage") == "PRODUCTION" or name in ("main", "master"),
        in_progress=job is not None and job.get("status") in AMPLIFY_RUNNING,
    )


def sst_state_bucket(parameter_value: str) -> str | None:
    try:
        return json.loads(parameter_value).get("state")
    except (json.JSONDecodeError, AttributeError):
        return None


class AwsScanner:
    """CloudFormation, SST state and Amplify Hosting in every configured region."""

    def __init__(self, session: Any, regions: list[str]):
        self._session = session
        self._regions = regions
        self._account = session.client("sts").get_caller_identity()["Account"]

    def scan(self) -> list[Sighting]:
        found: list[Sighting] = []
        for region in self._regions:
            found += self._cfn(region)
            found += self._sst(region)
            found += self._amplify(region)
        return found

    def _cfn(self, region: str) -> list[Sighting]:
        cfn = self._session.client("cloudformation", region_name=region)
        pages = cfn.get_paginator("describe_stacks").paginate()
        stacks = [s for page in pages for s in page["Stacks"]]
        return [s for st in stacks if (s := sight_cfn_stack(st, self._account, region))]

    def _sst(self, region: str) -> list[Sighting]:
        ssm = self._session.client("ssm", region_name=region)
        try:
            value = ssm.get_parameter(Name=SST_BOOTSTRAP)["Parameter"]["Value"]
        except ssm.exceptions.ParameterNotFound:
            return []
        bucket = sst_state_bucket(value)
        if not bucket:
            return []
        s3 = self._session.client("s3", region_name=region)
        objects = [
            o
            for prefix in ("app/", "lock/")
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
            for o in page.get("Contents", [])
        ]
        return sight_sst_objects(objects, bucket, self._account, region)

    def _amplify(self, region: str) -> list[Sighting]:
        amplify = self._session.client("amplify", region_name=region)
        found = []
        for page in amplify.get_paginator("list_apps").paginate():
            for app in page["apps"]:
                for bpage in amplify.get_paginator("list_branches").paginate(appId=app["appId"]):
                    for branch in bpage["branches"]:
                        jobs = amplify.list_jobs(
                            appId=app["appId"], branchName=branch["branchName"], maxResults=1
                        )["jobSummaries"]
                        found.append(
                            sight_amplify_branch(
                                app, branch, jobs[0] if jobs else None, self._account, region
                            )
                        )
        return found
