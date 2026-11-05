"""AWS scanners. boto3 lives here and nowhere else.

The `sight_*` functions are pure: they turn one API response shape into a `Sighting`, so the
fixture scanner and the live scanners share every rule.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable
from datetime import datetime
from typing import Any, assert_never

from botocore.exceptions import BotoCoreError, ClientError

from .config import SEVERITIES, severities_at_least
from .estate import (
    AmplifyBranch,
    CfnStack,
    Found,
    Framework,
    RunState,
    ScanError,
    Sighting,
    SstStage,
)
from .inspector import (
    Finding,
    ImageRunner,
    InspectorResource,
    ResourceType,
    RunnerKind,
    parse_image,
)
from .policy import parse_time

SST_BOOTSTRAP = "/sst/bootstrap"
SST_STATE_RE = re.compile(r"^app/(?P<app>[^/]+)/(?P<stage>[^/]+)\.json$")
SST_LOCK_RE = re.compile(r"^lock/(?P<app>[^/]+)/(?P<stage>[^/]+)\.json$")
AMPLIFY_SANDBOX_RE = re.compile(r"^amplify-(?P<app>.+)-(?P<user>[^-]+)-sandbox-[0-9a-f]+$")
SKIP_PREFIXES = ("CDKToolkit", "SSTBootstrap", "StackSet-", "aws-sam-cli-managed", "VulgardRoles")
AMPLIFY_RUNNING = ("PENDING", "PROVISIONING", "RUNNING", "CANCELLING")
AMPLIFY_FAILED = ("FAILED", "CANCELLED")
INSPECTOR_RESOURCE_TYPES = {
    "AWS_LAMBDA_FUNCTION": ResourceType.LAMBDA,
    "AWS_ECR_CONTAINER_IMAGE": ResourceType.ECR_IMAGE,
    "AWS_EC2_INSTANCE": ResourceType.EC2,
}
INSPECTOR_PAGE_SIZE = 100


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
        AmplifyBranch(account, region, app["appId"], name, app["name"]),
        app["name"],
        name,
        _time(last or branch.get("updateTime") or branch["createTime"]),
        tags=app.get("tags") or {},
        repo_hint=app.get("repository"),
        protected=production or branch.get("stage") == "PRODUCTION" or name in ("main", "master"),
        in_progress=job is not None and job.get("status") in AMPLIFY_RUNNING,
    )


def _inspector_resource(raw: dict[str, Any]) -> InspectorResource | None:
    kind = INSPECTOR_RESOURCE_TYPES.get(raw["type"])
    if kind is None:
        return None
    details = raw.get("details") or {}
    digest: str | None = None
    image_tags: tuple[str, ...] = ()
    match kind:
        case ResourceType.LAMBDA:
            name = details["awsLambdaFunction"]["functionName"]
        case ResourceType.ECR_IMAGE:
            image = details["awsEcrContainerImage"]
            name = image["repositoryName"]
            digest, image_tags = image.get("imageHash"), tuple(image.get("imageTags") or ())
        case ResourceType.EC2:
            name = raw["id"]
        case _ as unreachable:
            assert_never(unreachable)
    return InspectorResource(
        kind, raw["id"], name, raw.get("region", ""), raw.get("tags") or {}, digest, image_tags
    )


def sight_finding(raw: dict[str, Any]) -> Finding | None:
    """One ListFindings entry -> Finding, or None if vulgard doesn't report it: not a package
    vulnerability, a resource type vulgard doesn't map, or a severity outside `SEVERITIES`
    (Inspector's INFORMATIONAL and UNTRIAGED).

    Only the first vulnerable package is kept: a finding is one vulnerability on one resource.
    """
    severity = raw["severity"].lower()
    if raw["type"] != "PACKAGE_VULNERABILITY" or severity not in SEVERITIES:
        return None
    resource = _inspector_resource(raw["resources"][0])
    if resource is None:
        return None
    details = raw["packageVulnerabilityDetails"]
    package = details["vulnerablePackages"][0]
    fixed_in = package.get("fixedInVersion")
    return Finding(
        arn=raw["findingArn"],
        vulnerability_id=details["vulnerabilityId"],
        severity=severity,
        package=package["name"],
        package_manager=package.get("packageManager", ""),
        installed_version=package["version"],
        fixed_in=None if fixed_in in (None, "NotAvailable") else fixed_in,
        fix_available=raw.get("fixAvailable") in ("YES", "PARTIAL"),
        exploit_available=raw.get("exploitAvailable") == "YES",
        first_observed=_time(raw["firstObservedAt"]),
        title=raw.get("title", ""),
        resource=resource,
    )


def sight_lambda_runner(function: dict[str, Any], region: str) -> ImageRunner | None:
    """One GetFunction response -> runner, or None if the function isn't a container image in ECR.
    ListFunctions has no image URI, so the digest comes from `Code.ResolvedImageUri`. The tags
    are only in the response when the caller may `lambda:ListTags`."""
    configuration = function["Configuration"]
    image = parse_image(function.get("Code", {}).get("ResolvedImageUri", ""))
    if configuration.get("PackageType") != "Image" or image is None:
        return None
    return ImageRunner(
        RunnerKind.LAMBDA,
        configuration["FunctionName"],
        region,
        image,
        function.get("Tags") or {},
    )


def sight_task_definition_runners(response: dict[str, Any], region: str) -> list[ImageRunner]:
    """One DescribeTaskDefinition response (with `include=["TAGS"]`) -> one runner per container
    image in ECR."""
    definition = response["taskDefinition"]
    tags = {tag["key"]: tag["value"] for tag in response.get("tags") or []}
    return [
        ImageRunner(RunnerKind.ECS_TASK_DEFINITION, definition["family"], region, image, tags)
        for container in definition.get("containerDefinitions") or []
        if (image := parse_image(container.get("image", ""))) is not None
    ]


def latest_revisions(task_definition_arns: Iterable[str]) -> list[str]:
    """The highest revision of each family, from `arn:...:task-definition/<family>:<revision>`."""
    latest: dict[str, tuple[int, str]] = {}
    for arn in task_definition_arns:
        family, _, revision = arn.rpartition("/")[2].rpartition(":")
        if family not in latest or int(revision) > latest[family][0]:
            latest[family] = (int(revision), arn)
    return [arn for _, arn in latest.values()]


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
        try:
            for region in self._regions:
                found += self._cfn(region)
                found += self._sst(region)
                found += self._amplify(region)
        except (BotoCoreError, ClientError) as e:
            raise ScanError(f"AWS scan failed: {e}") from e
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


ACCESS_DENIED = ("AccessDenied", "AccessDeniedException")


class AwsInspector:
    """Active package-vulnerability findings from Amazon Inspector in every configured region.
    Severities below `min_severity` are filtered by Inspector itself: an account can hold tens of
    thousands of findings."""

    def __init__(self, session: Any, regions: list[str], min_severity: str):
        self._session = session
        self._regions = regions
        self._severities = severities_at_least(min_severity)

    def findings(self) -> list[Finding]:
        found: list[Finding] = []
        try:
            for region in self._regions:
                found += self._region(region)
        except (BotoCoreError, ClientError) as e:
            raise ScanError(f"Inspector scan failed: {e}") from e
        return found

    def _region(self, region: str) -> list[Finding]:
        inspector = self._session.client("inspector2", region_name=region)
        pages = inspector.get_paginator("list_findings").paginate(
            filterCriteria={
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
                "severity": [
                    {"comparison": "EQUALS", "value": severity.upper()}
                    for severity in self._severities
                ],
                "resourceType": [
                    {"comparison": "EQUALS", "value": resource_type}
                    for resource_type in INSPECTOR_RESOURCE_TYPES
                ],
            },
            maxResults=INSPECTOR_PAGE_SIZE,
        )
        return [
            finding
            for page in pages
            for raw in page["findings"]
            if (finding := sight_finding(raw))
        ]

    def runners(self) -> list[ImageRunner]:
        """The Lambda functions and ECS task definitions running container images. Call counts
        per region: one ListFunctions page per 50 functions, one GetFunction per container-image
        function, one ListTaskDefinitions page per 100 ACTIVE revisions and one
        DescribeTaskDefinition per task definition family (its latest ACTIVE revision only)."""
        found: list[ImageRunner] = []
        for region in self._regions:
            for read in (self._lambda_runners, self._ecs_runners):
                try:
                    found += read(region)
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") not in ACCESS_DENIED:
                        raise ScanError(f"Image runner scan failed: {e}") from e
                    print(
                        f"warning: can't trace shared-repository images ({e}); they stay "
                        "shared_asset_repository until the role can read them",
                        file=sys.stderr,
                    )
                except BotoCoreError as e:
                    raise ScanError(f"Image runner scan failed: {e}") from e
        return found

    def _lambda_runners(self, region: str) -> list[ImageRunner]:
        lambda_ = self._session.client("lambda", region_name=region)
        names = [
            function["FunctionName"]
            for page in lambda_.get_paginator("list_functions").paginate()
            for function in page["Functions"]
            if function.get("PackageType") == "Image"
        ]
        functions = [lambda_.get_function(FunctionName=name) for name in names]
        runners = [sight_lambda_runner(function, region) for function in functions]
        return [runner for runner in runners if runner is not None]

    def _ecs_runners(self, region: str) -> list[ImageRunner]:
        ecs = self._session.client("ecs", region_name=region)
        pages = ecs.get_paginator("list_task_definitions").paginate(status="ACTIVE")
        arns = latest_revisions(arn for page in pages for arn in page["taskDefinitionArns"])
        return [
            runner
            for arn in arns
            for runner in sight_task_definition_runners(
                ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"]), region
            )
        ]


CONSOLE = "https://{region}.console.aws.amazon.com"


class AwsOps:
    """Native deletes and Amplify releases. Runs with the lifecycle role; CloudFormation deletes
    pass `delete_role_arn` so the stack's resources are deleted by that service role."""

    def __init__(self, session: Any, delete_role_arn: str | None):
        self._session = session
        self._delete_role = delete_role_arn

    def _client(self, service: str, region: str) -> Any:
        return self._session.client(service, region_name=region)

    def stack(self, ref: CfnStack) -> dict[str, Any] | None:
        cfn = self._client("cloudformation", ref.region)
        try:
            stacks = cfn.describe_stacks(StackName=ref.name)["Stacks"]
        except ClientError as e:
            if "does not exist" in str(e):
                return None
            raise
        return stacks[0] if stacks else None

    def stack_url(self, ref: CfnStack) -> str:
        return (
            f"{CONSOLE.format(region=ref.region)}/cloudformation/home?region={ref.region}"
            f"#/stacks/stackinfo?stackId={ref.stack_id}"
        )

    def delete_stack(self, ref: CfnStack, request_id: str) -> str:
        if ref.deployment_bucket:
            self._empty_bucket(ref.deployment_bucket, ref.region)
        args: dict[str, Any] = {"StackName": ref.name, "ClientRequestToken": request_id}
        if self._delete_role:
            args["RoleARN"] = self._delete_role
        self._client("cloudformation", ref.region).delete_stack(**args)
        return self.stack_url(ref)

    def deleting(self, ref: CfnStack, request_id: str) -> Found | None:
        """The delete with this token, if the stack still exists. None when the stack is gone,
        because that says nothing about who deleted it."""
        stack = self.stack(ref)
        if stack is None:
            return None
        events = self._client("cloudformation", ref.region).describe_stack_events(
            StackName=ref.name
        )["StackEvents"]
        if not any(e.get("ClientRequestToken") == request_id for e in events):
            return None
        url = self.stack_url(ref)
        if stack.get("StackStatus") == "DELETE_FAILED":
            why = f"DELETE_FAILED: {stack.get('StackStatusReason', 'see the console')}"
            return Found(url, RunState.FAILED, why)
        return Found(url)

    def _empty_bucket(self, bucket: str, region: str) -> None:
        """Serverless deployment buckets must be empty before CloudFormation can delete them."""
        s3 = self._client("s3", region)
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            keys = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in [*page.get("Versions", []), *page.get("DeleteMarkers", [])]
            ]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})

    def sst_stage(self, ref: SstStage) -> Sighting | None:
        """The stage's state object (and lock, if any), read fresh. None when the state is gone."""
        s3 = self._client("s3", ref.region)
        objects = []
        for prefix in ("app", "lock"):
            key = f"{prefix}/{ref.app}/{ref.stage}.json"
            try:
                head = s3.head_object(Bucket=ref.state_bucket, Key=key)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                    continue
                raise
            objects.append({"Key": key, "LastModified": head["LastModified"]})
        found = sight_sst_objects(objects, ref.state_bucket, ref.account, ref.region)
        return found[0] if found else None

    def amplify_branch(self, ref: AmplifyBranch) -> Sighting | None:
        amplify = self._client("amplify", ref.region)
        try:
            app = amplify.get_app(appId=ref.app_id)["app"]
            branch = amplify.get_branch(appId=ref.app_id, branchName=ref.branch)["branch"]
        except amplify.exceptions.NotFoundException:
            return None
        jobs = amplify.list_jobs(appId=ref.app_id, branchName=ref.branch, maxResults=1)
        job = jobs["jobSummaries"][0] if jobs["jobSummaries"] else None
        return sight_amplify_branch(app, branch, job, ref.account, ref.region)

    def amplify_url(self, ref: AmplifyBranch) -> str:
        return (
            f"{CONSOLE.format(region=ref.region)}/amplify/apps/{ref.app_id}/branches/{ref.branch}"
        )

    def amplify_job(self, ref: AmplifyBranch, request_id: str) -> Found | None:
        amplify = self._client("amplify", ref.region)
        jobs = amplify.list_jobs(appId=ref.app_id, branchName=ref.branch, maxResults=10)
        job = next((j for j in jobs["jobSummaries"] if j.get("jobReason") == request_id), None)
        if job is None:
            return None
        url, status = self.amplify_url(ref), job.get("status")
        if status == "SUCCEED":
            return Found(url, RunState.SUCCEEDED)
        if status in AMPLIFY_FAILED:
            return Found(url, RunState.FAILED, f"the Amplify job ended `{status}`")
        return Found(url)

    def amplify_release(self, ref: AmplifyBranch, request_id: str) -> str:
        self._client("amplify", ref.region).start_job(
            appId=ref.app_id, branchName=ref.branch, jobType="RELEASE", jobReason=request_id
        )
        return self.amplify_url(ref)

    def amplify_delete(self, ref: AmplifyBranch) -> str:
        self._client("amplify", ref.region).delete_branch(appId=ref.app_id, branchName=ref.branch)
        return self.amplify_url(ref)
