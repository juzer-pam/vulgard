# Set up stale deployments

**Who this is for:** the admin who runs vulgard for the org. You should already have vulgard's
vulnerability side working, through step 7 of
[Rolling it out](../../README.md#rolling-it-out-to-a-real-org). To understand what you're
turning on, read [How stale deployments work](../stale-deployments.md) first.

**What you need:**

- admin on the vulgard fork,
- permission to create IAM roles in the AWS account your apps deploy to,
- optionally, a Vercel token for your team.

The plan is to turn on scanning in a mode that writes nothing, check what it finds, and fix the
config. Then let it open issues. Only after that, and only if you want to, let it redeploy and
delete things.

| Stage | What it does | Risk |
|---|---|---|
| 1. Report-only | Scans and lists findings. No issues, no pings. | None |
| 2. Issues | Opens `vulgard-stale` issues and pings owners. Commands are recorded but not carried out. | Notifications only |
| 3. Execute | Carries out `/vulgard redeploy` and `/vulgard delete` requests. | Real changes, on request |
| 4. Automatic | Also redeploys or deletes forgotten personal stacks, after a 7-day notice. | Real changes, unasked |

Most orgs should stop at stage 3 for a while.

## Step 1: create the AWS roles

vulgard reaches AWS through **GitHub OIDC**. AWS trusts tokens that GitHub Actions issues, so no
AWS keys are stored in GitHub. If your account has never used GitHub OIDC, first add the identity
provider: in the IAM console, open *Identity providers → Add provider → OpenID Connect*, with
provider URL `https://token.actions.githubusercontent.com` and audience `sts.amazonaws.com`.

You need two roles. Replace `111122223333` with your account ID and `acme` with your org.

### `VulgardStackDelete`: the role CloudFormation deletes with

When vulgard deletes a CloudFormation stack, it asks CloudFormation to do the deleting with this
role. So the role vulgard itself runs as never needs permission to delete Lambdas, tables or IAM
roles.

Trust policy (who may use the role):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "cloudformation.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
```

Permissions: whatever it takes to delete the resources in your stacks. Many teams attach
`AdministratorAccess`, because only CloudFormation can use the role, and only for stacks vulgard
asks it to delete. If that's too broad for you, start narrower and widen the policy whenever a
delete fails with an access error.

### `VulgardLifecycle`: the role vulgard runs as

Trust policy. Only workflows in your vulgard fork may use it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/vulgard:*"}
    }
  }]
}
```

Permissions. The first statement is read-only and is all that stages 1 and 2 need. The second
holds the writes, used from stage 3 on. You can add it later.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Read",
      "Effect": "Allow",
      "Action": [
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "ssm:GetParameter",
        "s3:ListBucket",
        "s3:GetObject",
        "amplify:ListApps",
        "amplify:ListBranches",
        "amplify:ListJobs",
        "amplify:GetApp",
        "amplify:GetBranch"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Write",
      "Effect": "Allow",
      "Action": [
        "cloudformation:DeleteStack",
        "amplify:StartJob",
        "amplify:DeleteBranch"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PassOnlyTheDeleteRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/VulgardStackDelete"
    },
    {
      "Sid": "EmptyServerlessBuckets",
      "Effect": "Allow",
      "Action": ["s3:ListBucketVersions", "s3:DeleteObject", "s3:DeleteObjectVersion"],
      "Resource": [
        "arn:aws:s3:::*-serverlessdeploymentbucket-*",
        "arn:aws:s3:::*-serverlessdeploymentbucket-*/*"
      ]
    }
  ]
}
```

The read statement uses `"Resource": "*"` to keep it short. You can scope it down: `ssm` only
reads `/sst/bootstrap`, and `s3:ListBucket` and `s3:GetObject` only touch SST's state bucket,
which that parameter names.

### The deploy role your repos already use

Redeploys, and SST removes, run in each app's own repo, using the role that repo already deploys
with (for example `GithubCI`). Make sure that role's trust policy allows those repos' workflows.
It usually already does, if they deploy from GitHub Actions today.

## Step 2: connect GitHub

On the vulgard fork, under *Settings → Secrets and variables → Actions*:

- **Variable `VULGARD_AWS_ROLE`**: the ARN of `VulgardLifecycle`.
- **Variable `VULGARD_AWS_REGION`** (optional): defaults to `us-east-1`.
- **Secret `VERCEL_TOKEN`** (optional): a Vercel token that can read your team's projects.

In the vulgard GitHub App's settings, add the repository permission **Actions: Read and
write**. vulgard needs it to trigger lifecycle workflows. The org has to approve the new
permission before it takes effect.

## Step 3: add the config, in report-only mode

Add a `deployments` block to your private `org.yml`. Start from the commented block in
[`vulgard.yml`](../../vulgard.yml). A minimal first version:

```yaml
deployments:
  enabled: true
  report_only: true                  # stage 1: write nothing
  unattributed_repo: vulgard         # where deployments with no known repo are listed
  aws:
    regions: [us-east-1]             # every region you deploy to
  vercel:
    team_id: team_xxxxxxxx           # only if you set VERCEL_TOKEN
```

`unattributed_repo` is required. Pick a repo the admins watch, and the vulgard fork itself is
fine.

## Step 4: look at what it finds, and fix the config

Run the survey from your laptop. It only reads. You'll need AWS credentials with at least the
read permissions above (your normal AWS login is fine), plus a GitHub token:

```bash
export GITHUB_TOKEN=$(gh auth token)
uv run vulgard --config org.yml --org acme report --topic stale --all
```

Remove `--all` to see only what's stale. Go down the table and check each column:

| Column | If it's wrong | Fix |
|---|---|---|
| repo | A stack shows the wrong repo, or `-` (none) | Map it: `attribution: {"DataPipeline*": data-pipeline}`, or tag the stack `vulgard:repo=data-pipeline`. |
| tier | A personal stack shows as `shared` | Add the stage to `people`: `people: {jlee: "@jlee"}`. The key is the stage name, or the user name in an Amplify sandbox's stack name. |
| tier | Something important shows as `shared` | Turn on termination protection for the stack, or add its stage to `production_stages`. |
| tier | A stage like `qa` shows as `shared` but you want it noticed | That's correct: shared is the default for anything that isn't production or personal. |
| (row exists) | Something should never be tracked (CDK's bootstrap stack, a third-party stack) | `ignore: ["CDKToolkit", "aws-sam-cli-*"]`. |

Save `org.yml`, update the secret, and run the survey again until it looks right:

```bash
gh secret set VULGARD_CONFIG -R acme/vulgard < org.yml
```

Leave `report_only: true` for about a week. The scheduled job keeps running the scan, which
shows that AWS access works in CI. Its log only says how many repos *would* get an issue,
because the public log is redacted. For the full list, use the survey above.

## Step 5: let it open issues

Before you switch, preview exactly what it would do:

```bash
uv run vulgard --config org.yml --org acme nag --topic stale
```

This is a dry run. It prints one line per repo, such as `create`, `comment` or `escalate`. When
it looks right, set `report_only: false`, update the secret, and let the next scheduled run go.
Tell your engineers it's coming, and point them at
[Respond to a stale-deployments issue](respond-to-stale-deployments.md).

People can now post `/vulgard` commands. Keeps take effect right away. Redeploy and delete
requests are recorded, but nothing carries them out yet.

## Step 6: add lifecycle workflows to repos

For vulgard to redeploy Serverless, SST or CDK stacks, or to remove SST stages, each of those
repos needs a small workflow that vulgard can trigger. First tell vulgard which role the repos
deploy with:

```yaml
deployments:
  aws:
    regions: [us-east-1]
    deploy_role_arn: arn:aws:iam::111122223333:role/GithubCI
    delete_role_arn: arn:aws:iam::111122223333:role/VulgardStackDelete
```

Then open a PR in each such repo:

```bash
uv run vulgard --config org.yml --org acme rollout --lifecycle          # dry run: which repos
uv run vulgard --config org.yml --org acme rollout --lifecycle --apply  # open the PRs
```

Each PR adds `.github/workflows/vulgard-lifecycle.yml`, which calls the shared `lifecycle.yml`
in your fork. That shared workflow installs dependencies, logs into AWS with the repo's deploy
role, and runs `serverless deploy`, `sst deploy`, `sst remove` or `cdk deploy`. The repo's team
reviews and merges the PR.

The generic workflow won't work for every repo. A repo may need secrets, extra build steps, or
an app in a subfolder. For those, point vulgard at the repo's existing deploy workflow instead.
See [Use your own deploy workflow](use-your-own-deploy-workflow.md).

Amplify and Vercel don't need any of this, because vulgard uses their APIs directly.

## Step 7: carry out requests

Try it once by hand first. Wait until a request is listed under *Requested* on some issue,
ideally a harmless delete of an old dev stack. Then open the fork's *Actions* tab, choose
**nag**, click **Run workflow**, and tick both *apply* and *execute*. Only repo admins can run
it with *execute*. Watch the issue: vulgard comments "Started …" with a link to the run.

When you trust it, set the variable **`VULGARD_EXECUTE`** to `true`. Every scheduled run then
carries out due requests.

## Step 8 (optional): automatic cleanup of personal stacks

List the repos where vulgard may act on personal stacks by itself, and start with redeploys
only:

```yaml
deployments:
  auto:
    repos: ["payments-*"]
    delete: false          # redeploy; set true to delete instead
    personal_stale_days: 90
    notice_days: 7
```

Only stacks listed in `people` (or Amplify sandboxes whose user is) count as personal, so this
can't touch anything shared or production. Each stack gets a notice comment that mentions its
owner, and nothing happens until 7 days later.

## Rolling back

Every stage can be undone in config. Set `VULGARD_EXECUTE` back to `false` to stop all ops.
Empty `auto.repos` to stop automatic ones. Set `report_only: true` to stop issues and pings.
Open issues stay open but stop being updated. Set `enabled: false` to turn the whole topic off.
