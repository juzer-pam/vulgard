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
AWS keys are stored in GitHub. vulgard needs two IAM roles:

- **`VulgardLifecycle`** is the role vulgard runs as. Only workflows on your fork's `main`
  branch may assume it.
- **`VulgardStackDelete`** is the role CloudFormation uses when vulgard asks it to delete a
  stack. Because CloudFormation does the deleting, vulgard's own role never needs permission
  to delete Lambdas, tables or IAM roles.

### With the CloudFormation template

[`infra/vulgard-roles.yaml`](../../infra/vulgard-roles.yaml) is a CloudFormation template that
creates both roles, plus the GitHub OIDC provider if your account doesn't have one yet. You only
need to be signed in to the AWS account with permission to create IAM roles. There's nothing to
install.

The quickest way is **AWS CloudShell**, a terminal in the AWS console that is already signed in
as you. Open it from the console's top bar, or at
<https://console.aws.amazon.com/cloudshell/home?region=us-east-1>, then run:

```bash
# Download the template from your fork
curl -sO https://raw.githubusercontent.com/acme/vulgard/main/infra/vulgard-roles.yaml

# Create the roles. Changes nothing outside IAM, and starts read-only.
aws cloudformation deploy --region us-east-1 \
  --stack-name VulgardRoles \
  --template-file vulgard-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubOrg=acme

# Stop the stack being deleted by accident. vulgard also never lists a protected stack as stale.
aws cloudformation update-termination-protection --region us-east-1 \
  --stack-name VulgardRoles --enable-termination-protection

# Print the two role ARNs
aws cloudformation describe-stacks --region us-east-1 --stack-name VulgardRoles \
  --query "Stacks[0].Outputs" --output table
```

Replace `acme` with the org that owns your fork. The outputs look like this:

```text
LifecycleRoleArn    arn:aws:iam::111122223333:role/VulgardLifecycle
StackDeleteRoleArn  arn:aws:iam::111122223333:role/VulgardStackDelete
```

You'll use both in the steps below. This first deploy is **read-only**: vulgard can scan, but it
can't redeploy or delete anything. Step 7 turns on the write permissions.

If you'd rather click through the console, open *CloudFormation, Create stack, With new
resources*, choose *Upload a template file*, and pick `vulgard-roles.yaml`. The form shows the
same parameters. Tick the box that acknowledges the template creates IAM roles, and turn on
termination protection under *Stack creation options*.

Parameters, each passed as `Name=value` after `--parameter-overrides`:

| Parameter | Default | When to change it |
|---|---|---|
| `GitHubOrg` | required | Always. The org that owns the vulgard fork. |
| `VulgardRepo` | `vulgard` | You named the fork something else. |
| `Branch` | `main` | The fork's default branch isn't `main`. |
| `SubjectPrefix` | (empty) | Your fork uses GitHub's immutable OIDC subject. See below. |
| `ExistingOidcProviderArn` | (create one) | The account already has a GitHub OIDC provider. Deploying fails with "already exists" if you don't pass it. Find it under *IAM, Identity providers*. |
| `Writes` | `false` | Set `true` at step 7, to let vulgard redeploy and delete. |
| `SstStateBucket` | `sst-state-*` | SST's state bucket has another name. It's the `state` value in the SSM parameter `/sst/bootstrap`. |
| `DeletePolicyArns` | `AdministratorAccess` | You want `VulgardStackDelete` narrower. A comma-separated list of managed policy ARNs. |

To change a parameter later, run the same `deploy` command again with the new value. Parameters
you leave out keep their default, not their previous value, so pass every one you changed.

**Immutable OIDC subjects.** When a GitHub workflow assumes an AWS role, GitHub sends a token
whose `sub` (subject) claim names the repo, and the role's trust policy only accepts the subject
it expects. By default the subject is `repo:acme/vulgard:ref:refs/heads/main`. Some orgs switch
to GitHub's immutable form, which adds the org's and repo's numeric IDs so a renamed or recreated
repo can't take over the role. Check yours:

```bash
gh api repos/acme/vulgard/actions/oidc/customization/sub
```

If it prints `"use_immutable_subject":true`, pass its `sub_claim_prefix` as `SubjectPrefix`, for
example `SubjectPrefix=repo:acme@123/vulgard@456`. Otherwise leave it empty. A wrong subject
shows up as `Not authorized to perform sts:AssumeRoleWithWebIdentity` in the `nag` run.

`VulgardStackDelete` gets `AdministratorAccess` by default, because deleting a stack means
deleting whatever is in it. Only CloudFormation in this account can assume the role, and
`VulgardLifecycle` can only pass it to CloudFormation for `DeleteStack`. If that's still too
broad for you, pass narrower policies with `DeletePolicyArns`, and widen them whenever a delete
fails with an access error.

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

First give `VulgardLifecycle` its write permissions:

```bash
# Adds DeleteStack, PassRole on VulgardStackDelete, and the Amplify writes
aws cloudformation deploy --region us-east-1 \
  --stack-name VulgardRoles \
  --template-file vulgard-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubOrg=acme Writes=true
```

Pass any other parameters you set in step 1 again too.

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

Every stage can be undone in config. Set `VULGARD_EXECUTE` back to `false` to stop all ops, and
redeploy the roles without `-c writes=true` to take the permissions away too.
Empty `auto.repos` to stop automatic ones. Set `report_only: true` to stop issues and pings.
Open issues stay open but stop being updated. Set `enabled: false` to turn the whole topic off.
