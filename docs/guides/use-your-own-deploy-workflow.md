# Use your own deploy workflow

**Who this is for:** a team whose repo deploys with Serverless, SST or CDK, where vulgard's
generic `vulgard-lifecycle.yml` can't deploy it. Common reasons are secrets, a build step
before deploying, an app in a subfolder of a monorepo, or a non-standard command.

**What you get:** when someone comments `/vulgard redeploy <name>` (or `/vulgard delete <name>`
for an SST stage), vulgard triggers *your* workflow instead of its own.

## How vulgard triggers a workflow

vulgard starts the workflow with GitHub's `workflow_dispatch` event, on the repo's default
branch. It passes six text inputs:

| Input | Example | Meaning |
|---|---|---|
| `action` | `redeploy` | `redeploy` or `delete`. `delete` is only sent for SST, because vulgard deletes the others itself. |
| `framework` | `serverless` | `serverless`, `sst` or `cdk` |
| `app` | `payments-api` | The Serverless service, SST app or CDK app name |
| `stage` | `dev` | The stage, empty for CDK |
| `stack` | `PaymentsApiDev` | The CloudFormation stack name, empty for SST |
| `request_id` | `vg-3f9c0a1b2c4d` | The id of this op |

Then it looks for the run it started. It does that by finding the request id in the run's
**name**. That's the one rule your workflow has to follow. Without it, vulgard can't tell
that it already started the op, and would trigger it again on every run.

## Step 1: make your workflow accept the inputs

Add a `workflow_dispatch` trigger that declares **all six inputs**, even ones you ignore.
GitHub rejects a dispatch that sends an input the workflow doesn't declare. Then add a
`run-name` that contains the request id:

```yaml
name: deploy stage
run-name: "deploy ${{ inputs.stage || github.ref_name }} [${{ inputs.request_id || 'manual' }}]"

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      action: {type: string, default: redeploy}
      framework: {type: string, default: ""}
      app: {type: string, default: ""}
      stage: {type: string, default: dev}
      stack: {type: string, default: ""}
      request_id: {type: string, default: ""}

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... your existing setup, secrets and build steps ...
      - run: npx serverless deploy --stage "${{ inputs.stage }}"
```

If your workflow can also delete (for SST, `sst remove`), branch on `inputs.action`. Refuse to
delete anything that looks like production, as vulgard's own workflow does. vulgard never asks
for a production delete, but a person with access to the *Run workflow* button could.

## Step 2: tell vulgard about it

Ask your vulgard admin to add your repo to `deployments.workflows` in the org config. The value
is the workflow's file name in `.github/workflows/`:

```yaml
deployments:
  workflows:
    payments-api: deploy-stage.yml
```

Repos listed here are skipped by `vulgard rollout --lifecycle`, so they don't get a second
workflow.

## Step 3: check it works

Trigger the workflow by hand from the *Actions* tab, filling in a harmless stage and a made-up
request id such as `vg-test`. Check that it deploys, and that the run's name shows `[vg-test]`.
That's the same thing vulgard does.

## Things to know

- **It runs from the default branch.** vulgard always dispatches on the default branch, so
  that's the code that gets deployed.
- **Success means the run's conclusion is `success`.** vulgard then counts the stack as
  deployed at that point, even if your tool found nothing to change and the stack itself
  wasn't updated. So make the workflow fail when the deploy fails. A step that swallows errors
  makes vulgard think the redeploy worked.
- **A failed run isn't retried.** vulgard comments once with the error and a link, then stops.
  Fix the problem, then either deploy by hand or post the `/vulgard redeploy` command again.
  A new comment gets a new request id.
