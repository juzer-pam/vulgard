# Configuration reference

Every setting vulgard reads from its config file, with its type, default and what it does.
Start from [`vulgard.yml`](../vulgard.yml), which lists the same keys with short comments, and
save your copy as `org.yml`. The [README](../README.md#rolling-it-out-to-a-real-org) covers
setup in order.

## How vulgard reads the file

- The scheduled workflow reads the `VULGARD_CONFIG` repository secret, writes it to
  `vulgard.yml`, and runs with `--config vulgard.yml`. Changing `org.yml` on your laptop does
  nothing until you run `gh secret set VULGARD_CONFIG -R <org>/vulgard < org.yml`.
- Locally, pass `--config org.yml`. Without `--config`, vulgard looks for `vulgard.yml` and
  uses the defaults if it's missing.
- **Unknown keys inside a section fail loading** with `Unknown keys in '<section>'`. That
  includes keys a newer vulgard understands but the deployed one doesn't, so merge and sync
  code before you put a new key in the secret. Unknown top-level keys are ignored.
- Globs use shell-style matching (`*`, `?`, `[abc]`), as in `payments-*`.
- Handles are GitHub handles with the `@`: `@jlee` for a person, `@your-org/payments` for a
  team.

## Who owns a repo

Several sections route by owner, so it helps to know where owners come from. vulgard takes
the first of these that gives a non-empty list:

1. `owners` for the exact repo name.
2. The `*` line in the repo's `CODEOWNERS` file, checked in `.github/`, the repo root, then
   `docs/`. Path-specific lines are ignored.
3. `default_owners`.

Settings that map a repo or owner to something (`slack.channels`, `linear.teams`) try the
exact repo name first, then repo globs in file order, then each owner in order, then the
section's default.

## Top-level settings

| Key | Type | Default | What it does |
|---|---|---|---|
| `org` | string | none | GitHub organization. Usually left out: the workflow passes `--org`. Required one way or the other. |
| `repos.include` | list of globs | `["*"]` | Repos vulgard works on. |
| `repos.exclude` | list of globs | `[]` | Repos skipped even if included. Archived repos are always skipped. |
| `sla_days` | map of severity to days | `{critical: 7, high: 30, medium: 90, low: 180}` | Days from when an alert opened until it's overdue. Keys must be `critical`, `high`, `medium` or `low`; missing ones keep their default. |
| `due_soon_days` | int | `5` | Alerts and deployments this close to their deadline are marked due soon. |
| `stale_pr_days` | int | `14` | Dependabot PRs open this long are called out as stale. |
| `ready_pr_days` | int | `2` | Dependabot PRs with passing CI that are open this long ping owners to review or merge. |
| `reminder_interval_days` | int | `7` | How often vulgard comments again while something is still overdue, ready or stale. |
| `owners` | map of repo to list of handles | `{}` | Owners for a repo, ahead of `CODEOWNERS`. Example: `payments-api: ["@your-org/payments"]`. |
| `default_owners` | list of handles | `[]` | Owners for repos with no `owners` entry and no `CODEOWNERS` `*` line. |

## `escalation`

An overdue item escalates once it's `after_days_overdue` past its deadline and its severity is
in `severities`. Alerts on CISA's known-exploited list escalate as soon as they're overdue,
whatever their severity.

| Key | Type | Default | What it does |
|---|---|---|---|
| `after_days_overdue` | int | `7` | Days past the deadline before escalating. |
| `severities` | list of severities | `[critical, high]` | Severities that escalate. |
| `mentions` | list of handles | `[]` | People or teams mentioned on the issue when it escalates. Escalations also go to `slack.escalation_channel`. |
| `weekday` | weekday name | none | Escalate only on runs on this day (UTC), e.g. `monday`. Items that come due on other days wait and escalate together. Unset escalates on every run. |

## `issue`

The GitHub tracking issue for vulnerability alerts. Stale deployments use their own label and
title under `deployments`.

| Key | Type | Default | What it does |
|---|---|---|---|
| `label` | string | `vulgard` | Label vulgard puts on its tracking issues and uses to find them again. Changing it makes vulgard lose track of existing issues. |
| `title` | string | `Security debt: vulnerable dependencies need attention` | Title of new tracking issues. |

## `slack`

Optional. Without a token or webhook in the environment, vulgard skips Slack.

| Key | Type | Default | What it does |
|---|---|---|---|
| `token_env` | string | `SLACK_BOT_TOKEN` | Environment variable holding the bot token. The bot needs `chat:write`, `chat:write.public` and `im:write`. |
| `webhook_env` | string | `SLACK_WEBHOOK_URL` | Environment variable holding an incoming webhook, used for the leaderboard when there's no bot token. |
| `default_channel` | string | none | Org-wide channel. Gets the weekly leaderboard, plus updates for repos `channels` doesn't map. |
| `escalation_channel` | string | none | Channel for escalations. |
| `channels` | map of repo, glob or handle to channel | `{}` | Team channel per repo. Matching order is described in [Who owns a repo](#who-owns-a-repo). |
| `users` | map of handle or email to Slack ID | `{}` | A `U…` or `W…` user ID turns a handle into a mention and a DM target. An `S…` user group ID turns a team handle into a group mention. Key a lead's email from `linear.leads` here so `rollout --slack` can DM them. |
| `dm_owners` | bool | `true` | DM each owner with a `U…` or `W…` ID in `users` one summary per run covering all their repos. |
| `leaderboard_weekday` | weekday name | none | Post the leaderboard only on runs on this day (UTC), e.g. `monday`. Unset posts it on every `nag --slack` run. |

## `linear`

Optional. Without the API key in the environment, vulgard skips Linear.

| Key | Type | Default | What it does |
|---|---|---|---|
| `api_key_env` | string | `LINEAR_API_KEY` | Environment variable holding the API key. |
| `default_team` | team key | none | Team for repos `teams` doesn't map. Without it, those repos get no Linear issue. |
| `teams` | map of repo, glob or handle to route | `{}` | Team per repo. See [Routes](#routes). |
| `labels` | list of strings | `["vulgard"]` | Labels on new issues. A name matches the team's own label first, then a workspace label, and vulgard creates a workspace label if neither exists. |
| `project` | string | none | Project new issues are added to. |
| `state` | string | team default | Workflow state for new and reopened issues, for example `Triage`. |
| `severity_labels` | map of severity to label | `{}` | Label for the worst open severity, swapped as it changes. Example: `{critical: Critical, high: High}`. |
| `users` | map of handle to email | `{}` | Linear account for an owner. A new issue is assigned to the first owner listed here. |
| `leads` | map of team key to email | `{}` | Assignee for a new issue when none of the repo's owners is in `users`. Every key must be a team that `teams` or `default_team` routes to, or loading fails. |

vulgard sets the team and assignee only when it creates an issue. Moving or reassigning an
existing issue in Linear sticks.

### Routes

A `teams` value is either a bare team key or a mapping that also overrides the defaults for
matching repos:

```yaml
linear:
  default_team: PLAT
  teams:
    sam-api: INB                 # bare team key
    "payments-*": PAY
    "@your-org/security":
      team: SEC                  # required
      labels: [vulgard, security]
      project: Security debt
      state: Triage
      severity_labels: {critical: Critical, high: High}
```

A mapping must have `team` and may have only `labels`, `project`, `state` and
`severity_labels`. Unset fields fall back to the `linear` defaults. `labels: []` means no
labels, not the default.

## `kev`

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `true` | Check alerts against CISA's Known Exploited Vulnerabilities catalog. |
| `sla_days` | int | `3` | Deadline for known-exploited alerts, when shorter than their severity's SLA. They escalate once overdue. |

## `exceptions`

Accepted risks. Each entry hides matching alerts until it expires, and the tracking issue lists
it so it stays visible.

| Key | Type | Default | What it does |
|---|---|---|---|
| `repo` | glob | `*` | Repos the exception covers. |
| `advisory` | string | none | GHSA or CVE id. |
| `package` | string | none | Package name. Each entry needs `advisory`, `package` or both. |
| `reason` | string | none | Required. Why the risk is accepted. |
| `expires` | date | none | Required, as `YYYY-MM-DD`. The alert comes back after this date. |

```yaml
exceptions:
  - repo: web-storefront
    package: nanoid
    reason: Only used by build tooling; never shipped to browsers.
    expires: 2027-03-31
```

## `rollout`

What `vulgard rollout` writes to each repo.

| Key | Type | Default | What it does |
|---|---|---|---|
| `workflow_repo` | string | `vulgard` | Repo in the org hosting the reusable workflows that repos call. |
| `workflow_ref` | string | `main` | Branch or tag of `workflow_repo` that repos call. |
| `fail_on_severity` | `low`, `medium`, `high` or `critical` | `high` | The dependency check fails a PR that adds a vulnerability at or above this severity. |
| `engine` | `github` or `osv` | `github` | Scanner for the PR check. `github` needs GitHub Advanced Security on private repos; `osv` doesn't. |
| `auto_merge` | list of globs | `[]` | Repos that opt in to auto-approving and auto-merging Dependabot PRs. `["*"]` means every repo. |
| `auto_merge_update_types` | list | patch and minor | Dependabot update types that auto-merge. |
| `schedule_interval` | string | `weekly` | Dependabot's update schedule. |
| `branch` | string | `vulgard/rollout` | Branch vulgard opens rollout PRs from. |

## `deployments`

The stale-deployments topic. [Stale deployments](stale-deployments.md) explains the ideas;
this table is the reference. With `enabled: false`, vulgard builds no AWS or Vercel client.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `false` | Scan AWS and Vercel and track stale deployments and inactive repos. |
| `report_only` | bool | `false` | Write findings to the job summary only: no issues, Linear issues or Slack messages. |
| `stale_days` | int | `30` | A deployment not deployed for this long is flagged. |
| `repo_inactive_days` | int | `90` | A repo with no human commit to its default branch for this long is flagged. |
| `baseline_days` | int | `14` | Time to act once flagged, before the item is overdue. |
| `max_keep_days` | int | `180` | Longest date allowed in `/vulgard keep … until` or `/vulgard active until`. |
| `production_stages` | list | `[production, prod, live]` | A match anywhere in the stage, app or stack name, or tags makes a deployment production. vulgard never deletes production. |
| `shared_stages` | list | `[development, dev, staging, stage, preview, test]` | Stages treated as shared. A stage can't be in both lists. |
| `severity` | map of tier to severity | `{production: high, shared: medium, personal: low}` | Severity per tier, used for escalation and Linear severity labels. Keys must be `production`, `shared` or `personal`. |
| `repo_severity` | severity | `low` | Severity for inactive repos. |
| `people` | map of stage or OS username to handle | `{}` | Marks matching deployments as personal and pings that person. Values must start with `@`. |
| `attribution` | map of app or stack glob to repo | `{}` | Which repo a deployment belongs to. Wins over tags, platform links and manifests. |
| `ignore` | list of app or stack globs | `[]` | Deployments vulgard never tracks. |
| `unattributed_repo` | string | none | Required when `enabled`. Repo whose issue tracks deployments with no known repo. |
| `label` | string | `vulgard-stale` | Label on this topic's tracking issues. |
| `title` | string | `Stale deployments need a baseline` | Title of this topic's tracking issues. |
| `workflows` | map of repo to workflow file | `{}` | A repo's own deploy workflow, used instead of `lifecycle_workflow`. See [Use your own deploy workflow](guides/use-your-own-deploy-workflow.md). |
| `lifecycle_workflow` | string | `vulgard-lifecycle.yml` | Workflow file vulgard dispatches to redeploy or delete. |
| `linear.labels` | list | routed labels | Replaces the routed labels on this topic's Linear issues. |
| `linear.project` | string | routed project | Replaces the routed project. |
| `linear.state` | string | routed state | Replaces the routed state. The team still comes from `linear.teams`. |
| `auto.repos` | list of globs | `[]` | Repos that opt in to automatic ops on personal deployments. Empty means nowhere. |
| `auto.delete` | bool | `false` | `false` redeploys stale personal deployments, `true` deletes them. |
| `auto.personal_stale_days` | int | `90` | A personal deployment not deployed for this long gets an automatic op. So does one whose repo has open critical alerts. |
| `auto.notice_days` | int | `7` | Days of notice on the issue before the op. A keep or cancel stops it. |
| `aws.regions` | list | `[us-east-1]` | Regions to scan. Credentials come from the environment, through GitHub OIDC in CI. |
| `aws.delete_role_arn` | string | none | CloudFormation service role that deletes a stack's resources. |
| `aws.deploy_role_arn` | string | none | Role repos deploy with, written into `vulgard-lifecycle.yml`. |
| `vercel.team_id` | string | none | Vercel team to scan, when the token is set. |
| `vercel.token_env` | string | `VERCEL_TOKEN` | Environment variable holding the Vercel token. |

## `inspector`

**Amazon Inspector** is the AWS service that scans what you have deployed (Lambda functions, EC2 instances, and container images stored in ECR, AWS's container image registry) for packages with known vulnerabilities, and reports each one as a **finding**.

Dependabot only knows the dependencies a repo declares. Inspector sees what is actually running. The catch is that a finding names a resource, such as a Lambda function, and says nothing about the repo that deployed it. vulgard works out the repo, so a finding can reach the team that can fix it.

So far this topic is read-only. `vulgard report --topic inspector` prints the findings grouped by repo, and says what each fix still needs. It opens no issues and sends no messages, and `nag` doesn't accept `--topic inspector`.

```bash
vulgard report --topic inspector                       # a table: one row per repo
vulgard report --topic inspector --format json         # every fix item and resource, and how each got its repo
vulgard report --topic inspector --repo payments-api   # only that repo; unattributed rows are left out
```

**Fix items.** One upgrade of a package fixes every vulnerability that package has in a repo, so vulgard reports a **fix item** per package, not per vulnerability. A fix item holds all the findings for one package in one repo, whichever vulnerabilities and resources they come from. For example, two vulnerabilities in `axios` found on three Lambda functions are one fix item. Its severity is the worst of its findings, and its **required version** (`fixed_in` in the JSON) is the highest fixed version any finding names.

The first table has one row per repo, worst first, then one row per reason a finding has no repo (see [Findings with no repo](#findings-with-no-repo)). The severity columns, `items` and `exploitable` count fix items. `resources` counts the distinct resources affected.

The second table has the same rows and counts items by [fix status](#fix-status). In the JSON, `repos` and `unattributed` list the fix items. Each has its `package`, `ecosystem`, `severity`, `fixed_in`, `status`, `main_versions` (the versions on the default branch), `pr` (`number`, `url` and `target`, the version the pull request moves to, or `null`), `vulnerability_ids`, `exploit_available`, `resources` and the `findings` behind it. The top level has a `status` object with the number of items per status.

```yaml
inspector:
  regions: [us-east-1]
  min_severity: high
  ignore:
    - "scratch-*"                      # never reported
```

| Key | Type | Default | What it does |
|---|---|---|---|
| `regions` | list | `[us-east-1]` | Regions to read findings from. Credentials come from the environment, through GitHub OIDC in CI. The role needs `inspector2:ListFindings`, which the `VulgardLifecycle` role in `infra/` grants. |
| `min_severity` | `critical`, `high`, `medium` or `low` | `high` | The least severe findings to report. Anything more severe is included too. See below for why it defaults to `high`. |
| `ignore` | list of globs | `[]` | Resources never reported. Each glob is matched against the resource name (a Lambda function name, an ECR repository name or an EC2 instance id) and against its CloudFormation stack name. |

**Why `min_severity` defaults to `high`.** An AWS account can hold a very large number of findings. In one account we checked, about 62,000 findings were active and about 22,600 of them were high or critical. Reading all of them is slow, and the report would bury the ones that need action first. Lower it to `medium` or `low` when you want the long tail. Inspector's `INFORMATIONAL` and `UNTRIAGED` findings are never reported, and only package vulnerabilities are, not code or network findings.

### How a finding gets a repo

There is no repo map to maintain for Inspector. vulgard tries these in order and uses the first that answers:

1. **A repo tag on the resource.** A tag is a key and value label on an AWS resource. vulgard reads `vulgard:repo`, `github:repo`, `repository`, `Repository`, `repo` and `Repo`, the same tags the stale topic reads. The value can be `repo`, `org/repo` or a GitHub URL.
2. **The deployment the resource belongs to.** vulgard already finds your deployments for the stale topic (CloudFormation stacks, SST stages and Amplify branches) and knows which repo each came from. A resource says which deployment it belongs to through its tags:
   - `aws:cloudformation:stack-name`, which AWS adds to everything a CloudFormation stack (a group of resources AWS creates and deletes together) creates. Serverless Framework and CDK both deploy this way.
   - `sst:app` and `sst:stage`, which SST adds.
   - `amplify:app-id` and `amplify:branch-name`, which Amplify Gen2 adds.
   - For ECR images only, the repository name. ECR images have no tags, but Serverless names its repository `serverless-<service>-<stage>`, and the stack is `<service>-<stage>`.

The JSON output records which rule was used for each finding (`via` is `tag` or `deployment`) and, for `deployment`, the deployment's name.

### Fix status

Each fix item gets one status that says what has to happen next. vulgard only reads GitHub, so a status is a statement about the code on the repo's default branch and its open pull requests, never a promise about what is running. It checks the statuses below in order and uses the first that holds.

Two terms first. The **dependency graph** is GitHub's list of every package version on a repo's default branch, read from its lockfiles and manifests. A **Dependabot pull request** is a pull request the Dependabot bot opens to upgrade a dependency. A single-package pull request names its package in the title. A grouped one lists its packages in a table in the description, and vulgard reads the version each moves to from the table's `To` column, from lines such as ``Updates `axios` from 1.5.0 to 1.6.0``, and from lines such as ``Removes `zod` ``.

1. `needs_deploy`: the code is already fixed on the default branch, but Inspector still finds the old version, so the fix is not running yet. Either the package is gone from the default branch's dependency graph, or every copy of it there is at or past the required version. Redeploy the repo. This only applies to ecosystems (npm, Maven, PyPI, Go) the default branch declares at all. A Java library in a repo that only has Node manifests is not counted as removed, because the graph says nothing about Java there.
2. `needs_pr_merge`: the fix isn't on the default branch yet, but an open Dependabot pull request in the repo moves the package to the required version or later, or removes it. Merge the pull request, then redeploy. The JSON links it as `pr`. A pull request to a version below the required one doesn't count, because merging it would leave the vulnerability in place.
3. `needs_fix`: the default branch still has a vulnerable version and no open pull request covers it. Someone has to upgrade the package, or ask Dependabot to. This is the status to work through first.
4. `needs_os_update`: the vulnerable package comes from the operating system (Inspector reports its package manager as `OS`). Dependabot can't see these because they aren't in any repo's dependency files. The usual fix is a newer base image or runtime.
5. `unknown`: none of the above can be decided, so a person has to look. This happens when the repo has no dependency graph, when the package's ecosystem isn't on the default branch, when Inspector gives no fixed version and the package is still on the branch, or when a version can't be read as a number.

When Inspector names no fixed version for some finding, the item's required version is unknown. In that case `needs_deploy` only means the package is gone from the branch, and `needs_pr_merge` only means a pull request removes it, because vulgard can't compare any version against an unknown one.

Findings with no repo (see below) have no repository to look in, so their items can only be `needs_os_update` or `unknown`.

### Findings with no repo

These land in rows labelled `unattributed: <reason>`. Each reason says what to fix:

- `shared_asset_repository`: the image is in `sst-asset` or a `cdk-*-container-assets-*` repository. Every app in the account shares these, so the repository name can't say whose image it is.
- `no_deployment_tags`: the resource has none of the tags above, so there is nothing to look up. Tag the resource `vulgard:repo=<repo>`, or tag the stack that creates it, since CloudFormation copies stack tags onto the resources it creates.
- `deployment_not_found`: the resource's tags name a deployment, but vulgard's scan didn't find one with that name. For example, the stack is nested inside another stack, or lives in a region outside `deployments.aws.regions`.
- `deployment_unattributed`: vulgard found the deployment, but no repo is known for it either. Fix it the way you would for a stale deployment. Tag the stack with `github:repo` when it deploys, for example `Tags.of(app).add("github:repo", "<org>/<repo>")` in a CDK app. `deployments.attribution` also works, but it's a map someone has to keep up to date.

## Errors you may see

| Message | Fix |
|---|---|
| `An 'org' is required` | Set `org` or pass `--org`. |
| `Unknown keys in '<section>'` | Fix the spelling, or check the deployed vulgard supports the key. |
| `Unknown severities in sla_days` (or another section) | Use `critical`, `high`, `medium` or `low`. |
| `linear.teams['x'] must be a team key or a mapping with 'team' …` | Give the route a `team`, and only the allowed keys. |
| `linear.leads: no repo routes to X` | Use a team key from `linear.teams` or `linear.default_team`. |
| `linear.label is now linear.labels, a list` | Rename it and make it a list. |
| `rollout.auto_merge is a list of repos` | Write it as a list, for example `["web-*"]`. |
| `exceptions[i] needs a 'reason' and an 'expires' date` | Add both. |
| `exceptions[i] needs an 'advisory' or a 'package'` | Add one of them. |
| `deployments.unattributed_repo is required` | Name the repo for deployments with no known repo. |
| `deployments: stages can't be both production and shared` | Remove the stage from one list. |
| `deployments.people values are GitHub handles starting with @` | Add the `@`. |
| `deployments.severity: unknown tiers` | Use `production`, `shared` or `personal`. |
| `inspector.min_severity must be one of` | Use `critical`, `high`, `medium` or `low`. |
| `Inspector scan failed` | Inspector couldn't be read. The message has AWS's reason, for example missing `inspector2:ListFindings` permission or expired credentials. |
