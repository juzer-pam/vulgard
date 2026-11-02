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
