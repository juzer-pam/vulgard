# vulgard

Org-wide automation that makes teams actually deal with vulnerable dependencies.
Turning on Dependabot isn't enough if nobody merges its PRs. vulgard covers the rest:

| Problem | What vulgard does |
|---|---|
| Alerts pile up and nobody owns them | Opens **one tracking issue per repo**, assigns and mentions the owners, and **comments when an alert goes past its SLA**. Re-pings on a schedule and **escalates** to security leads when criticals or highs stay overdue. |
| GitHub notifications get ignored | Posts **one Slack message per team channel** per run, sends each owner one DM covering all their repos, and posts escalations to a security channel. **Mirrors each tracking issue into Linear** in the owning team, with priority and due date taken from the worst alert. If someone closes the Linear issue while alerts are still open, vulgard reopens it. |
| Everything looks equally urgent | Alerts whose CVE is on **CISA's Known Exploited Vulnerabilities** list get a 3-day deadline and escalate as soon as they're overdue. |
| "Won't fix" decisions are invisible and permanent | **Exceptions in `vulgard.yml` need a reason and an expiry date.** Accepted risks stay listed in the tracking issue and come back when they expire. The leaderboard names anyone who dismissed a critical or high alert without a comment. |
| Fixes go unnoticed | A **leaderboard** in the org-wide Slack channel ranks teams by alerts fixed in the last 7 days and by alerts past deadline. |
| Dependabot PRs rot | Dependabot config that **groups security, minor/patch, and major updates into a few PRs per ecosystem** (not one PR per package). Repos that opt in also **auto-approve and auto-merge** minor and patch PRs once CI passes. **A PR that passes CI but is still open after 2 days** pings its owners in GitHub, Slack, and Linear, listing the alerts it would fix. The tracking issue lists stale PRs. |
| New vulnerabilities get merged | A reusable **`vulgard / guard / scan`** check fails any PR that adds a dependency with a known vulnerability, and an **org ruleset** makes it required. |

Everything that writes to GitHub runs as a **dry run by default**. Add `--apply` to make changes.

## Documentation

This README is the setup and reference guide. The rest of the docs are written for someone new
to the project.

**To understand how it works:**

- [How vulgard works](docs/how-it-works.md) explains the terms, follows one alert from opening
  to closing, and walks through the code. Start here if you're new to the project or to
  Dependabot.
- [How stale deployments work](docs/stale-deployments.md) does the same for deployments nobody
  has updated in a while.
- [The stale-deployments design doc](docs/design/stale-deployments.md) explains why it's
  built the way it is.

**If vulgard pinged you:**

- [Fix the alerts on a vulgard tracking issue](docs/guides/fix-vulnerability-alerts.md)
- [Respond to a stale-deployments issue](docs/guides/respond-to-stale-deployments.md)
- [Use your own deploy workflow](docs/guides/use-your-own-deploy-workflow.md), if vulgard's
  generic one can't deploy your repo
- [Troubleshooting](docs/guides/troubleshooting.md)

**If you run vulgard:** follow [Rolling it out](#rolling-it-out-to-a-real-org) below, then
[Set up stale deployments](docs/guides/set-up-stale-deployments.md). The
[configuration reference](docs/configuration.md) lists every setting, its default and its
validation rules.

## How it fits together

```
this repo (acme/vulgard)
├── .github/workflows/nag.yml             scheduled: vulgard nag --apply --slack --linear
├── .github/workflows/guard.yml           reusable PR check (GitHub or OSV engine)
├── .github/workflows/automerge.yml       reusable auto-merge for Dependabot PRs
├── .github/workflows/guard-required.yml  for `enforce --mode workflow`
├── .github/workflows/lifecycle.yml       reusable redeploy and remove, for stale deployments
└── infra/vulgard-roles.yaml              CloudFormation template for the AWS roles vulgard uses

every other repo (installed by `vulgard rollout`)
├── .github/dependabot.yml          generated from detected ecosystems
└── .github/workflows/vulgard.yml   calls guard.yml, plus automerge.yml if the repo opts in
```

On a pull request the checks show up as `vulgard / guard / scan` and, in repos that opt in
to auto-merge, `vulgard / automerge / approve` (skipped on PRs not opened by Dependabot).

## Try it locally (no token needed)

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
V="uv run vulgard --config examples/vulgard.yml --fixtures examples/demo-org.json"
$V report                    # SLA status per repo
$V report --format markdown  # what goes in the Actions job summary
$V nag                       # what issues/comments/escalations it would make
$V nag --slack --linear      # plus Slack messages and Linear issues (fakes, no tokens)
$V rollout --show            # PRs it would open, with generated files
$V enforce                   # the org ruleset it would create
uv run pytest
```

`examples/demo-org.json` is a fake org. Dates like `"@-19d"` resolve relative to today so
the demo never goes stale.

## Rolling it out to a real org

1. **Fork this repo into your org**, keeping the name `vulgard`. The fork stays public,
   which is what lets your private and internal repos call its reusable workflows.
   Don't commit org settings to the fork (step 4 keeps them in an Actions secret),
   so **Sync fork** always applies upstream updates cleanly.

   GitHub turns off workflows on new forks. Open the fork's *Actions* tab and click
   *I understand my workflows, go ahead and enable them*.

2. **Create a GitHub App** owned by the org and install it on all repositories, with these
   permissions:
   - Repository: Dependabot alerts (read), Issues (read/write), Contents (read/write),
     Pull requests (read/write), Administration (read/write), Workflows (read/write),
     Checks (read), Commit statuses (read). The last two let vulgard see whether a
     Dependabot PR's CI passed.
   - Organization: Administration (read/write), needed only for `enforce`

   Save its ID as the Actions variable `VULGARD_APP_ID` and its private key as the secret
   `VULGARD_APP_PRIVATE_KEY`.

3. **Connect Slack and Linear** (both optional; each is skipped if its secret is missing):
   - **Slack:** create a Slack app with bot scopes `chat:write`, `chat:write.public`, and
     `im:write`, install it, and save the bot token as the secret `SLACK_BOT_TOKEN`. An
     incoming webhook in `SLACK_WEBHOOK_URL` still works for the leaderboard alone.
   - **Linear:** create an API key for a bot or service account (*Settings → Security &
     access → Personal API keys*) and save it as the secret `LINEAR_API_KEY`.

4. **Write your org's config** and save it as the Actions **secret** `VULGARD_CONFIG` on the
   fork. Start from [`vulgard.yml`](vulgard.yml), save your copy as `org.yml`, then run
   `gh secret set VULGARD_CONFIG -R <org>/vulgard < org.yml`. The nag job writes it to
   `vulgard.yml` before it runs. Don't use an Actions *variable*: Actions prints step
   environment values in run logs, which anyone can read on a public fork, and only secrets
   are masked. Secrets can't be read back, so keep `org.yml` somewhere private (a private
   repo or a password manager) as the source of truth. The
   [configuration reference](docs/configuration.md) describes every key. Settings to fill
   in: SLA days, owners, escalation contacts, included and excluded repos, `rollout.engine`
   (see the caveats below), `rollout.auto_merge`, and the `slack` and `linear` routing:
   - `rollout.auto_merge` lists the repos (names or globs like `web-*`) whose minor and
     patch Dependabot PRs merge automatically. It's empty by default, so nothing
     auto-merges until a repo is added. `["*"]` turns it on everywhere.
   - `slack.default_channel` is the org-wide channel, for example `#engineering`. It gets
     the weekly leaderboard, plus updates for repos that `slack.channels` doesn't map.
   - `slack.channels` maps a repo name, a repo glob, or an owner handle (from config or
     `CODEOWNERS`) to a team channel. Matching order: exact repo, repo glob, then owner.
   - `linear.teams` maps a repo name, repo glob, or owner handle to a Linear team key. Repos
     with no match go to `linear.default_team`. `linear.labels`, `linear.project`, and
     `linear.state` (for example `Triage`) set what new issues get. Map an entry to
     `{team, labels, project, state, severity_labels}` instead of a bare key to override them
     for that repo or team. Labels and project apply when vulgard creates the issue; the state
     is also used when it reopens one. `severity_labels` maps the worst open severity to a
     label (for example `{critical: Critical, high: High}`), and vulgard swaps it as that
     changes. A label name matches the team's own label first, then a workspace
     label, and vulgard creates a workspace label if neither exists.
   - `slack.users` maps GitHub handles to Slack user IDs, used for mentions and DMs, or to
     user group IDs (`S…`) for team mentions. Add each `linear.leads` email too, so
     `rollout --slack` can DM leads their rollout PRs to approve.
   - `linear.users` maps GitHub handles to Linear emails. `linear.leads` maps a Linear team
     key to its lead's email, for example `{INB: lead@your-org.com}`. vulgard assigns a new
     Linear issue to the repo's first owner listed in `linear.users`. If none is listed, the
     issue goes to the lead of the team it lands in. Every key in `linear.leads` must be a team
     that `linear.teams` or `linear.default_team` routes to, so a typo fails config loading.
     vulgard sets the assignee only when it creates the issue.

5. **Roll out to repos.** Run with a token that has the permissions above (for example
   `export GITHUB_TOKEN=$(gh auth token)` for an org admin):

   ```bash
   uv run vulgard --config org.yml --org acme rollout          # review the plan
   uv run vulgard --config org.yml --org acme rollout --apply  # open PRs; enables alerts,
                                                                 # security updates, and
                                                                 # auto-merge if opted in
   ```

   Or run the **rollout** workflow from the Actions tab. It uses the GitHub App, and with
   *slack* ticked it DMs each team lead the open rollout PRs in their team's repos.

   To pilot first, set `repos.include` to a few repos in `org.yml`, update the secret,
   and widen it later.

   Re-running is safe. Repos that are up to date are skipped. A `vulgard.yml` that vulgard
   wrote (it starts with `# Managed by vulgard`) is refreshed when config changes, for
   example after opting a repo in to auto-merge. If the rollout PR is still open, the new
   files are pushed to it instead of opening another. A workflow file without that header
   is never overwritten, and neither is an existing `dependabot.yml`.

6. **Make the check required** once those PRs are merged:

   ```bash
   uv run vulgard --config org.yml --org acme enforce --apply
   ```

   This creates or updates the org ruleset *"vulgard: block vulnerable dependencies"*,
   requiring `guard / scan` on default branches of repos that have the
   workflow. Re-run it after more rollout PRs merge. On GitHub Enterprise Cloud, use
   `--mode workflow` instead: the ruleset runs `guard-required.yml` on every repo
   directly, with no per-repo files.

7. **Turn on the nag job.** `nag.yml` runs weekdays at 15:00 UTC with `--slack --linear`.
   Trigger it once manually with *apply* unchecked to preview.

## How nagging works

This is the short reference. [How vulgard works](docs/how-it-works.md) explains each step
with a worked example.

- Each alert gets a deadline: `sla_days[severity]` days after it opened (default: critical 7,
  high 30, medium 90, low 180). CVEs on CISA's KEV list get `kev.sla_days` (default 3).
- Each repo with open alerts or stale Dependabot PRs gets one issue labeled `vulgard`. It
  lists overdue, due-soon, and within-SLA alerts, the patched version, the Dependabot PR
  that fixes each one, and any accepted risks with their expiry.
- Owners come from `owners:` in config, then the `*` rule in `CODEOWNERS`, then
  `default_owners`. vulgard assigns individual owners, but not teams, to the issue.
- Comments and Slack messages, which are what notify people, are only sent when:
  - a tracking issue is first opened,
  - an alert newly passes its deadline,
  - a Dependabot PR newly passes CI with no conflicts and has been open `ready_pr_days`
    (default 2, which gives auto-merge time to act) without being merged,
  - `reminder_interval_days` have passed and something is still overdue or stale, or
  - an alert is more than `escalation.after_days_overdue` past due, or a KEV alert is past
    due at all (each alert escalates once).
- Slack messages are batched: each channel and each owner gets at most one message per run.
- vulgard rewrites the Linear issue's description, priority, and due date on each run.
  Priority is urgent for exploited alerts or overdue criticals, and the due date is the
  earliest alert deadline. vulgard comments on the Linear issue for newly overdue alerts,
  newly ready PRs, and escalations. It reopens the issue if someone closes it while alerts
  remain, and closes it when the GitHub issue closes.
- State, including the Linear issue link, lives in a hidden HTML comment in the GitHub issue
  body, so the bot needs no database.
- When every alert is resolved, the issue is closed with a thank-you.

To silence an alert legitimately, either dismiss it in GitHub with a reason (permanent; the
leaderboard flags high-severity dismissals with no comment), or add an exception that expires:

```yaml
exceptions:
  - repo: payments-api            # glob, default "*"
    advisory: GHSA-xxxx-xxxx-xxxx # or a CVE id, and/or `package: lodash`
    reason: Not reachable from user input; see SEC-123
    expires: 2027-03-31
```

## Stale deployments

With `deployments.enabled`, `nag` also tracks deployments in AWS (Serverless Framework v3 and
CDK stacks in CloudFormation, SST v3/v4 state, Amplify branches) and Vercel, and repos nobody
commits to. This section is the reference. For an explanation from scratch, read
[How stale deployments work](docs/stale-deployments.md). To turn it on step by step, follow
[Set up stale deployments](docs/guides/set-up-stale-deployments.md).
[The design doc](docs/design/stale-deployments.md) has the rationale.

- A deployment not deployed in `stale_days` (30), or a repo with no human commits in
  `repo_inactive_days` (90), needs a baseline within `baseline_days` (14). The clocks come from
  AWS, Vercel and GitHub timestamps, so editing the issue can't reset them.
- Each such repo gets one issue labeled `vulgard-stale`, with the same reminders, escalation,
  Slack digests, DMs (including the person a personal stack belongs to), Linear issue, and
  leaderboard section as alerts. Severity comes from the tier: production high, shared medium,
  personal low.
- Record a baseline by commenting on that issue:

  ```text
  /vulgard redeploy <name>                       bring it up to date
  /vulgard delete <name>                         delete it (never production)
  /vulgard keep <name> until 2027-01-31: why     leave it as it is until then
  /vulgard active until 2027-01-31: why          the repo is maintained without commits
  /vulgard cancel <name>                         cancel an earlier command
  ```

  Only people with write access can baseline. vulgard re-reads the thread every run. The latest
  command wins, and an expired keep brings the finding back. Deploying, deleting or committing
  by hand also counts.
- `nag --apply --execute` carries out `redeploy` and `delete` requests, and comments on the
  issue when one starts and once when it ends. Each op has a fixed request id, so it runs once
  however often `nag` does. A failed op isn't retried: post the command again to get a new
  request id. A successful redeploy counts as a deploy even when CloudFormation had nothing to
  update.

  | Framework | Redeploy | Delete |
  |---|---|---|
  | Serverless v3 (OSLS), CDK | the repo's lifecycle workflow | CloudFormation `DeleteStack` (Serverless bucket emptied first) |
  | SST v3/v4 | lifecycle workflow (`sst deploy`) | lifecycle workflow (`sst remove`) |
  | Amplify Hosting | `StartJob` (release) | `DeleteBranch` |
  | Amplify sandbox | not supported (it runs from a laptop) | CloudFormation `DeleteStack` |
  | Vercel | rebuild of the production deployment | `DELETE project` (on request only) |

  `vulgard rollout --lifecycle` opens a PR adding `vulgard-lifecycle.yml` to each repo with a
  Serverless, SST or CDK app. Repos with their own deploy workflow can list it in
  `deployments.workflows` instead; vulgard dispatches it with `action`, `framework`, `app`,
  `stage`, `stack` and `request_id` inputs, and finds the run by the request id in its run name.
- Automatic ops apply only to personal deployments in repos listed in `deployments.auto.repos`.
  A deployment is personal when its stage, or an Amplify sandbox's user, is listed in
  `deployments.people`. A personal deployment that hasn't
  deployed in `auto.personal_stale_days` (90), or whose repo has open critical alerts, gets a
  notice on the issue mentioning its owner. After `auto.notice_days` (7), the next
  `--execute` run redeploys it, or deletes it with `auto.delete: true`.
  `/vulgard keep` or `/vulgard cancel` stops it. The 7 days count from vulgard's own notice
  comment, so editing the issue body can't shorten them, and a notice older than the stack's
  last deploy or last keep no longer counts.
- vulgard never deletes production or protected deployments. Those are a production stage or
  tag, CloudFormation termination protection, an Amplify production branch (or one named `main`
  or `master`), and a Vercel project with a custom domain. Before every delete it re-reads the
  live target and skips it if someone redeployed, protected or reclassified it since.

- Deployments with no known repo land in `unattributed_repo`. Tag stacks with `vulgard:repo`,
  or map them in `deployments.attribution`.
- `vulgard report --topic stale` lists every stale deployment and inactive repo and writes
  nothing. To trial the topic org-wide, set `deployments.report_only: true`. `nag` then opens no
  issues, Linear issues or Slack messages. Run without `--redact`, it writes the findings to the
  workflow summary. The scheduled job redacts its output, so it only logs how many repos would
  get an issue. Use `report --topic stale` for the list.

### AWS roles for stale deployments

The `nag` job assumes `VULGARD_AWS_ROLE` (repo variable) through GitHub OIDC. The
CloudFormation template `infra/vulgard-roles.yaml` creates both roles below, with no install
needed. It starts read-only, and the `Writes=true` parameter adds the write permissions. See
[Set up stale deployments](docs/guides/set-up-stale-deployments.md#step-1-create-the-aws-roles)
for the options.

- `VulgardLifecycle`, trusted by the vulgard repo's workflows:
  - Reads: `cloudformation:DescribeStacks`, `DescribeStackEvents`; `ssm:GetParameter` on
    `/sst/bootstrap`; `s3:ListBucket` and `s3:GetObject` on the SST state bucket;
    `amplify:ListApps`, `ListBranches`, `ListJobs`, `GetApp`, `GetBranch`;
    `inspector2:ListFindings`, `lambda:ListFunctions`, `lambda:GetFunction`, `lambda:ListTags`,
    `ecs:ListTaskDefinitions`, `ecs:DescribeTaskDefinition`, for `report --topic inspector`.
  - Writes: `cloudformation:DeleteStack`; `iam:PassRole` on `VulgardStackDelete` only;
    `s3:ListBucketVersions`, `s3:DeleteObject` and `s3:DeleteObjectVersion` on
    `arn:aws:s3:::*-serverlessdeploymentbucket-*`; `amplify:StartJob`, `amplify:DeleteBranch`.
- `VulgardStackDelete`, trusted by `cloudformation.amazonaws.com` and set as
  `deployments.aws.delete_role_arn`. CloudFormation deletes a stack's resources with this role,
  so `VulgardLifecycle` itself never needs permission to delete Lambdas, tables or roles.

Redeploys and SST removes run in the target repo with its own deploy role
(`deployments.aws.deploy_role_arn`, e.g. `GithubCI`). The vulgard GitHub App needs
the Actions write permission to dispatch them. Set the `VULGARD_EXECUTE` variable to `true` to add
`--execute` to the scheduled run.

Two gates keep a manual run from bypassing the issue thread. Running the `nag` workflow by hand
with `execute` checked needs repo admin. The per-repo `vulgard-lifecycle.yml` accepts a dispatch
only from an app (such as vulgard's) or a repo admin, and refuses to delete a stage with a
production word (`prod`, `prd`, `production`, `live`, in any case) in its name.

## Caveats

- **The `github` engine** (GitHub's dependency-review action) needs the dependency graph,
  which on **private repos requires GitHub Code Security (GHAS)**. Without it, set
  `rollout.engine: osv` to use OSV-Scanner, which works everywhere.
- **Auto-merge** (opt-in per repo) only waits for checks that are *required*. If a repo has no required
  checks, Dependabot PRs merge right away. If PR reviews are required, enable *"Allow GitHub
  Actions to create and approve pull requests"* in the org's Actions settings.
- **Org rulesets** need a GitHub plan that supports them, and `--mode workflow` needs
  Enterprise Cloud.
- The org Dependabot alerts API only returns repos the token can see. Use an org-wide App
  installation.

## Development

CI (`.github/workflows/ci.yml`) runs on every PR in two jobs:

- `test` runs `ruff check`, `pytest`, and dry runs of `report` and `nag` against the demo org.
- `types` runs `mypy`.
- `infra` checks `infra/vulgard-roles.yaml` with cfn-lint.

The same commands work locally:

```bash
uv run ruff check .
uv run pytest
uv run mypy
```

For a suggested reading order, see [Reading the code](docs/how-it-works.md#reading-the-code)
and, for the stale path, [its counterpart](docs/stale-deployments.md#reading-the-code). Code
lives in `src/vulgard/`.

| Module | What it holds |
|---|---|
| `cli.py` | Command-line parsing and the four commands |
| `topics.py` | One `nag` runner per topic: `run_vulns` and `run_stale` |
| `plan.py` | Plan types shared by every topic, and the state stored in tracking issues |
| `nag.py` | The engine: writes tracking issues and comments, and syncs Linear, for every topic |
| `vulns.py` | Vulnerabilities topic: collecting alerts, `plan_repo`, the leaderboard |
| `policy.py` | SLA evaluation, exceptions, escalation rules, the weekly fixed and dismissed summary |
| `render.py` | Issue, comment, and summary markdown for vulnerabilities |
| `stale.py`, `stale_plan.py`, `stale_render.py` | Stale topic: findings and SLAs, the per-repo plan, and its markdown |
| `estate.py` | Deployment types, `classify` (repo, tier, person), and `discover` |
| `aws.py`, `vercel.py` | Deployment scanners and native operations |
| `baseline.py` | Parsing `/vulgard` commands and folding a comment thread into decisions |
| `lifecycle.py` | Which redeploys and deletes to run, notices, and the safety checks |
| `execute.py`, `executor.py` | Running one op idempotently, and the live GitHub, AWS and Vercel executor |
| `repos.py` | Repo selection, owners, the framework index, and commit activity |
| `linear.py`, `slack.py` | Linear sync; Slack routing, DMs, and the leaderboard |
| `kev.py` | The CISA KEV feed |
| `rollout.py`, `enforce.py` | Generated Dependabot config and workflows; org rulesets |
| `github.py`, `clients.py` | The GitHub REST and GraphQL client; building the live clients |
| `config.py` | Loading `vulgard.yml`, rejecting unknown keys |
| `fixtures.py` | Offline fakes for GitHub, Linear and Slack, plus a fake deployment scanner and executor, used by the demo and tests |
