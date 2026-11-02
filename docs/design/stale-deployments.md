# Stale deployments

## Problem

Every deployment and every repo has to show it's still in use. A stack that hasn't been deployed
in 30 days needs a baseline: bring it up to date or delete it. So does a repo with no commits in
90 days: mark it active or clean it up. Personal stacks that haven't been deployed in 90 days, or
that carry critical vulnerabilities, get redeployed or deleted automatically. The supported
frameworks are Serverless v3 (via OSLS), SST v3/v4, Amplify, Vercel and CDK. All of it goes
through the same tracking issues, escalation, Linear tickets, Slack messages and leaderboard as
vulnerabilities.

Four things about the existing system shape the design:

- **The pipeline only knows about alerts.** `nag.py`, `linear.py`, `slack.py` and `render.py`
  all read `RepoReport` alert fields directly.
- **Humans have nowhere to record a decision.** Config `exceptions` live in an admin-only secret.
  Issue state disappears when an issue closes and a fresh one opens.
- **Only a repo's own build context can redeploy it.** The stalest repos are also the ones whose
  builds have rotted.
- **SST v3/v4 doesn't use CloudFormation.** Its state is Pulumi JSON stored at
  `app/<app>/<stage>.json` in the bucket that the SSM parameter `/sst/bootstrap` points to
  (verified in `sst/sst` `pkg/project/provider/aws.go`). Only `sst remove` can delete it.

## Usage (caller's view)

```yaml
# vulgard.yml
deployments:
  enabled: true
  stale_days: 30
  baseline_days: 14            # time to act once flagged, then overdue, then escalation
  repo_inactive_days: 90
  production_stages: [production, prod, live]
  shared_stages: [development, dev, staging, stage, preview, test]
  people: {juzer: "@juzer-pam"}          # stage / OS username -> GitHub handle
  attribution: {"PamKnowledge-*": pam-knowledge}
  ignore: ["CDKToolkit"]
  unattributed_repo: vulgard
  workflows: {pam-agent-core: deploy-stage.yml}   # use an existing deploy workflow
  aws: {regions: [us-east-1]}
  vercel: {team_id: team_xxx}
  auto: {repos: ["pam-*"], delete: false, personal_stale_days: 90, notice_days: 7}
  linear: {labels: [vulgard, stale], project: Baselines}
```

Humans record a baseline by commenting on the repo's `vulgard-stale` tracking issue:

```
/vulgard redeploy pam-agent-core/development
/vulgard delete   pam-agent-core/feature-x          # rejected for production
/vulgard keep     api-prod until 2027-01-15: frozen until the Q1 migration
/vulgard active   until 2027-03-01: stable library, no changes needed
/vulgard cancel   pam-agent-core/juzer              # stop a scheduled automatic op
```

Deploying, deleting, committing or archiving by hand works too. The next run sees the change.

```bash
vulgard report --topic stale --all     # every deployment: repo, how it was attributed, tier, person
vulgard nag --topic stale              # full dry run
vulgard nag --slack --linear --redact --apply             # weekly: both topics + leaderboard
vulgard nag --topic stale --no-leaderboard --apply --execute   # daily: perform due ops
```

## Shape

**Data comes first.** A `Sighting` is what a scanner sees for one control plane. A
`Deployment` is a classified sighting: its repo, its `Attribution`, its `Tier` and its person.
`NativeRef = CfnStack | SstStage | AmplifyBranch | VercelProject` is the handle that operations
match on. A `StaleFinding` uses the alert SLA vocabulary: severity, flagged_at, deadline and
`SlaStatus`. `Command` and `Decisions` are the fold of the comment thread. An `Op` carries a
deterministic `request_id`.

1. **One generic engine, with topics plugged in.** `RepoPlan` carries rendered content plus a
   `TopicSpec`. `nag.track`, `linear.sync_linear` and `slack.notify_slack` never read domain
   fields. A topic is a module with a pure `plan_repo(report, config, issue, now) -> RepoPlan`.
   Vulnerabilities (`vulns.py`) are the first topic, unchanged, and stale is the second. Each
   repo gets one GitHub issue and one Linear issue per topic, because each topic closes on its
   own condition.
2. **Staleness is an SLA.** `flagged_at = last_deployed + stale_days` and
   `deadline = flagged_at + baseline_days`. Escalation, Linear severity labels and "most
   overdue" therefore work unchanged. Every clock comes from cloud and GitHub timestamps and is
   never stored.
3. **Baselines are `/vulgard` commands, re-folded from the thread every run.** Each comment has
   one authenticated author and the thread is append-only, so vulgard keeps no copy of a
   decision that could drift. The engine reopens the latest closed tracking issue instead of
   creating a new one, so decisions survive clean periods. A request counts as done when the
   world shows it: the deployment was redeployed after the comment, or it's gone.
4. **Redeploys go through the repo; deletes are native wherever possible.**
   - Redeploys dispatch the repo's lifecycle workflow, or the workflow named in
     `deployments.workflows`. Amplify Hosting and Vercel redeploy through their own release
     APIs.
   - Deletes call CloudFormation `DeleteStack` (after emptying the Serverless deployment
     bucket), Amplify `DeleteBranch` or Vercel `DELETE project`.
   - SST is the exception: it can only be deleted with `sst remove`, through the workflow.
5. **Safety is enforced by the types, then rechecked at runtime.**
   - A delete step can only be built from a `SafeDelete`, and only `check_delete` creates one.
   - A deployment is PERSONAL only on positive evidence: its stage maps to a known person, or
     it's an Amplify sandbox.
   - Automatic ops need all four of: an `auto.repos` match, `--apply`, `--execute`, and a
     notice at least `auto.notice_days` old. The notice time is the `created_at` of vulgard's own
     comment, found by a hidden marker in a comment whose author ends in `[bot]`, so editing the
     issue body can't backdate it. A notice only counts if it is newer than the deployment's last
     deploy and the last keep, and a notice posted today never runs today.
   - `recheck` repeats the planning rules against a fresh read of the target right before the
     delete, for every framework including SST.
6. **Ops are idempotent.** `request_id` is a hash of the decision. It goes into the workflow
   run name, the CFN `ClientRequestToken`, the Amplify `jobReason` and the Vercel `meta`.
   `execute` always looks for an existing op before starting one.
7. **Discovery runs in two phases.** I/O-only scanners feed a pure `classify`. A
   `deployments.attribution` glob wins. Otherwise attribution goes through the repo tag, the
   platform's own repo link, and manifest identity on default branches, then falls back to
   `unattributed_repo`.

Module map. The stale path is `cli`, then `stale`, then `nag`/`lifecycle`.

| Module | Role |
|---|---|
| `plan.py` | generic plan types |
| `nag.py` | engine: issue lifecycle, state, Linear sync, writes |
| `vulns.py` | vulnerabilities topic |
| `estate.py` | estate types, `classify`, `discover` |
| `aws.py` | AWS scanners and native ops |
| `vercel.py` | Vercel scanner and ops |
| `baseline.py` | command parsing and `fold` |
| `lifecycle.py` | `Op`, `check_delete`, `recheck`, notices, `reconcile` (pure) |
| `execute.py` | the `Executor` protocol and idempotent `execute` |
| `executor.py` | the live executor: GitHub, AWS and Vercel, failures become `OpFailed` |
| `stale.py` | stale model and policy: findings, `evaluate`, `survey` |
| `stale_plan.py` | stale topic: the `RepoPlan` for one repo |
| `stale_render.py` | stale topic: issue body, comments, summary, leaderboard, tables |
| `repos.py` | GitHub-side repo data: selection, owners, framework index, activity |
| `topics.py` | one runner per topic, so `nag` loops instead of branching |

What it deliberately doesn't do:

- run framework CLIs inside vulgard's own job
- archive repos
- delete production, even when a human asks
- act automatically on SHARED stacks
- run a webhook server

## Synthesis decision

The base is candidate B, chosen on its rubric scores. A second reviewer reached the same
choice independently. It had the stronger answers to the two hardest problems:

- **Close conditions.** Separate topics each close on their own condition. With a single
  combined issue, a repo with 1,431 open alerts and one stale stack would stay open until both
  were fixed.
- **Safety.** `SafeDelete`, positive-evidence PERSONAL, the notice period that starts only after
  the comment is posted, and deterministic `request_id`s.

Taken from candidate A:

- `deployments.workflows`, so repos with an existing deploy workflow (`pam-agent-core`'s
  `deploy-stage.yml`) don't wait on `rollout --lifecycle`
- `Sighting.in_progress` (CloudFormation `*_IN_PROGRESS` or an SST lock object), so vulgard
  never dispatches over a human's deploy

Fixes from the reviewer:

- Bot commits (`[bot]` authors) don't count toward repo activity.
- Vercel projects are never auto-deleted. A project is PRODUCTION when it has a custom
  production domain, so only a human request can delete one without a domain.

Fixes made while building it:

- CDK stacks are detected by the `BootstrapVersion` parameter in `DescribeStacks`, not by
  calling `ListStackResources` for every stack.
- The SST state path was checked against SST's source, and a reviewer's challenge to it was wrong.

Rejected from candidate A:

- one combined issue per repo
- baselines kept in three places (config, comments and issue state)
- personal stacks detected by stage-name heuristics
- a 24-hour cooldown instead of idempotency keys

## Tradeoffs accepted

- We accept refactoring working vulnerability code in exchange for one pipeline that a third
  topic can join without touching the engine.
- We accept two issues and two Linear tickets for a repo that's both vulnerable and stale, in
  exchange for crisp close conditions.
- We accept reopening old issues, and so longer threads, in exchange for durable decisions.
- We accept that commands can take up to a day to act on, in exchange for having no webhook
  infrastructure.
- We accept that stages are SHARED until `people` lists them, in exchange for never
  auto-deleting on a guess.

## Alternatives considered

- **Extend `RepoReport` and keep one issue per repo.** The diff is smaller, but every module that
  reads alerts gets a second branch, and the combined issue never closes. The interface is
  shallow.
- **A parallel stale pipeline that reuses only the clients.** It would duplicate issue lifecycle,
  Linear dedupe, reopen and severity logic, and Slack routing. That's two ways to do one task.
- **Baselines in a repo file or in `vulgard.yml`.** A repo file means a PR for every decision,
  and the commit itself resets the repo clock. `vulgard.yml` is admin-only.
- **Every delete through the repo's workflow.** Deleting the stalest stacks would then depend on
  90-day-old builds still working.

## Decisions on the open questions

- **Day-one volume.** Org-wide, but report-only for the first week
  (`deployments.report_only`): findings go to the workflow summary, with no issues or pings.
- **Lifecycle role.** A new `VulgardLifecycle` role, not `GithubCI`. CloudFormation deletes
  pass a separate `VulgardStackDelete` service role (`RoleARN`). Without it, `DeleteStack`
  deletes resources with the caller's own permissions, so the lifecycle role couldn't stay
  narrow.
- **Termination protection.** It blocks automatic and requested deletes: a protected stack is
  classified as production. vulgard doesn't turn protection on itself.

## Risks

- Generic redeploys through `vulgard-lifecycle.yml` fail for repos whose deploys need secrets
  or build steps beyond `npm ci`. Those repos set `deployments.workflows`.
- The notice marker is trusted when its comment's author ends in `[bot]`. Another GitHub App
  with write access to the repo could post one. Pinning the vulgard App's login would close
  that, at the cost of one more setting.
- A failed op is retried on every run and comments on the issue each time. Nothing throttles
  the repeats yet.
- A workflow run that carries the request id counts as started whatever its conclusion, so a
  failed lifecycle run is never retried and its request stays pending. Posting the command again
  gives it a new request id.
- A redeploy that changes nothing (CDK's "no changes", or Serverless skipping an unchanged
  service) doesn't move the stack's update time, so the request never reads as done.

## Implementation slices

1. **Engine extraction.** Generic `plan.py` and `nag.track`, a `vulns.py` topic, and REOPEN. One
   behavior change for vulnerabilities: a closed tracking issue is reopened when alerts return,
   instead of a new one being opened. Everything else is byte-identical.
2. **Read-only discovery.** `estate.py`, the `aws.py` and `vercel.py` scanners, config, and
   `report --topic stale --all`.
3. **Stale topic.** Baselines, the planner, notifications and leaderboard sections, without
   `--execute`.
4. **Lifecycle.** `reconcile`, `execute`, the executors, the reusable `lifecycle.yml`, and
   `rollout --lifecycle`.
