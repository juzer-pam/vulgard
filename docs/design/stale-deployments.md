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
  linear: {team: PLAT, labels: [vulgard, stale]}
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
`SlaStatus`. `Command` and `Decisions` are the fold of the comment thread. An `OpRecord` carries
a deterministic `request_id`.

1. **One generic engine, with topics plugged in.** `RepoPlan` carries rendered content plus a
   `TopicSpec`. `nag.track`, `linear.sync_linear` and `slack.notify_slack` never read domain
   fields. A topic implements `plan(subject, prev, issue, now) -> RepoPlan`. Vulnerabilities
   become the first topic, unchanged; stale is the second. Each repo gets one GitHub issue and
   one Linear issue per topic, because each topic closes on its own condition (per
   information-leakage).
2. **Staleness is an SLA.** `flagged_at = last_deployed + stale_days` and
   `deadline = flagged_at + baseline_days`. Escalation, Linear severity labels and "most
   overdue" therefore work unchanged. Every clock comes from cloud and GitHub timestamps and is
   never stored.
3. **Baselines are `/vulgard` commands, re-folded from the thread every run.** The thread is
   per-actor and append-only, and merged when read (per
   separate-before-serializing-shared-state). The engine reopens the latest closed tracking
   issue instead of creating a new one, so decisions survive clean periods. Whether a request
   is done is read from the world: redeployed after the comment, or gone.
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
     notice period whose clock starts only once the @mention comment was actually posted.
   - The executor re-reads the live target before deleting.
6. **Ops are idempotent.** `request_id` is a hash of the decision. It goes into the workflow
   run name, the CFN `ClientRequestToken`, the Amplify `jobReason` and the Vercel `meta`.
   `execute` always looks for an existing op before starting one.
7. **Discovery runs in two phases.** I/O-only scanners feed a pure `classify`. Attribution
   order: tag, then platform link, then manifest identity on default branches, then config
   glob, then `unattributed_repo`.

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
| `lifecycle.py` | `reconcile`, the framework table, `execute` |
| `stale.py` | stale topic: policy, planner, rendering |

What it deliberately doesn't do:

- run framework CLIs inside vulgard's own job
- archive repos
- delete production, even when a human asks
- act automatically on SHARED stacks
- run a webhook server

## Synthesis decision

The base is the Opus candidate, chosen on its rubric scores. The Gemini cross-judge reached the
same choice independently. It had the stronger answers to the two hardest problems:

- **Close conditions.** Separate topics each close on their own condition. With a single
  combined issue, a repo that has 1,431 alerts and 185 stale stacks would never close.
- **Safety.** `SafeDelete`, positive-evidence PERSONAL, the notice period that starts only after
  the comment is posted, and deterministic `request_id`s.

Grafted from the Gemini candidate:

- `deployments.workflows`, so repos with an existing deploy workflow (`pam-agent-core`'s
  `deploy-stage.yml`) don't wait on `rollout --lifecycle`
- `Sighting.in_progress` (CloudFormation `*_IN_PROGRESS` or an SST lock object), so vulgard
  never dispatches over a human's deploy

Fixes from the cross-judge:

- Bot commits (`[bot]` authors) don't count toward repo activity.
- Vercel projects are never auto-deleted. A project is PRODUCTION when it has a custom
  production domain, so only a human request can delete one without a domain.

My own fixes:

- CDK stacks are detected by the `BootstrapVersion` parameter in `DescribeStacks`, not by
  calling `ListStackResources` for every stack.
- The SST path claim was checked against SST's source; the judge's challenge to it was wrong.

Rejected from Gemini:

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
- The notice clock starts when the notice is recorded in issue memory, which the engine writes
  just before posting the comment. If posting fails after the body write, the op can still run
  after the notice period without a visible notice.

## Implementation slices

1. **Engine extraction.** Generic `plan.py` and `nag.track`, a `vulns.py` topic, and REOPEN. No
   behavior change.
2. **Read-only discovery.** `estate.py`, the `aws.py` and `vercel.py` scanners, config, and
   `report --topic stale --all`.
3. **Stale topic.** Baselines, the planner, notifications and leaderboard sections, without
   `--execute`.
4. **Lifecycle.** `reconcile`, `execute`, the executors, the reusable `lifecycle.yml`, and
   `rollout --lifecycle`.
