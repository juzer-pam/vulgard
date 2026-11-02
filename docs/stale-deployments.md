# How stale deployments work

This guide explains the stale-deployments part of vulgard from the ground up. It assumes you've
read [How vulgard works](how-it-works.md), or at least know what a tracking issue is. You don't
need to know AWS or Vercel well. Each term is explained below.

If you just got pinged on an issue and want to know what to type, skip to
[Respond to a stale-deployments issue](guides/respond-to-stale-deployments.md).

## The problem

When you deploy an app, real things get created in the cloud: functions, databases, queues,
buckets, websites. Together they're called a **deployment**. Deployments cost money while they
exist, and they keep running whatever code was in them on the day they were deployed.

Deployments quietly pile up. Someone makes a stack to try out a branch and forgets it. A staging
copy from last year still runs a Node version that no longer gets security fixes. A repo nobody
has touched in months still has three environments live. Nobody deletes them, because nobody is
sure they're unused, and deleting the wrong thing is scary.

vulgard asks a simple question about every deployment and every repo: **is this still in use?**
If nobody has deployed something in 30 days, its team has to answer. The answer is called a
**baseline**: bring it up to date, delete it, or write down why it stays as it is.

## Words you'll see

| Term | Meaning |
|---|---|
| Deployment | One running copy of an app in the cloud, for example the `dev` copy of `payments-api`. vulgard also calls these *stacks*. |
| CloudFormation | AWS's service for creating a group of resources from a template and deleting them together. A group made this way is a *CloudFormation stack*. Serverless Framework, CDK and Amplify sandboxes all create these. |
| Framework | The tool a repo deploys with. vulgard understands Serverless Framework v3, AWS CDK, SST v3/v4, Amplify (Hosting branches and sandboxes) and Vercel. |
| Stage | The name of one copy of an app, such as `dev`, `staging`, `production` or `jlee`. One repo often has several stages. |
| Tier | How important a deployment is: **production**, **shared** or **personal**. See [Tiers](#tiers). |
| Stale | A deployment nobody has deployed in `stale_days` (30 by default), or a repo with no human commits in `repo_inactive_days` (90). |
| Baseline | A decision recorded on the issue that clears a stale finding. See [Baselines](#baselines). |
| SLA | Here, the number of days (`baseline_days`, 14 by default) a team has to record a baseline after something goes stale. |
| Attribution | Working out which repo a deployment belongs to, so the right team hears about it. |
| Lifecycle workflow | A GitHub Actions workflow in the app's own repo that vulgard can trigger to redeploy or remove a stack. |
| Request id | A short id like `vg-3f9c0a1b2c4d` that vulgard attaches to each redeploy or delete. It's how vulgard makes sure one decision only ever runs once. |

## The clock

Every deployment has a "last deployed" date, and vulgard reads it straight from AWS or Vercel.
For a CloudFormation stack it's the last update time, for SST it's the state file's
modification time, for Amplify it's the latest job, and for Vercel it's the latest production
deployment. Every repo has a "last human commit" date on its default branch. Commits by bots,
whose author names end in `[bot]`, don't count.

From those dates vulgard works out two more:

- **Flagged**: last deployed + `stale_days`. From this day on, the deployment needs a baseline.
- **Deadline**: flagged + `baseline_days`. After this the baseline is *overdue*, and the usual
  escalation rules kick in, exactly like an overdue vulnerability alert.

So with the defaults, a stack last deployed on March 1 is flagged on March 31 and due on April
14. Because the dates come from AWS, Vercel and GitHub, nobody can reset the clock by editing an
issue. The only ways to reset it are to really deploy, really commit, or record a baseline.

## Tiers

The tier decides how loudly vulgard nags and what it's allowed to do. vulgard checks these rules
in order and uses the first one that matches.

1. **Production** if the stage name, app name, stack name or any tag contains a word from
   `production_stages` (`production`, `prod`, `live`). It's also production if it's
   protected: a CloudFormation stack with termination protection on, an Amplify production
   branch (or one named `main` or `master`), or a Vercel project with a custom domain.
   `DataPipelineProduction` counts, because vulgard splits names into words.
2. **Shared** if the stage is in `shared_stages` (`dev`, `staging`, `test` and so on).
3. **Personal** if the stage (or, for Amplify sandboxes, the user name) is listed in
   `deployments.people`, which maps names like `jlee` to GitHub handles like `@jlee`.
4. **Shared** otherwise.

Rule 4 matters: vulgard never *guesses* that something is personal. A stage called `jlee` is
shared until an admin adds `jlee` to `people`. That's on purpose, because personal is the only
tier vulgard may act on by itself.

| Tier | Severity | What vulgard does |
|---|---|---|
| Production | high | Nags. Will redeploy on request. **Never deletes**, even when asked. |
| Shared | medium | Nags. Redeploys or deletes when someone with write access asks. |
| Personal | low | Same as shared, plus it pings the person who owns it. In opted-in repos it can also act automatically (see [Automatic ops](#automatic-ops-on-personal-stacks)). |

Inactive repos get `repo_severity`, low by default.

## Attribution: which repo does this belong to?

AWS doesn't know which GitHub repo created a stack, so vulgard has to work it out. It tries
these in order:

1. **Config.** A glob in `deployments.attribution`, such as `"storefront*": web-storefront`.
   This always wins, so it's how you fix a wrong guess.
2. **Tag.** A tag on the stack such as `vulgard:repo`, `repository` or `repo`.
3. **Platform.** Amplify and Vercel record the Git repo they deploy from.
4. **Manifest.** vulgard reads `serverless.yml` and `sst.config.ts` on each repo's default
   branch. If exactly one repo declares `service: payments-api`, the `payments-api` stack is
   theirs. If two repos declare the same name, as with a copied template, vulgard doesn't guess.
5. **Nobody.** The deployment goes to `unattributed_repo`, usually the vulgard repo itself, so
   someone can sort it out.

`vulgard report --topic stale --all` shows the result for every deployment, including the
*repo from* column that says which rule matched.

## Baselines

Each repo with something stale gets one GitHub issue labeled `vulgard-stale`. It's separate from
the vulnerability tracking issue, because each one closes on its own condition. The issue lists
every stale item with the commands that would clear it. You record a baseline by commenting one
of these on the issue:

```text
/vulgard redeploy <name>                       bring it up to date
/vulgard delete <name>                         delete it (never production)
/vulgard keep <name> until 2027-01-31: why     leave it as it is until then
/vulgard active until 2027-01-31: why          the repo is maintained without commits
/vulgard cancel <name>                         cancel an earlier command
```

`<name>` is the name shown in backticks in the issue, such as `payments-api-dev` or
`web-storefront-site/feature-x`. You can also skip the commands and act by hand: deploy it,
delete it yourself, push a commit, or archive the repo. vulgard sees the change on its next run.

A few rules keep this trustworthy:

- **Only people with write access to the repo can baseline.** Commands from anyone else are
  listed under *Commands vulgard didn't accept* with the reason.
- **The thread is the record.** vulgard keeps no copy of your decision. On every run it re-reads
  all the comments from oldest to newest and works out what's in effect now. If you say
  `keep` and later say `delete`, the delete wins. That's also why editing or deleting your
  comment changes the decision.
- **A keep expires.** `keep` and `active` need a date, at most `max_keep_days` (180) ahead.
  When the date passes, the finding comes back by itself.
- **Issues get reopened, not recreated.** When everything is baselined, the issue closes. If
  something goes stale again, vulgard reopens the same issue, so earlier decisions are still
  in the thread.

## What happens after you ask for a redeploy or delete

vulgard runs once a day, so commands aren't instant. A request goes like this:

1. **You comment** `/vulgard delete payments-api-dev`.
2. **The next run reads it.** It checks the command is valid and that you have write access. The
   request then shows under *Requested* in the issue.
3. **If the run has `--execute`, vulgard carries it out.** Without `--execute`, requests wait.
   Admins turn it on for the scheduled job with the `VULGARD_EXECUTE` variable.
4. **Right before deleting, it checks again.** It re-reads the live stack. If someone redeployed
   it, turned on termination protection, or it now counts as production, vulgard skips it and
   says why.
5. **It comments on the issue** when the op starts, with a link. On later runs it checks how the
   op is going. When it ends, vulgard comments once: "Finished …" or "Couldn't …" with the
   error. It doesn't retry a failed op. Post the command again once you've fixed the cause.
6. **Then the request drops off the list.** A redeploy is done once the stack's last-deployed
   time is after your comment, or once vulgard has seen the redeploy finish successfully. The
   second rule matters because CloudFormation leaves a stack untouched when a deploy changes
   nothing. A delete is done once the stack is gone.

How each framework is redeployed or deleted:

| Framework | Redeploy | Delete |
|---|---|---|
| Serverless v3, CDK | the repo's lifecycle workflow | CloudFormation deletes the stack (for Serverless, the deployment bucket is emptied first) |
| SST v3/v4 | lifecycle workflow (`sst deploy`) | lifecycle workflow (`sst remove`) |
| Amplify Hosting | starts a new release job | deletes the branch |
| Amplify sandbox | not possible: sandboxes run from a laptop | CloudFormation deletes the stack |
| Vercel | rebuilds the production deployment | deletes the project (only when asked) |

**Why some ops go through the repo and some don't.** Redeploying needs the repo's code and build
steps, so vulgard triggers a workflow *in that repo*, running with that repo's own deploy
permissions. Deleting a CloudFormation stack doesn't need the code at all, and the stalest
stacks are often the ones whose builds no longer work. So vulgard deletes those directly. SST is
the exception: its state isn't in CloudFormation, and only `sst remove` can delete it.

**Why it never runs twice.** Every op gets a request id made by hashing the deployment, the verb
and the comment that asked for it. The id goes into the workflow run's name, the CloudFormation
request token, the Amplify job reason and the Vercel metadata. Before starting anything, vulgard
looks for an op with that id. If it finds one, it reports it as running instead of starting a
second one. That makes it safe for `nag` to run many times.

## Automatic ops on personal stacks

Personal stacks are the ones most often forgotten. In repos an admin lists under
`deployments.auto.repos`, vulgard can clean them up without being asked. A personal stack
qualifies when either:

- it hasn't been deployed in `auto.personal_stale_days` (90), or
- its repo has open **critical** vulnerability alerts.

vulgard never acts on the same day it decides. First it posts a **notice** comment on the issue
that mentions the stack's owner and says what will happen and when. After `auto.notice_days`
(7), the next `--execute` run redeploys the stack, or deletes it if `auto.delete` is `true`.
Commenting `/vulgard keep <name> until …: why` or `/vulgard cancel <name>` before then stops
it.

The 7 days count from when vulgard's own comment was posted. vulgard finds it by a hidden marker
in a comment whose author ends in `[bot]`, so pasting the marker into your own comment does
nothing. The notice also stops counting if the stack is deployed again or kept after the notice.
Shared and production stacks are never touched automatically, and neither are Vercel projects.

## One stack's story

Here is `payments-api-jlee`, a Serverless stack in the demo config. `people` maps `jlee` to
`@jlee`, so it's personal. `payments-api` matches `auto.repos: ["payments-*"]`, and
`auto.delete` is `false`. It was last deployed on **January 10**.

| Date | What happens |
|---|---|
| Feb 9 | 30 days without a deploy. vulgard opens `payments-api`'s `vulgard-stale` issue, mentions the owners and `@jlee`, and lists the stack under *Needs a baseline*. |
| Feb 10 to 22 | The issue description is refreshed daily. No new pings. |
| Feb 23 | 14 days later, the baseline is overdue. vulgard comments and posts to Slack. |
| Mar 2 | 7 days overdue. vulgard escalates to `escalation.mentions`, like an overdue alert. |
| Apr 10 | 90 days without a deploy. vulgard posts a notice: `payments-api-jlee` will be **redeployed** on April 17 unless someone keeps or cancels it. |
| Apr 17 | The scheduled run has `--execute`. vulgard dispatches the repo's deploy workflow with a request id and comments with a link to the run. |
| Apr 18 | The stack's last-deployed time is now April 17. The finding is gone, so the issue closes itself. |

If `@jlee` had commented `/vulgard delete payments-api-jlee` on February 9, the next `--execute`
run would have deleted the stack, and the issue would have closed the day after.

## Safety, in one place

- **Production and protected deployments are never deleted.** Asking doesn't change that.
  vulgard rejects the command and tells you to delete it by hand if you really mean it.
- **Automatic ops only touch personal stacks in opted-in repos.** They need `--apply`,
  `--execute` and a notice that's at least 7 days old.
- **Every delete is rechecked against the live stack** right before it runs.
- **Nothing runs while a deploy is in progress.** A CloudFormation stack in an `*_IN_PROGRESS`
  state, or an SST stage with a lock, is skipped until it's finished.
- **The lifecycle workflow has its own checks.** It only accepts dispatches from a GitHub App
  (like vulgard's) or a repo admin, and refuses to delete any stage whose name contains `prod`,
  `prd`, `production` or `live`.
- **vulgard's AWS role can't delete resources itself.** CloudFormation deletes them with a
  separate role, `VulgardStackDelete`, so the role vulgard runs as stays narrow.
- **Report-only mode** (`deployments.report_only: true`) finds everything and writes nothing,
  which is how an org should start.

## Reading the code

The stale path in `src/vulgard/` runs in this order:

1. **`topics.py`** has `run_stale`, which drives the whole topic for one `nag` run.
2. **`estate.py`**, **`aws.py`** and **`vercel.py`** find deployments. Scanners only read from
   AWS and Vercel. Then `classify` in `estate.py` picks each one's repo, tier and person, with
   no network calls.
3. **`repos.py`** reads GitHub: which repos exist, their owners, their manifests, and their last
   human commit.
4. **`baseline.py`** parses `/vulgard` commands. `fold` turns a comment thread into the
   decisions in effect now.
5. **`stale.py`** computes the clock and SLA for each finding. Start with `evaluate`.
6. **`lifecycle.py`** decides which redeploys and deletes to run (`reconcile`), and holds the
   safety checks (`check_delete`, `recheck`).
7. **`execute.py`** runs one op idempotently. **`executor.py`** talks to GitHub, AWS and
   Vercel.
8. **`stale_plan.py`** and **`stale_render.py`** decide and write the issue, comments, Slack
   lines and leaderboard. `nag.track` in **`nag.py`** writes them, the same as for
   vulnerabilities.

As with vulnerabilities, deciding and doing are kept apart. Everything from `classify` to
`reconcile` is pure, so `tests/test_stale.py`, `tests/test_estate.py` and
`tests/test_lifecycle.py` test it with plain data and no mocks. For why it's built this way, see
the [design doc](design/stale-deployments.md).
