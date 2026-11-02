# Troubleshooting

Answers to the questions people ask most, grouped by what you're looking at. If yours isn't
here, run vulgard as a dry run (no `--apply`) and read what it says it would do. That's usually
the fastest way to see why.

## Pings and issues

**Nobody got pinged today.** That's normal. vulgard only comments when something changes: an
alert or deployment newly goes overdue, a fix PR newly becomes ready, something escalates, or
a week has passed since the last ping. On other days it quietly updates the issue description.

**I closed the tracking issue and it came back.** vulgard reopens it while anything is still open
or stale. Fix the items, or record why they stay (a dismissal with a reason, an exception, or a
`/vulgard keep`).

**I edited the issue description and my change disappeared.** vulgard rewrites the description on
every run. Put notes in comments instead.

**The issue went to the wrong team.** Owners come from `owners:` in the config, then from the
`*` line in the repo's `CODEOWNERS` file, then from `default_owners`. Fixing `CODEOWNERS` is
usually easiest, and you can do it yourself in a PR.

**The Slack message went to the wrong channel.** vulgard picks the channel by exact repo name,
then by repo glob (such as `payments-*`), then by owner, and falls back to
`slack.default_channel`. An admin changes `slack.channels` in the config.

## `/vulgard` commands

**My command is listed under "Commands vulgard didn't accept".** The reason is next to it:

| Reason | Fix |
|---|---|
| only people with write access to the repo can baseline | Ask someone with write access to post it, or get access. |
| no deployment named `x` in this repo | Copy the name exactly from the backticks in the issue. Names are case-sensitive, and some include a `/` or an `@` suffix. |
| `/vulgard keep` needs a deployment name | `keep` needs a name before `until`: `/vulgard keep api-dev until 2027-01-31: why`. |
| expected `until YYYY-MM-DD: why` | Check the date format and the colon before the reason. |
| … is in the past | Pick a future date. |
| keeps last at most 180 days | Pick an earlier date. Post a new keep when it runs out, if it's still true. |
| vulgard never deletes production or protected deployments | Delete it by hand, if you really mean to. See [below](#it-says-production-but-it-isnt). |
| `/vulgard active` applies to the whole repo and takes no name | Remove the name: `/vulgard active until 2027-03-01: why`. |
| unknown command | Use one of `redeploy`, `delete`, `keep`, `active`, `cancel`. |

**My command isn't in the issue at all, accepted or rejected.** vulgard only reads lines that
*start* with `/vulgard`. Check that it's at the start of its own line, not wrapped in backticks,
and not in a quote (`>`). Then wait for the next run, which is on weekdays at 15:00 UTC.

**It's been days and my request is still under "Requested".** First look for a comment from
vulgard that says "Started …":

- **No "Started" comment.** Your org may not run vulgard with execution on, so requests wait
  for an admin. Do it by hand, or ask an admin. If the line ends in *vulgard can't do this one:
  …*, the reason tells you why, and you'll need to do it by hand.
- **A "Started" comment, and nothing since.** The run is still going. vulgard checks it on
  every run. When it ends, vulgard comments "Finished …" or "Couldn't …".
- **The line says *Its run failed*.** vulgard commented "Couldn't …" with the error and a
  link, and it won't try that request again. Fix the cause, then deploy by hand, or post the
  command again. A new comment gets a new request id, so vulgard starts a fresh run.
- **The line says *In progress*.** A deploy or delete is running on that stack right now,
  started by vulgard or a person. vulgard checks again on the next run.

**vulgard commented "Couldn't redeploy …" or "Couldn't delete …".** The error is in the comment.
If it ends with "vulgard won't try this one again", the op ran and failed: a workflow run that
didn't succeed, a failed Amplify job or Vercel deployment, or CloudFormation's `DELETE_FAILED`.
Otherwise vulgard couldn't start the op at all. The usual causes are:

- **Access denied in AWS.** The `VulgardLifecycle` or `VulgardStackDelete` role is missing a
  permission. Ask an admin.
- **`DELETE_FAILED`.** CloudFormation couldn't delete one of the stack's resources, often a
  non-empty bucket or a resource someone changed by hand. Open the stack's *Events* tab in the
  AWS console, fix that resource, and delete the stack by hand.
- **Workflow not found, or HTTP 422 from GitHub.** The repo has no lifecycle workflow, or its
  workflow doesn't declare all six inputs. See
  [Use your own deploy workflow](use-your-own-deploy-workflow.md).
- **no repo to run it from.** The deployment isn't linked to a repo. See the next section.

When the op couldn't start, vulgard tries again on every run, and comments each time, until it
works or someone records a different decision. When the op ran and failed, vulgard reports it
once and stops.

## Deployments vulgard found

**A deployment is listed under the wrong repo, or under the catch-all repo.** vulgard didn't know
whose it was. To fix it, do one of:

- tag the stack `vulgard:repo=<repo-name>` (in Serverless, under `provider.stackTags`; in CDK,
  with `Tags.of(app).add(...)`),
- make sure exactly one repo's `serverless.yml` or `sst.config.ts` declares that app name on its
  default branch,
- or ask an admin to map it in `deployments.attribution`.

`vulgard report --topic stale --all` shows how each deployment was matched, in the *repo from*
column.

**It says production but it isn't.** Something in the stage, app name, stack name or tags
contains `production`, `prod` or `live` as a word. Or the stack is protected: CloudFormation
termination protection, an Amplify branch marked production or named `main`/`master`, or a
Vercel project with a custom domain. vulgard errs on the side of production on purpose. If it's
really disposable, turn off the protection or delete it by hand.

**It says shared, but it's my personal stack.** vulgard only treats a stack as personal when an
admin has listed its stage in `deployments.people`. Ask for yours to be added, for example
`jlee: "@jlee"`.

**Something should never be tracked.** Ask an admin to add it to `deployments.ignore`, such as
CDK's bootstrap stack `CDKToolkit`.

**It says "⏳ deploy in progress".** A CloudFormation update or an SST deploy is running, or
stuck. vulgard won't touch the stack until it finishes. If it's stuck, check the stack in the
AWS console.

**A deleted deployment is still listed.** vulgard notices on its next run. If it's still there
after that, the delete didn't finish. Check the AWS console or Vercel.

**My repo is listed as inactive, but we're working on it.** Only human commits to the default
branch count, and bot commits such as Dependabot's don't. If the work is on a long-lived branch,
or the repo is simply stable, comment `/vulgard active until YYYY-MM-DD: why`.

## For admins

**The scheduled run's log shows only counts.** The job runs with `--redact`, because logs on a
public fork are public. For the details, run the same command from your laptop without
`--redact`, or use `vulgard report` and `vulgard report --topic stale`.

**"skipped stale deployments: AWS scan failed".** The `nag` job couldn't read AWS. Check
`VULGARD_AWS_ROLE`, the role's trust policy (it must allow `repo:<org>/vulgard:*`), and the
read permissions in [Set up stale deployments](set-up-stale-deployments.md). The vulnerability
topic keeps working when this happens.

**`rollout --lifecycle` skipped a repo.** The reason is printed next to it. The most common are
"set deployments.aws.deploy_role_arn first", "no Serverless, SST or CDK app", and "uses
<workflow>", which means the repo is listed in `deployments.workflows`.

**A config change didn't take effect.** The scheduled job reads the `VULGARD_CONFIG` secret, not
the file in the repo. Run `gh secret set VULGARD_CONFIG -R <org>/vulgard < org.yml` again. An
unknown or misspelled key makes vulgard stop with an error, so check the run log too.
