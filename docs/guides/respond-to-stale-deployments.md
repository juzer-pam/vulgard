# Respond to a stale-deployments issue

**Who this is for:** you were mentioned on an issue titled *"Stale deployments need a baseline"*
(label `vulgard-stale`), or got a Slack message about one.

**What it means:** something your team owns hasn't been deployed in 30 days, or your repo has
had no human commits in 90 days. vulgard wants a decision, called a *baseline*: is it still
needed? You have 14 days before it's overdue and gets escalated. The background is in
[How stale deployments work](../stale-deployments.md).

## 1. Read the issue

Each stale item is one bullet, followed by the commands that would clear it:

```text
- 🟨 **shared** `payments-api-dev` (serverless): last deployed 2026-09-20 (42d ago) · baseline due in 2d
  `/vulgard redeploy payments-api-dev` · `/vulgard delete payments-api-dev` · `/vulgard keep payments-api-dev until YYYY-MM-DD: why`
```

The parts are, in order:

- **Icon and tier.** Production, shared or personal. Production items have no `delete` command,
  because vulgard never deletes production.
- **Name**, in backticks. This is exactly what you type in a command.
- **Framework** in brackets.
- **Last deployed**, read from AWS or Vercel.
- **When the baseline is due**, or how overdue it is.
- Sometimes **a person**, for a personal stack, or **⏳ deploy in progress**.

At the bottom, *All deployments of this repo* lists everything vulgard found for the repo,
including things that aren't stale.

## 2. Decide what it should be

Ask yourself or your team one question: **does anyone still use this?**

| Situation | What to do |
|---|---|
| It's needed and should run current code | `/vulgard redeploy <name>`, or just deploy it yourself the usual way |
| Nobody uses it any more | `/vulgard delete <name>`, or delete it yourself |
| It's needed but must stay exactly as it is for now (a frozen environment, a demo for a customer) | `/vulgard keep <name> until 2027-01-31: <why>` |
| The issue is about the repo, which is finished and stable (a library that doesn't need changes) | `/vulgard active until 2027-03-01: <why>` |
| The repo is dead | Archive it in GitHub (*Settings → Archive this repository*) |
| You don't know | Ask in your team channel. If nobody claims it within a few days, it's a good sign it can go. |

## 3. Comment the command

Post a new comment on the issue with the command on its own line. For example:

```text
/vulgard delete payments-api-dev
```

You can put several commands in one comment, one per line, and add normal text around them.
Some details:

- **You need write access** to the repo. Commands from anyone else are ignored and listed under
  *Commands vulgard didn't accept*.
- **Dates are `YYYY-MM-DD`** and must be in the future, at most 180 days ahead.
- **`keep` and `active` need a reason** after the colon. Write it for a teammate who finds this
  issue in six months.
- **The latest command wins.** If you change your mind, post the new command. A `keep` after a
  `delete` replaces it. `/vulgard cancel <name>` clears whatever you said before.
- **Don't edit the issue description.** vulgard rewrites it on every run. Comments are fine.

## 4. Wait for the next run

vulgard runs on weekdays at 15:00 UTC, so nothing happens the moment you comment. On the next
run:

- A `keep` or `active` moves the item to *Kept*, or to the "Marked active" line, straight away.
- A `redeploy` or `delete` shows under *Requested*. If your org runs vulgard with execution on,
  it starts the op and comments with a **Progress** link. If not, the request waits there, and
  an admin can run it, or you can do it yourself.
- If something's wrong with your command, it appears under *Commands vulgard didn't accept*
  with the reason. Fix it and post again.

When every item is handled, vulgard closes the issue with "✅ Every deployment here is up to
date or baselined". If something goes stale again later, the same issue reopens, and your
earlier decisions are still in its thread.

## If you got a notice about an automatic op

In some repos, vulgard cleans up **personal** stacks by itself. Before it does, it posts a
comment like this:

```text
@jlee @acme/payments vulgard will act on these personal deployments automatically unless someone
comments `/vulgard keep <name> until YYYY-MM-DD: why` or `/vulgard cancel <name>` first:

- `payments-api-jlee` (@jlee): **redeploy** on 2026-11-08 (personal and not deployed recently)
```

You have until the date shown. If that stack is yours and you still need it as it is, comment
`/vulgard keep payments-api-jlee until 2027-01-31: <why>`. If you're happy for vulgard to go
ahead, do nothing. Deploying the stack yourself also resets the notice.

## Doing it by hand instead

Commands are a convenience. vulgard checks the real state every run, so any of these clear the
item too:

- deploying the stack the way you normally do (`serverless deploy --stage dev`,
  `npx sst deploy --stage dev`, `npx cdk deploy`, a Vercel or Amplify deploy),
- deleting it yourself (`serverless remove`, `sst remove`, deleting the CloudFormation stack,
  the Amplify branch, or the Vercel project),
- pushing a commit to the default branch, for an inactive repo,
- archiving the repo.

Deleting by hand is the only way to delete production. vulgard won't do it for you.

Something not behaving? See [Troubleshooting](troubleshooting.md).
