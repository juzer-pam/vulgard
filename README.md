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
| Dependabot PRs rot | Dependabot config that **groups minor and patch updates into one PR per ecosystem**. Repos that opt in also **auto-approve and auto-merge** them once CI passes. **A PR that passes CI but is still open after 2 days** pings its owners in GitHub, Slack, and Linear, listing the alerts it would fix. The tracking issue lists stale PRs. |
| New vulnerabilities get merged | A reusable **`vulgard / guard / scan`** check fails any PR that adds a dependency with a known vulnerability, and an **org ruleset** makes it required. |

Everything that writes to GitHub runs as a **dry run by default**. Add `--apply` to make changes.

New to this project, or to Dependabot? Start with **[How vulgard works](docs/how-it-works.md)**.
It explains the terms, follows one alert from opening to closing, and walks through the code.
This README is the setup and reference guide.

## How it fits together

```
this repo (acme/vulgard)
├── .github/workflows/nag.yml             scheduled: vulgard nag --apply --slack --linear
├── .github/workflows/guard.yml           reusable PR check (GitHub or OSV engine)
├── .github/workflows/automerge.yml       reusable auto-merge for Dependabot PRs
└── .github/workflows/guard-required.yml  for `enforce --mode workflow`

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
   Don't commit org settings to the fork (step 4 keeps them in a private Actions variable),
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

4. **Write your org's config** and save it as the Actions variable `VULGARD_CONFIG` on the
   fork. Actions variables aren't visible to the public, even on a public repo. Start from
   [`vulgard.yml`](vulgard.yml), save your copy as `org.yml`, then run
   `gh variable set VULGARD_CONFIG -R <org>/vulgard < org.yml`. The nag job writes this
   variable to `vulgard.yml` before it runs. Settings to fill in: SLA days, owners,
   escalation contacts, included and excluded repos, `rollout.engine` (see the caveats
   below), `rollout.auto_merge`, and the `slack` and `linear` routing:
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
     `{team, labels, project, state}` instead of a bare key to override them for that repo
     or team. Labels and project apply when vulgard creates the issue; the state is also used
     when it reopens one. A label name matches the team's own label first, then a workspace
     label, and vulgard creates a workspace label if neither exists.
   - `slack.users` maps GitHub handles to Slack user IDs, used for mentions and DMs, or to
     user group IDs (`S…`) for team mentions.
   - `linear.users` maps GitHub handles to Linear emails, used to assign issues.

5. **Roll out to repos.** Run with a token that has the permissions above (for example
   `export GITHUB_TOKEN=$(gh auth token)` for an org admin):

   ```bash
   gh variable get VULGARD_CONFIG -R acme/vulgard > org.yml
   uv run vulgard --config org.yml --org acme rollout          # review the plan
   uv run vulgard --config org.yml --org acme rollout --apply  # open PRs; enables alerts,
                                                                 # security updates, and
                                                                 # auto-merge if opted in
   ```

   To pilot first, set `repos.include` to a few repos in `org.yml`, update the variable,
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

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

For a suggested reading order, see [Reading the code](docs/how-it-works.md#reading-the-code).
Code lives in `src/vulgard/`: `policy.py` (SLA evaluation, exceptions, escalation rules,
weekly fixed and dismissed summary), `plan.py` (per-repo decisions and the state stored in the
tracking issue), `render.py` (issue, comment, and summary markdown), `nag.py` (tracking issues
and comments), `linear.py` (Linear client and sync), `slack.py` (routed messages, DMs, leaderboard),
`kev.py` (CISA KEV feed), `clients.py` (live API clients), `rollout.py`
(Dependabot config and workflow generation), `enforce.py` (org rulesets), `github.py` (REST
client), and `fixtures.py` (offline fakes for GitHub, Linear, and Slack used by the demo and
tests).
