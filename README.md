# vulgard

Org-wide automation that makes teams actually deal with vulnerable dependencies.
Turning on Dependabot isn't enough if nobody merges its PRs. vulgard covers the rest:

| Problem | What vulgard does |
|---|---|
| Alerts pile up and nobody owns them | Opens **one tracking issue per repo**, assigns and mentions the owners, and **comments when an alert goes past its SLA**. Re-pings on a schedule and **escalates** to security leads when criticals or highs stay overdue. |
| GitHub notifications get ignored | Posts **one Slack message per team channel** per run, sends each owner one DM covering all their repos, and posts escalations to a security channel. **Mirrors each tracking issue into Linear** in the owning team, with priority and due date taken from the worst alert. If someone closes the Linear issue while alerts are still open, vulgard reopens it. |
| Everything looks equally urgent | Alerts whose CVE is on **CISA's Known Exploited Vulnerabilities** list get a 3-day deadline and escalate as soon as they're overdue. |
| "Won't fix" decisions are invisible and permanent | **Exceptions in `vulgard.yml` need a reason and an expiry date.** Accepted risks stay listed in the tracking issue and come back when they expire. The digest names anyone who dismissed a critical or high alert without a comment. |
| Fixes go unnoticed | The Slack digest counts alerts fixed in the last 7 days per repo, next to the repos with the most overdue alerts. |
| Dependabot PRs rot | Dependabot config that **groups minor and patch updates into one PR per ecosystem**, plus a workflow that **auto-approves and auto-merges** them once CI passes. **A PR that passes CI but is still open after 2 days** pings its owners in GitHub, Slack, and Linear, listing the alerts it would fix. The tracking issue lists stale PRs. |
| New vulnerabilities get merged | A reusable **`dependency-review / review`** check fails any PR that adds a dependency with a known vulnerability, and an **org ruleset** makes it required. |

Everything that writes to GitHub runs as a **dry run by default**. Add `--apply` to make changes.

## How it fits together

```
this repo (acme/vulgard)
├── .github/workflows/nag.yml                  scheduled: vulgard nag --apply --slack
├── .github/workflows/dependency-review.yml    reusable PR gate (GitHub or OSV engine)
├── .github/workflows/dependabot-automerge.yml reusable auto-merge for Dependabot PRs
└── .github/workflows/required-dependency-review.yml  for `enforce --mode workflow`

every other repo (installed by `vulgard rollout`)
├── .github/dependabot.yml          generated from detected ecosystems
└── .github/workflows/vulgard.yml calls the two reusable workflows above
```

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

1. **Put this repo in your org** as `vulgard`. Under *Settings → Actions → General →
   Access*, allow access from repositories in the organization, so other repos can call
   the reusable workflows.

2. **Create a GitHub App** owned by the org and install it on all repositories, with these
   permissions:
   - Repository: Dependabot alerts (read), Issues (read/write), Contents (read/write),
     Pull requests (read/write), Administration (read/write), Workflows (read/write)
   - Organization: Administration (read/write), needed only for `enforce`

   Save its ID as the Actions variable `VULGARD_APP_ID` and its private key as the secret
   `VULGARD_APP_PRIVATE_KEY`.

3. **Connect Slack and Linear** (both optional; each is skipped if its secret is missing):
   - **Slack:** create a Slack app with bot scopes `chat:write`, `chat:write.public`, and
     `im:write`, install it, and save the bot token as the secret `SLACK_BOT_TOKEN`. An
     incoming webhook in `SLACK_WEBHOOK_URL` still works for the digest alone.
   - **Linear:** create an API key for a bot or service account (*Settings → Security &
     access → Personal API keys*) and save it as the secret `LINEAR_API_KEY`.

4. **Edit `vulgard.yml`**: SLA days, owners, escalation contacts, excluded repos,
   `rollout.engine` (see the caveats below), and the `slack` and `linear` routing:
   - `slack.channels` maps a repo name or owner handle (from config or `CODEOWNERS`) to a
     Slack channel. Repos with no match post to `slack.default_channel`.
   - `linear.teams` maps a repo name or owner handle to a Linear team key. Repos with no
     match go to `linear.default_team`.
   - `slack.users` maps GitHub handles to Slack user IDs, used for mentions and DMs, or to
     user group IDs (`S…`) for team mentions.
   - `linear.users` maps GitHub handles to Linear emails, used to assign issues.

5. **Roll out to repos.** Run with a token that has the permissions above (for example
   `export GITHUB_TOKEN=$(gh auth token)` for an org admin):

   ```bash
   uv run vulgard --org acme rollout                # review the plan
   uv run vulgard --org acme rollout --apply        # open PRs; enables alerts, security
                                                      # updates, and auto-merge per repo
   ```

   Re-running is safe: repos that already have the files, or an open rollout PR, are skipped.

6. **Make the check required** once those PRs are merged:

   ```bash
   uv run vulgard --org acme enforce --apply
   ```

   This creates or updates the org ruleset *"vulgard: block vulnerable dependencies"*,
   requiring `dependency-review / review` on default branches of repos that have the
   workflow. Re-run it after more rollout PRs merge. On GitHub Enterprise Cloud, use
   `--mode workflow` instead: the ruleset runs `required-dependency-review.yml` on every repo
   directly, with no per-repo files.

7. **Turn on the nag job.** `nag.yml` runs weekdays at 15:00 UTC with `--slack --linear`.
   Trigger it once manually with *apply* unchecked to preview.

## How nagging works

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
digest flags high-severity dismissals with no comment), or add an exception that expires:

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
- **Auto-merge** only waits for checks that are *required*. If a repo has no required
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

Code lives in `src/vulgard/`: `policy.py` (SLA evaluation, exceptions, escalation rules,
weekly fixed and dismissed summary), `plan.py` (per-repo decisions and the state stored in the
tracking issue), `render.py` (issue, comment, and summary markdown), `nag.py` (tracking issues
and comments), `linear.py` (Linear client and sync), `slack.py` (routed messages, DMs, digest),
`kev.py` (CISA KEV feed), `clients.py` (live API clients), `rollout.py`
(Dependabot config and workflow generation), `enforce.py` (org rulesets), `github.py` (REST
client), and `fixtures.py` (offline fakes for GitHub, Linear, and Slack used by the demo and
tests).
