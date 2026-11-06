# Fix the items on an Inspector tracking issue

**Who this is for:** you were assigned or mentioned on an issue titled *"Security: vulnerable
packages running in AWS"* (label `vulgard-inspector`), or on a Linear issue with that title, or
got a Slack message about one.

**What it means:** something your repo deployed to AWS (a Lambda function, a container image or
an EC2 instance) runs a package version with a known security hole. **Amazon Inspector**, the AWS
service that scans what is deployed, found it, and vulgard worked out that your repo deployed it.
This is different from a Dependabot alert, which only looks at the files in your repo. An
Inspector item is about what is actually running.

If your issue is titled *"Security debt: vulnerable dependencies need attention"* instead, it's a
Dependabot issue. Follow [Fix the alerts on a vulgard tracking issue](fix-vulnerability-alerts.md).

## 1. Read the issue

The issue lists **fix items**, worst first. A fix item is one package in your repo. One upgrade
and one redeploy fix every vulnerability and every resource listed under it, so you work through
items, not individual vulnerabilities. Each line looks like this:

```text
- 🟧 **high** `axios` (npm): **needs_pr_merge**, merge #88, then redeploy · default branch has `1.5.0` · fixed in `1.6.0` · CVE-2023-45857 · on `payments-api-prod-handler` · due in 12d
```

In order, that's:

- the severity,
- the package and its ecosystem,
- the **fix status** and the next step (see below),
- the versions on your default branch, when it still has the package,
- the version that fixes every vulnerability in the item,
- 🔥 **exploit available**, when Inspector knows of a public exploit. Do those first.
- the vulnerability IDs,
- the first five resources that run it,
- and the deadline.

## 2. Do what the status says

vulgard sets the status by comparing what Inspector sees running with your default branch and
your open Dependabot pull requests. These are listed in the order vulgard checks them.

- **`needs_deploy`**: your default branch is already fixed, but the old version is still running.
  Either the package is gone from the default branch, or every copy there is at the fixed
  version. Redeploy the repo. This is the cheapest kind of item.
- **`needs_pr_merge`**: an open Dependabot pull request moves the package to the fixed version or
  removes it. Review and merge the linked pull request, then redeploy.
- **`needs_fix`**: your default branch still has a vulnerable version and no open pull request
  fixes it. Upgrade the package to at least the "fixed in" version, merge, then redeploy. If it's
  a dependency of a dependency, upgrade the package that pulls it in, or use your package
  manager's override feature (`overrides` in npm, `resolutions` in Yarn).
- **`needs_os_update`**: the package comes from the operating system inside the image or
  runtime, not from your dependency files. Move to a newer base image (the `FROM` line of your
  `Dockerfile`) or a newer Lambda runtime, then redeploy.
- **`unknown`**: vulgard couldn't tell. For example, the repo has no dependency graph, Inspector
  gave no fixed version, or a version couldn't be compared. Look at the vulnerability IDs and the
  resources yourself.

Merging alone isn't enough for any of these. Inspector only stops reporting a package once the
fixed version is what runs, so every fix ends in a deploy.

## 3. Deadlines

Each item is due a number of days after vulgard first listed it on your issue, by severity. With
the default settings that's 7 days for critical and 30 for high. The deadline doesn't move when the
item's status changes, for example from `needs_fix` to `needs_deploy` after you merge. Overdue
critical and high items escalate to the security leads 7 days after their deadline, the same way
overdue Dependabot alerts do.

There's no per-item exception for Inspector items. If a resource should never be reported, for
example a scratch environment, ask an admin to add it to `inspector.ignore` in vulgard's config.

## 4. Wait for the next run

vulgard runs on weekdays at 15:00 UTC. Each run rewrites the issue from Inspector's current
findings, so an item you fixed drops off once Inspector no longer reports it. When every item is
gone, vulgard closes the GitHub issue and its Linear sub-issue.

vulgard comments when items are new or newly overdue, when something escalates, and with a
reminder every 7 days while something is overdue. Editing the issue description doesn't help,
because the next run overwrites it.

## Things that may look odd

- **A public repo has no GitHub issue.** Inspector data says what is vulnerable in what runs in
  AWS, which is useful to an attacker, so vulgard never writes it anywhere the public can read.
  Public repos are tracked in Linear only.
- **Your team has a Linear parent issue with the same title.** Each team gets one parent issue,
  with a sub-issue per repo under it. The parent shows how many items each repo has, how many are
  overdue, and how many have each status.
- **Your repo used to have a Dependabot issue, and it closed.** Once Inspector has items for a
  repo, it tracks that repo instead, so you don't get asked for the same work twice. The old issue
  says "Inspector now tracks this repo's vulnerabilities." If the Inspector items all clear and
  Dependabot alerts remain, the Dependabot issue comes back.
- **A resource is listed under the wrong repo.** See
  [Troubleshooting](troubleshooting.md#amazon-inspector-issues).
