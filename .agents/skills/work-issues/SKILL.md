---
name: work-issues
description: "Finish an authorized Hooray issue backlog in small verified packages, reconcile existing PRs, and preserve progress across restarts."
disable-model-invocation: true
---

# Work issues through completion

Use for an explicit request to fix or implement issues. Read-only discovery
stays read-only. Coordinate with [fix-issue](../fix-issue/SKILL.md) and use
[triage](../triage/SKILL.md) only where evidence or scope is actually missing.

## Scope and authority

- “All open issues” means the finite list of OPEN issue IDs captured at the
  start. A filter also becomes a frozen list. New issues do not enter that run
  automatically. With no scope at all, select one ready issue by priority/age.
- Source work includes isolated worktrees, focused checks and local commits
  needed for a reviewable handoff. Preserve the user's dirty checkout.
- Record the user's authorized publication actions once. Reuse an earlier
  still-applicable instruction to push, open PRs, merge green PRs or close
  resolved issues; do not ask again at every package or restart. Missing
  external authorization is a boundary, not permission to infer it.
- “Publish” does not automatically request a release/tag/artifact campaign.
  Use release procedures only when that outcome is explicitly requested.
- Continue the captured scope until each item reaches its authorized endpoint
  or has a concrete blocker. Do not stop after one wave to demand “continue”.
  Stop the whole run only for a shared safety/authorization boundary; a local
  compiler failure or unavailable reference blocks its package, not all others.

Expose IDs, action contract, current owners and immediate packages concisely.
This disclosure is not an approval question when authority already exists.

## Recover before dispatching

On first entry, capture compact issue metadata and open PRs once. On restart,
read the existing ledger, retained worktrees and receipts, then refresh live
issue/PR state. Do not rebuild a prose TODO list or reread every report.

Read the complete body, comments and relevant timeline/linked-PR discussion
for the next actual package. Follow real dependencies; do not recursively
expand the whole backlog through every incidental link. Cache that evidence
with issue `updatedAt`, base SHA and PR head; refresh changed records only.

An OPEN issue with `ready-for-agent` and pinned acceptance is eligible.
Classifications remain Bug, Coverage request, Enhancement or Documentation.
An unready selected issue gets bounded triage from existing evidence. A missing
label alone is not a reason to discard it from an “all” request: record the
triage result, synchronize labels only when authorized, or report that exact
boundary. Do not invent labels or treat catalog presence as executable coverage.

An existing PR is work to reconcile, not a reason to send the issue back to
triage. Inspect failed checks, missing acceptance, review and merge state.
Finish the current campaign's PR under its existing authorization before
starting another fix for those IDs. Never take over unrelated active work
without authorization. A merged partial PR does not close its whole issue.

Order work: repair/finalize existing packages, then critical/high-priority
ready issues, then normal/low/unprioritized issues by age and number. Preserve
missing priorities as absent. Dependency prerequisites precede their dependents.

## Small packages and bounded concurrency

Default to at most four active implementation packages and one coordinator.
Start with one issue per package; combine a few only when they share the actual
root cause and can be tested/reviewed together. A language crate or “all Python
issues” is not a package boundary. Large accepted enhancements get separate
prerequisite and dependent packages, with complete issue acceptance retained.

Each package has one owner, explicit paths, base SHA and a separate clean
worktree. Shared registries, catalogs, lockfiles, generated files and public
core interfaces require serialized ownership or an explicit prerequisite PR.
Disjoint intentions inside one changing file are not isolation. OMP's automatic
copy of a dirty checkout is not a clean publication base. Never auto-apply
worker patches into the user's integration checkout.

Delegate when useful and supported. Workers receive the exact package, cached
issue evidence, acceptance, paths, base, permitted actions and evidence location.
They do not spawn more fixers. The coordinator can execute a package directly
when delegation is unavailable or adds no useful parallel work.

Workers own implementation **and focused verification**. They may and should
compile/test their changed package and run the bounded CLI/compiler/runtime
reproduction immediately. Never tell every worker to skip all builds, tests,
formatters or linters until all backlog writers finish. Use a separate Cargo
target directory per worktree; bound concurrent builds if memory is tight.

Use [fix-issue](../fix-issue/SKILL.md) for the regression/control contract.
Run shared checks once per independently publishable package or small integrated
set when its scope requires them, at its tested head. Existing unchanged check
results remain evidence. Do not postpone all verification until the last issue,
run full workspace suites in every child, or freeze unrelated worktrees.

If a provider returns 429, reduce dispatch and use its retry/reset information.
Do not launch replacement workers against the same exhausted provider. Preserve
model choices; verify actual worker model and any prewalk/advisor routing.
More agents do not repair a serial integration or provider bottleneck.

## Persistent progress and completion loop

Use [scripts/issue_queue.py](scripts/issue_queue.py) for durable local ownership,
WIP limits, overlapping-path refusal and restart reports. Its SQLite database
belongs under a persistent state directory outside the repository. It does not
spawn agents, mutate Git/GitHub, certify semantic correctness or grant authority.
See [references/queue.md](references/queue.md) for commands and receipt format.

Save each transition, not merely a final chat summary: issue IDs, owner,
worktree, paths, base/head, next action, verification receipt, PR and blocker.
The local states (`working`, `verified`, `pr-open`, `blocked`, tracker `closed`)
are execution bookkeeping, not new GitHub labels. A stale heartbeat requires
owner/process inspection; it never authorizes automatic reassignment or deletion.
Blocked work keeps its path ownership until explicitly reconciled.

For each completed package:

1. Inspect the real diff and executed regression/acceptance evidence. Compile
   and test the clean publication worktree, not an adjacent dirty superset.
   Reject zero-test runs and unexecuted “tests added” handoffs.
2. Commit only owned changes. Pin the tested commit. If publication is
   authorized, fill `.github/pull_request_template.md` (or the release template
   only for an explicitly requested release) into a body file; use
   `gh pr create --body-file` and read the published body back. Missing templates
   in an old base call for reading the current base, not a second template PR.
3. List every fully resolved issue separately with `Closes #N`. A partial
   package uses related references and records the remaining acceptance.
   Verify GitHub's `closingIssuesReferences`; a bare mention does not close it.
4. Reconcile CI at that exact head. Failed checks go to the package owner with
   the first root error; unrelated packages continue. Pending checks stay
   pending. Avoid repeated full log/status dumps while waiting.
5. If already authorized, merge once protected checks and required reviews are
   satisfied, using exact-head protection. Never bypass protections, use admin
   merge, force-push or create an unrequested release.
6. Read merged SHA and actual issue states back. Record fixed only for complete
   accepted behavior on the intended base. A green/open PR is not resolved;
   tracker closure alone is not proof of a fix. Investigate missing closure
   links under the existing authority rather than quietly counting completion.

If 30 minutes pass without a commit, verified reproduction, PR/check transition
or precise new blocker, inspect the stalled package. Split excessive scope,
resolve ownership, run its smallest check or retain a concrete blocked handoff.
Do not respond by repeating broad reviews or spawning a replacement army.

Report compactly: original scope, verified merged/closed, PR-open, locally
verified, working and blocked counts; links/SHAs for completed packages and
specific next actions. Separate tracker closure from behavioral fix evidence.
