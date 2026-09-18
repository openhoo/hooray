# Issue execution

For requests to fix or finish issues, read
[work-issues](.agents/skills/work-issues/SKILL.md) before dispatching. A request
for all open issues selects a finite snapshot, not one issue and not an
ever-growing backlog. Reuse the user's existing publication/merge contract.

Recover existing worktrees, PRs and persisted ownership before creating new
implementations. Unclaimed in a new ledger does not mean unimplemented in an
older campaign. Keep the user's dirty integration checkout intact.

Complete small independently publishable packages. Workers run focused tests
and observable reproductions in their own worktrees immediately. Parent-only
full-suite validation never means a ban on all worker tests. Fix failing CI and
finish authorized PRs before adding more work in those same areas.

Use at most four implementation packages by default, one owner per changing
surface, and no recursive worker delegation. The coordinator may use fewer
workers under resource/provider pressure or work directly. Preserve explicitly
selected models; avoid automatic prewalk/advisor fan-out during issue work.

Broad review rotation and release/artifact skills apply when those outcomes
are requested. They are not additional gates for every ordinary issue fix.
Do not turn an issue backlog into repeated whole-tree adversarial reviews or
a single all-issues integration/release barrier.

The local [queue helper](.agents/skills/work-issues/scripts/issue_queue.py)
records ownership and verification receipts outside Git; it grants no external
permissions. A local test pass, green PR, merged PR and verified issue closure
are distinct evidence states. Preserve required checks and negative controls.
