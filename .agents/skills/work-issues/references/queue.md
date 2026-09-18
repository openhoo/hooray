# Local queue and evidence receipts

Run from the repository root. Choose one persistent directory per authorized
campaign. Reuse its database on continuation; `init` refuses to overwrite it.

```sh
mkdir -p "$RUN_DIR"
gh issue list -R openhoo/hooray --state open --limit 10000 \
  --json number,title,state,labels,createdAt,updatedAt > "$RUN_DIR/issues.json"
python3 .agents/skills/work-issues/scripts/issue_queue.py --db "$RUN_DIR/queue.sqlite" \
  init --inventory "$RUN_DIR/issues.json" --max-active 4
```

`RUN_DIR` must be set to the campaign's absolute directory first. For selected
IDs/filters, save only that authorized selection before initialization. If a
list reaches its requested limit, retrieve the remaining pages before using
it. The initial metadata inventory does not replace reading complete reports
for issues actually entering implementation.

Before dispatch and at PR transitions, refresh from live read-only data:

```sh
gh issue list -R openhoo/hooray --state all --limit 10000 \
  --json number,title,state,labels,createdAt,updatedAt,closedAt > "$RUN_DIR/current-issues.json"
gh pr list -R openhoo/hooray --state all --limit 10000 \
  --json number,title,state,isDraft,headRefOid,closingIssuesReferences,statusCheckRollup \
  > "$RUN_DIR/current-prs.json"
python3 .agents/skills/work-issues/scripts/issue_queue.py --db "$RUN_DIR/queue.sqlite" \
  refresh --inventory "$RUN_DIR/current-issues.json" --prs "$RUN_DIR/current-prs.json"
```

Refresh requires every captured issue, including closed ones, and ignores
newly created issues outside the original scope. It records tracker closure;
it cannot establish semantic resolution. Open PRs are never counted closed.
PRs without closing references are reported for manual inspection, because
prose mentions alone are not reliable ownership. Associate their known issue
IDs with a retained package before allowing a new worker on those issues.

Create a clean worktree from the pinned intended base, then claim its real
paths **before spawning or editing**. Include shared registration surfaces.

```sh
python3 .agents/skills/work-issues/scripts/issue_queue.py --db "$RUN_DIR/queue.sqlite" \
  claim --package issue-123 --issues 123 --owner worker-123 \
  --worktree /absolute/clean/worktree \
  --surfaces src/scanners/sast.rs
```

The transaction rejects duplicate issue ownership, open closing PRs,
non-ready issues, the WIP limit, shared worktrees and overlapping file/directory
paths. Do not list unrelated narrow paths to evade ownership. Unknown overlap
uses the containing directory. Claims survive a process crash. Blocked packages
release a WIP slot but retain their paths/issues, preventing duplicate repairs.

A worker records a heartbeat with `checkpoint --state working --detail ...`,
or a real blocker with `--state blocked`. Both require the package and owner.
Inspect stale process/worktree state before resuming the same owner. Never
delete a claim/database to bypass a conflict; coordinate the retained package.

After a local scoped commit, save the executed check results and behavior in
a JSON receipt outside the worktree:

```json
{
  "head": "the full tested Git commit SHA",
  "checks": [
    {"command": "cargo test --locked exact_regression_name", "exit_code": 0}
  ],
  "acceptance": {
    "123": "Reference the captured failing baseline, passing regression, actual CLI and clean/refusal controls."
  }
}
```

The receipt records real execution, not future commands. Confirm tests actually
ran and inspect assertions/output. The helper checks head identity, a clean
worktree, successful exit records and receipt integrity; it cannot validate the
truth of prose or replace the coordinator's review.

```sh
python3 .agents/skills/work-issues/scripts/issue_queue.py --db "$RUN_DIR/queue.sqlite" \
  checkpoint --package issue-123 --owner worker-123 --state verified \
  --detail 'Focused regression and CLI controls passed' --evidence "$RUN_DIR/issue-123.json"
```

After an authorized PR is created and its head/body checked, checkpoint
`--state pr-open --pr N`. Changed heads or receipts require working/reverification.
Live refresh retains ownership even when an external actor closes an issue.
After stopping the package's writer and inspecting its final work/evidence,
its owner checkpoints `--state closed`; the queue requires every owned issue
to be closed in the saved tracker readback. Retain the merged SHA and acceptance evidence so a
wontfix/duplicate closure is never described as an implemented fix.

```sh
python3 .agents/skills/work-issues/scripts/issue_queue.py --db "$RUN_DIR/queue.sqlite" report
```

No command sends messages, changes tracker metadata, creates branches,
publishes PRs, merges code, starts models or certifies protected checks.
