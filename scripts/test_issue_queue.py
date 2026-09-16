"""Ownership and truthful progress regressions for the issue coordinator."""

import concurrent.futures
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".agents/skills/work-issues/scripts/issue_queue.py"
SPEC = importlib.util.spec_from_file_location("issue_queue", SCRIPT)
queue = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(queue)


def issue(number, state="OPEN", ready=True):
    return {"number": number, "state": state, "title": f"Issue {number}",
            "labels": [{"name": "ready-for-agent"}] if ready else []}


class IssueQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "queue.sqlite"
        self.inventory = [issue(1), issue(2), issue(3, ready=False)]
        queue.initialize(self.db, self.inventory, 2)
        self.worktrees = []
        for name in ["one", "two", "three"]:
            p = self.root / name
            p.mkdir()
            self.worktrees.append(p)

    def claim(self, number=1, surface="crates/one", worktree=None):
        queue.claim(self.db, f"p{number}", [number], f"w{number}",
                    worktree or self.worktrees[number - 1], [surface])

    def commit(self, worktree, message):
        subprocess.run(["git", "-C", str(worktree), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Queue test",
                        "-c", "user.email=queue@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-qm", message], check=True, capture_output=True)

    def receipt(self):
        p = self.worktrees[0]
        subprocess.run(["git", "init", "-q", str(p)], check=True, capture_output=True)
        (p / "fix.txt").write_text("fixed\n")
        self.commit(p, "test: create verified fixture")
        self.claim()
        receipt = self.root / "evidence.json"
        receipt.write_text(json.dumps({"head": queue.git_head(str(p)),
                                       "checks": [{"command": "fixture regression", "exit_code": 0}],
                                       "acceptance": {"1": "Observable fixture result"}}))
        return receipt

    def test_reinitialization_preserves_existing_progress(self):
        self.claim()
        with self.assertRaisesRegex(ValueError, "already initialized"):
            queue.initialize(self.db, [issue(9)], 20)
        self.assertEqual(queue.report(self.db)["active_packages"], 1)
        self.assertEqual(queue.report(self.db)["scope"], 3)

    def test_atomic_competing_claims_only_one_owner_wins(self):
        def take(owner):
            try:
                queue.claim(self.db, owner, [1], owner, self.worktrees[0], ["crates/one"])
                return True
            except ValueError:
                return False
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sum(pool.map(take, ["a", "b"])), 1)
        self.assertEqual(queue.report(self.db)["active_packages"], 1)

    def test_directory_ownership_blocks_child_file(self):
        self.claim()
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.claim(2, "crates/one/lib.rs")
        self.assertEqual(queue.report(self.db)["active_packages"], 1)

    def test_same_worktree_rejected_for_disjoint_paths(self):
        self.claim()
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.claim(2, "crates/two", self.worktrees[0])

    def test_wip_limit_survives_fresh_database_connection(self):
        self.claim()
        self.claim(2, "crates/two")
        with self.assertRaisesRegex(ValueError, "WIP limit"):
            self.claim(3, "crates/three")

    def test_unready_or_out_of_scope_issue_is_not_dispatched(self):
        with self.assertRaisesRegex(ValueError, "not open and ready"):
            self.claim(3, "crates/three")
        with self.assertRaisesRegex(ValueError, "outside snapshot"):
            queue.claim(self.db, "p9", [9], "w9", self.worktrees[0], ["crates/nine"])

    def test_blocker_releases_slot_but_retains_ownership(self):
        self.claim()
        queue.checkpoint(self.db, "p1", "w1", "blocked", "Waiting for reference runtime")
        self.assertEqual(queue.report(self.db)["active_packages"], 0)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.claim(2, "crates/one/lib.rs")
        self.claim(2, "crates/two")
        queue.checkpoint(self.db, "p1", "w1", "working", "Reference available")
        self.assertEqual(queue.report(self.db)["active_packages"], 2)

    def test_wrong_owner_cannot_replace_checkpoint(self):
        self.claim()
        with self.assertRaisesRegex(ValueError, "wrong owner"):
            queue.checkpoint(self.db, "p1", "other", "blocked", "not my work")
        self.assertEqual(queue.report(self.db)["packages"][0]["state"], "working")

    def test_verification_requires_executed_checks(self):
        receipt = self.receipt()
        data = json.loads(receipt.read_text())
        data["checks"][0]["exit_code"] = 101
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "successful checks"):
            queue.checkpoint(self.db, "p1", "w1", "verified", "candidate", receipt)

    def test_dirty_candidate_cannot_reuse_committed_receipt(self):
        receipt = self.receipt()
        (self.worktrees[0] / "fix.txt").write_text("untested\n")
        with self.assertRaisesRegex(ValueError, "clean committed"):
            queue.checkpoint(self.db, "p1", "w1", "verified", "candidate", receipt)

    def test_head_change_invalidates_verified_pr_handoff(self):
        receipt = self.receipt()
        queue.checkpoint(self.db, "p1", "w1", "verified", "passed", receipt)
        (self.worktrees[0] / "fix.txt").write_text("new behavior\n")
        self.commit(self.worktrees[0], "test: change head after verification")
        with self.assertRaisesRegex(ValueError, "head differs"):
            queue.checkpoint(self.db, "p1", "w1", "pr-open", "PR ready", pr=10)

    def test_mutated_receipt_cannot_publish_verified_claim(self):
        receipt = self.receipt()
        queue.checkpoint(self.db, "p1", "w1", "verified", "passed", receipt)
        receipt.write_text(receipt.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "receipt has changed"):
            queue.checkpoint(self.db, "p1", "w1", "pr-open", "PR ready", pr=10)

    def test_green_pr_is_not_a_closed_issue(self):
        receipt = self.receipt()
        queue.checkpoint(self.db, "p1", "w1", "verified", "passed", receipt)
        queue.checkpoint(self.db, "p1", "w1", "pr-open", "PR ready", pr=10)
        prs = [{"number": 10, "state": "OPEN", "closingIssuesReferences": [{"number": 1}],
                "statusCheckRollup": [{"name": "tests", "status": "COMPLETED", "conclusion": "SUCCESS"}]}]
        queue.refresh(self.db, self.inventory, prs)
        self.assertEqual(queue.report(self.db)["tracker_closed"], [])
        self.assertEqual(queue.report(self.db)["packages"][0]["state"], "pr-open")
        queue.refresh(self.db, [issue(1, "CLOSED"), *self.inventory[1:]], prs)
        self.assertEqual(queue.report(self.db)["tracker_closed"], [1])
        self.assertEqual(queue.report(self.db)["packages"][0]["state"], "pr-open")
        queue.checkpoint(self.db, "p1", "w1", "closed", "Writer stopped; merged behavior and tracker checked")
        self.assertEqual(queue.report(self.db)["packages"][0]["state"], "closed")

    def test_external_issue_closure_does_not_release_a_running_writer(self):
        self.claim()
        queue.refresh(self.db, [issue(1, "CLOSED"), *self.inventory[1:]], [])
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.claim(2, "crates/one/lib.rs")
        self.assertEqual(queue.report(self.db)["packages"][0]["state"], "working")

    def test_partial_package_closure_does_not_release_owned_paths(self):
        queue.claim(self.db, "group", [1, 2], "owner", self.worktrees[0], ["crates/one"])
        queue.checkpoint(self.db, "group", "owner", "blocked", "Waiting for remaining acceptance")
        queue.refresh(self.db, [issue(1, "CLOSED"), *self.inventory[1:]], [])
        with self.assertRaisesRegex(ValueError, "every owned issue"):
            queue.checkpoint(self.db, "group", "owner", "closed", "Only one issue done")

    def test_refresh_preserves_scope_and_fails_on_missing_original_issue(self):
        queue.refresh(self.db, self.inventory + [issue(9)], [])
        self.assertEqual(queue.report(self.db)["scope"], 3)
        with self.assertRaisesRegex(ValueError, "incomplete issue readback"):
            queue.refresh(self.db, self.inventory[:1], [])
        self.assertEqual(queue.report(self.db)["open"], 3)

    def test_existing_closing_pr_prevents_duplicate_dispatch(self):
        prs = [{"number": 10, "state": "OPEN", "closingIssuesReferences": [{"number": 1}]}]
        queue.refresh(self.db, self.inventory, prs)
        with self.assertRaisesRegex(ValueError, "already has a PR"):
            self.claim()
        self.assertEqual(queue.report(self.db)["linked_open_issues"], [1])

    def test_report_distinguishes_ci_repair_and_pending(self):
        prs = [{"number": 10, "state": "OPEN", "statusCheckRollup": [
            {"name": "compile", "conclusion": "FAILURE"}]},
               {"number": 11, "state": "OPEN", "statusCheckRollup": [
                   {"name": "CodeQL", "status": "IN_PROGRESS", "conclusion": ""}]}]
        queue.refresh(self.db, self.inventory, prs)
        self.assertEqual([p["next"] for p in queue.report(self.db)["existing_prs"]],
                         ["repair CI", "wait for CI"])


if __name__ == "__main__":
    unittest.main()
