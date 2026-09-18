#!/usr/bin/env python3
"""Durable local issue ownership. No GitHub writes, Git mutations or agent spawns."""

import argparse
import contextlib
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import sqlite3
import subprocess
import sys


ACTIVE = ("working", "verified", "pr-open")


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path):
    return json.loads(Path(path).read_text())


@contextlib.contextmanager
def transaction(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def initialize(path, inventory, max_active=4):
    if max_active < 1:
        raise ValueError("max-active must be positive")
    with transaction(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        if db.execute("SELECT 1 FROM settings WHERE key='initialized'").fetchone():
            raise ValueError("queue already initialized; refresh it instead of replacing progress")
        db.execute("CREATE TABLE issues (number INTEGER PRIMARY KEY, record TEXT, package TEXT)")
        db.execute("""CREATE TABLE packages (
            name TEXT PRIMARY KEY, owner TEXT, worktree TEXT, surfaces TEXT,
            state TEXT, updated TEXT, detail TEXT, head TEXT, evidence TEXT, pr INTEGER)""")
        db.execute("CREATE TABLE events (at TEXT, package TEXT, action TEXT, detail TEXT)")
        numbers = set()
        for issue in inventory:
            number = int(issue["number"])
            if number in numbers:
                raise ValueError(f"duplicate issue #{number}")
            numbers.add(number)
            if issue.get("state", "OPEN").upper() != "OPEN":
                continue
            db.execute("INSERT INTO issues VALUES (?, ?, NULL)", (number, json.dumps(issue)))
        db.executemany("INSERT INTO settings VALUES (?, ?)",
                       [("initialized", now()), ("max_active", str(max_active))])


def surfaces_normalized(paths):
    result = []
    for raw in paths:
        p = PurePosixPath(raw)
        if p.is_absolute() or ".." in p.parts or any(c in raw for c in "*?[]\\"):
            raise ValueError("surfaces must be relative file/directory paths, without globs")
        result.append(p.as_posix())
    if not result:
        raise ValueError("at least one owned surface is required")
    return sorted(set(result))


def overlaps(left, right):
    return any(a == "." or b == "." or a == b or a.startswith(b + "/")
               or b.startswith(a + "/") for a in left for b in right)


def event(db, package, action, detail):
    db.execute("INSERT INTO events VALUES (?, ?, ?, ?)", (now(), package, action, detail))


def claim(path, name, numbers, owner, worktree, surfaces):
    if not name.strip() or not owner.strip() or not numbers:
        raise ValueError("package, owner and issues are required")
    surfaces = surfaces_normalized(surfaces)
    worktree = str(Path(worktree).resolve(strict=True))
    with transaction(path) as db:
        limit = int(db.execute("SELECT value FROM settings WHERE key='max_active'").fetchone()[0])
        packages = db.execute("SELECT * FROM packages WHERE state != 'closed'").fetchall()
        if sum(p["state"] in ACTIVE for p in packages) >= limit:
            raise ValueError("WIP limit reached; finish or explicitly block an existing package")
        for p in packages:
            if p["worktree"] == worktree or overlaps(surfaces, json.loads(p["surfaces"])):
                raise ValueError(f"ownership overlaps retained package {p['name']} ({p['state']})")
        for number in numbers:
            issue = db.execute("SELECT * FROM issues WHERE number=?", (number,)).fetchone()
            if issue is None or issue["package"]:
                raise ValueError(f"issue #{number} outside snapshot or already owned")
            record = json.loads(issue["record"])
            labels = [l["name"] if isinstance(l, dict) else l for l in record.get("labels", [])]
            if record.get("state", "OPEN").upper() != "OPEN" or "ready-for-agent" not in labels:
                raise ValueError(f"issue #{number} is not open and ready; resolve its triage first")
            if record.get("active_prs"):
                raise ValueError(f"issue #{number} already has a PR; inspect that PR first")
        db.execute("INSERT INTO packages VALUES (?, ?, ?, ?, 'working', ?, ?, NULL, NULL, NULL)",
                   (name, owner, worktree, json.dumps(surfaces), now(), "claimed"))
        db.executemany("UPDATE issues SET package=? WHERE number=?", [(name, n) for n in numbers])
        event(db, name, "claim", json.dumps({"issues": numbers, "owner": owner}))


def git_head(worktree):
    return subprocess.check_output(["git", "-C", worktree, "rev-parse", "HEAD"], text=True).strip()


def verify_receipt(package, evidence):
    receipt_path = Path(evidence).resolve(strict=True)
    data = receipt_path.read_bytes()
    receipt = json.loads(data)
    head = git_head(package["worktree"])
    if receipt.get("head") != head:
        raise ValueError("receipt head differs from package HEAD")
    dirty = subprocess.check_output(
        ["git", "-C", package["worktree"], "status", "--porcelain"], text=True)
    if dirty.strip():
        raise ValueError("verification handoff requires a clean committed package")
    checks = receipt.get("checks", [])
    if not checks or any(not c.get("command") or type(c.get("exit_code")) is not int
                         or c["exit_code"] != 0 for c in checks):
        raise ValueError("receipt requires executed successful checks with command and exit_code")
    if not receipt.get("acceptance"):
        raise ValueError("receipt requires observable acceptance evidence")
    return head, json.dumps({"path": str(receipt_path), "sha256": hashlib.sha256(data).hexdigest()})


def checkpoint(path, name, owner, state, detail, evidence=None, pr=None):
    with transaction(path) as db:
        p = db.execute("SELECT * FROM packages WHERE name=?", (name,)).fetchone()
        if p is None or p["owner"] != owner:
            raise ValueError("unknown package or wrong owner")
        allowed = {"working": {"working", "verified", "blocked"},
                   "verified": {"working", "pr-open", "blocked", "closed"},
                   "pr-open": {"pr-open", "working", "blocked", "closed"},
                   "blocked": {"working", "closed"}, "closed": set()}
        if state not in allowed[p["state"]]:
            raise ValueError(f"invalid transition {p['state']} to {state}")
        if state in ACTIVE and p["state"] not in ACTIVE:
            limit = int(db.execute("SELECT value FROM settings WHERE key='max_active'").fetchone()[0])
            count = db.execute("SELECT count(*) FROM packages WHERE state IN ('working','verified','pr-open')").fetchone()[0]
            if count >= limit:
                raise ValueError("WIP limit reached")
        head, saved_evidence = p["head"], p["evidence"]
        if state == "verified":
            if not evidence:
                raise ValueError("verified requires an evidence receipt")
            head, saved_evidence = verify_receipt(p, evidence)
        if state == "pr-open":
            if not pr or pr < 1 or not saved_evidence:
                raise ValueError("pr-open requires PR number and verified evidence")
            saved = json.loads(saved_evidence)
            if hashlib.sha256(Path(saved["path"]).read_bytes()).hexdigest() != saved["sha256"]:
                raise ValueError("verified receipt has changed")
            current_head, _ = verify_receipt(p, saved["path"])
            if current_head != head:
                raise ValueError("package changed after verification")
        if state == "working":
            head, saved_evidence = None, None
        if state == "closed":
            records = [json.loads(r[0]) for r in db.execute(
                "SELECT record FROM issues WHERE package=?", (name,))]
            if not records or any(r.get("state", "OPEN").upper() != "CLOSED" for r in records):
                raise ValueError("close requires a closed tracker readback for every owned issue")
        db.execute("UPDATE packages SET state=?,updated=?,detail=?,head=?,evidence=?,pr=COALESCE(?,pr) WHERE name=?",
                   (state, now(), detail, head, saved_evidence, pr, name))
        event(db, name, state, detail)


def referenced_issues(pr):
    # Explicit GraphQL closing links only; prose mentions are not ownership proof.
    return {int(i["number"]) for i in pr.get("closingIssuesReferences", [])}


def refresh(path, inventory, prs):
    """Update only original scope; never erase ownership or count a green PR as closed."""
    current = {int(i["number"]): i for i in inventory}
    with transaction(path) as db:
        stored = db.execute("SELECT * FROM issues").fetchall()
        missing = {r["number"] for r in stored} - current.keys()
        if missing:
            raise ValueError(f"incomplete issue readback: {sorted(missing)}")
        for row in stored:
            issue = dict(current[row["number"]])
            issue["active_prs"] = [p["number"] for p in prs if p["state"] == "OPEN"
                                  and row["number"] in referenced_issues(p)]
            db.execute("UPDATE issues SET record=? WHERE number=?", (json.dumps(issue), row["number"]))
        # Tracker closure does not stop a writer. Retain ownership until its
        # owner explicitly checkpoints closed after reviewing the readback.
        db.execute("INSERT OR REPLACE INTO settings VALUES ('prs', ?)", (json.dumps(prs),))
        db.execute("INSERT OR REPLACE INTO settings VALUES ('refreshed', ?)", (now(),))


def report(path):
    with transaction(path) as db:
        settings = dict(db.execute("SELECT key,value FROM settings"))
        issues = [dict(r) for r in db.execute("SELECT * FROM issues ORDER BY number")]
        packages = [dict(r) for r in db.execute("SELECT * FROM packages ORDER BY updated")]
    prs = json.loads(settings.get("prs", "[]"))
    scope = {r["number"] for r in issues}
    open_issues, ready, unready, closed, linked = [], [], [], [], []
    for row in issues:
        i = json.loads(row["record"])
        if i.get("state", "OPEN").upper() == "CLOSED":
            closed.append(row["number"])
            continue
        open_issues.append(row["number"])
        if row["package"]:
            continue
        if i.get("active_prs"):
            linked.append(row["number"])
            continue
        labels = [l["name"] if isinstance(l, dict) else l for l in i.get("labels", [])]
        (ready if "ready-for-agent" in labels else unready).append(row["number"])
    existing_prs = []
    for p in prs:
        if p["state"] != "OPEN":
            continue
        checks = p.get("statusCheckRollup", [])
        failed = [c.get("name", c.get("context", "unknown")) for c in checks
                  if c.get("conclusion", c.get("state")) in {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"}]
        pending = [c.get("name", c.get("context", "unknown")) for c in checks
                   if c.get("status") in {"QUEUED", "IN_PROGRESS", "WAITING", "PENDING", "REQUESTED"}
                   or c.get("state") in {"PENDING", "EXPECTED"}]
        existing_prs.append({"number": p["number"], "head": p.get("headRefOid"),
                             "issues": sorted(scope & referenced_issues(p)),
                             "failed_checks": failed, "pending_checks": pending,
                             "next": "repair CI" if failed else "wait for CI" if pending
                             else "inspect draft, coverage, approvals and protected checks"})
    stale = [p["name"] for p in packages if p["state"] in ACTIVE
             and (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(p["updated"])).total_seconds() > 1800]
    return {"scope": len(scope), "open": len(open_issues), "tracker_closed": closed,
            "refreshed_at": settings.get("refreshed"), "max_active": int(settings["max_active"]),
            "active_packages": sum(p["state"] in ACTIVE for p in packages),
            "stale_packages_inspect_before_reassigning": stale, "existing_prs": existing_prs,
            "linked_open_issues": linked, "ready_unclaimed": ready, "needs_triage": unready,
            "packages": packages,
            "warning": "Unclaimed does not mean unimplemented; inspect retained campaign work before claiming.",
            "next": "reconcile existing PRs and retained work before claiming new issues"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--inventory", required=True, type=Path)
    init.add_argument("--max-active", type=int, default=4)
    take = commands.add_parser("claim")
    take.add_argument("--package", required=True)
    take.add_argument("--issues", required=True, type=int, nargs="+")
    take.add_argument("--owner", required=True)
    take.add_argument("--worktree", required=True, type=Path)
    take.add_argument("--surfaces", required=True, nargs="+")
    mark = commands.add_parser("checkpoint")
    mark.add_argument("--package", required=True)
    mark.add_argument("--owner", required=True)
    mark.add_argument("--state", required=True, choices=["working", "verified", "pr-open", "blocked", "closed"])
    mark.add_argument("--detail", required=True)
    mark.add_argument("--evidence", type=Path)
    mark.add_argument("--pr", type=int)
    sync = commands.add_parser("refresh")
    sync.add_argument("--inventory", required=True, type=Path)
    sync.add_argument("--prs", required=True, type=Path)
    commands.add_parser("report")
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.db, read_json(args.inventory), args.max_active)
        elif args.command == "claim":
            claim(args.db, args.package, args.issues, args.owner, args.worktree, args.surfaces)
        elif args.command == "checkpoint":
            checkpoint(args.db, args.package, args.owner, args.state, args.detail, args.evidence, args.pr)
        elif args.command == "refresh":
            refresh(args.db, read_json(args.inventory), read_json(args.prs))
        print(json.dumps(report(args.db), indent=2))
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        parser.exit(2, f"issue queue: {exc}\n")


if __name__ == "__main__":
    main()
