#!/usr/bin/env python3
"""Exercise two real, public Cargo inputs with one Hooray binary and their existing policy.

Requires Python 3.11+, git, and live OSV access. Writes a small JSON receipt to
stdout even when a policy expectation fails. Exit 2 indicates a setup/scan error.
Run in a clone with both revisions available. No project build scripts are run.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
BASE = "0361fda09da6d49d477b127a64624e52aef3969e"
CONTROL = "CVE-2026-115905"
FILES = ("Cargo.lock", "Cargo.toml", "LICENSE", "hooray-policy.yaml")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def scan(binary, rev, expected_exit, parent, save_reports):
    commit = git("rev-parse", "--verify", "--end-of-options", rev + "^{commit}").decode().strip()
    run = parent / str(expected_exit)
    case = run / "project"
    case.mkdir(parents=True)
    hashes = {}
    for name in FILES:
        data = git("show", f"{commit}:{name}")
        (case / name).write_bytes(data)
        hashes[name] = sha(data)
    env = {k: v for k, v in os.environ.items() if not k.startswith("HOORAY_")}
    env["HOORAY_DATABASE_PATH"] = str(run / "history.db")
    report_file = run / "report.json"
    proc = subprocess.run([binary, "scan", "project", case, "--policy", case / "hooray-policy.yaml",
                           "--format", "json", "--output", report_file],
                          cwd=run, env=env, timeout=420, stdout=sys.stderr)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"scanner exited {proc.returncode} on {commit}")
    report = json.loads(report_file.read_bytes())["report"]
    if save_reports is not None:
        name = "base-report.json" if expected_exit == 1 else "candidate-report.json"
        (save_reports / name).write_bytes(report_file.read_bytes())
    components = report["inventory"]["components"]
    expected = {f"pkg:cargo/{p['name']}@{p['version']}" for p in
                tomllib.loads((case / "Cargo.lock").read_text())["package"]}
    actual = {c["purl"] for c in components.values()}
    if expected != actual or len(components) != len(expected):
        raise ValueError(f"inventory disagrees with the lockfile on {commit}")
    if report["run"]["metadata"]["offline"] is not False:
        raise ValueError("unable to verify use of the online provider")
    outcomes = {d["finding_id"]: d["outcome"] for d in report["policy_decisions"]}
    findings = report["findings"].values()
    records = []
    for f in findings:
        if f["kind"] == "vulnerability":
            records.append({"purl": components[f["component_id"]]["purl"],
                            "advisory": f["advisory_id"], "aliases": sorted(f.get("aliases", [])),
                            "severity": f["severity"], "decision": outcomes[f["id"]]})
    records.sort(key=lambda r: (r["purl"], r["advisory"]))
    # The positive control requires the correct package, version and a real block.
    # New findings may legitimately change the nonblocking control: surface drift.
    positive = any(r["purl"] == "pkg:cargo/zip@8.6.0" and r["decision"] == "deny"
                   and CONTROL in [r["advisory"], *r["aliases"]] for r in records)
    fixed_zip = sorted(p for p in expected if p.startswith("pkg:cargo/zip@"))
    fixed_coordinate = (fixed_zip == ["pkg:cargo/zip@9.8.1"]
                        and not any(r["purl"] in fixed_zip and CONTROL in
                                    [r["advisory"], *r["aliases"]] for r in records))
    passed = proc.returncode == expected_exit and (positive if expected_exit == 1 else fixed_coordinate)
    return {"commit": commit, "input_sha256": hashes, "started_at": report["run"]["started_at"],
            "exit_code": proc.returncode, "expected_exit_code": expected_exit, "passed": passed,
            "zip_coordinates": fixed_zip, "components": len(components),
            "edges": len(report["inventory"]["dependencies"]), "lockfile_inventory_equal": True,
            "decisions": dict(sorted(Counter(outcomes.values()).items())),
            "vulnerability_rows": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--candidate-ref", required=True, help="reviewed candidate commit or release tag")
    parser.add_argument("--save-reports", type=Path, help="new private directory for full native reports")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.save_reports is not None:
        args.save_reports.mkdir(mode=0o700, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="hooray-public-controls-") as tmp:
        rows = [scan(binary, ref, code, Path(tmp), args.save_reports) for ref, code in [(BASE, 1), (args.candidate_ref, 0)]]
    if rows[0]["input_sha256"]["hooray-policy.yaml"] != rows[1]["input_sha256"]["hooray-policy.yaml"]:
        raise ValueError("policy changed between controls; review and requalify the comparison")
    print(json.dumps({"control": CONTROL, "provider": "live OSV; no pinned snapshot",
                      "binary_version": subprocess.check_output([binary, "--version"], text=True).strip(),
                      "executable_sha256": sha(binary.read_bytes()),
                      "cases": rows}, indent=2))
    return 0 if all(r["passed"] for r in rows) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, RuntimeError) as err:
        print(f"control check failed: {err}", file=sys.stderr)
        sys.exit(2)
