#!/usr/bin/env python3
"""Measure complete offline CLI scans on deterministic inputs (macOS/Linux).

Run: python3 scripts/bench_scan.py [--compare /path/to/previous/hooray] > scan-baseline.json
Includes process startup, SQLite creation, policy evaluation and JSON export.
Fixture generation, checks, one warmup per case and compiling are not timed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = 512
CHAIN_LENGTH = 8
SOURCE_FILES = 32
SOURCE_LINES = 1024


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def source_digest():
    digest = hashlib.sha256()
    for path in sorted([ROOT / "Cargo.toml", ROOT / "Cargo.lock",
                        *ROOT.glob("src/**/*.rs"), *ROOT.glob("migrations/*.sql")]):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def fixtures(directory):
    names = [f"bench-{idx:04d}" for idx in range(COMPONENTS)]
    pairs = [(left, right) for idx, (left, right) in enumerate(zip(names, names[1:]))
             if (idx + 1) % CHAIN_LENGTH]
    expected_edges = dict(pairs)
    sbom = directory / "fixture.cdx.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "library", "bom-ref": name, "name": name,
                        "version": "1.0.0", "purl": f"pkg:cargo/{name}@1.0.0"}
                       for name in names],
        "dependencies": [{"ref": a, "dependsOn": [b]} for a, b in pairs],
    }, indent=1), encoding="utf-8")

    archive = directory / "fixture.zip"
    lock = ['version = 3']
    for name in names:
        lock += ['[[package]]', f'name = "{name}"', 'version = "1.0.0"']
        if name in expected_edges:
            lock.append(f'dependencies = ["{expected_edges[name]}"]')
    with zipfile.ZipFile(archive, "w") as writer:
        # ZipInfo supplies a stable timestamp; never copy file mtimes.
        def member(path, body):
            writer.writestr(zipfile.ZipInfo(path), body, compress_type=zipfile.ZIP_DEFLATED)
        member("Cargo.lock", "\n".join(lock) + "\n")
        for idx in range(SOURCE_FILES):
            member(f"src/module_{idx:02d}.rs", "".join(
                f"// ordinary benchmark module {idx:02d} line {line:04d}\n"
                for line in range(SOURCE_LINES)))
    return [("sbom", sbom), ("artifact", archive)], set(names), set(pairs)


def run_scan(binary, kind, fixture, directory, names, edges):
    database = directory / "scan.db"
    report = directory / "scan.json"
    policy = directory / "policy.yaml"
    policy.write_text("version: 1\ndefault_outcome: allow\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("HOORAY_")}
    env["HOORAY_DATABASE_PATH"] = str(database)
    cmd = [binary, "scan", kind, fixture, "--offline", "--policy", policy,
           "--format", "json", "--output", report]
    # wait4 reports this exact child, unlike cumulative RUSAGE_CHILDREN.
    started = time.perf_counter_ns()
    with subprocess.Popen(cmd, cwd=directory, env=env, stdout=subprocess.DEVNULL) as child:
        _, status, usage = os.wait4(child.pid, 0)
        wall_ms = (time.perf_counter_ns() - started) / 1e6
        child.returncode = os.waitstatus_to_exitcode(status)
        if child.returncode:
            raise subprocess.CalledProcessError(child.returncode, cmd)
    data = json.loads(report.read_bytes())["report"]
    inventory = data["inventory"]
    components = inventory["components"]
    observed_edges = {(components[e["from"]]["name"], components[e["to"]]["name"])
                      for e in inventory["dependencies"]}
    run = data["run"]
    # Export, policy, and persistence each need to show the actual work.
    with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as conn:
        rows = conn.execute("SELECT run_id, finding_count FROM scan_runs").fetchall()
    findings = data["findings"]
    if not (run["metadata"]["offline"] is True
            and len(components) == len(names)
            and {c["name"] for c in components.values()} == names
            and observed_edges == edges and len(inventory["dependencies"]) == len(edges)
            and {v["component_id"] for v in findings.values()
                 if v["rule_id"] == "license:unknown"} == set(components)
            and len(data["policy_decisions"]) == len(findings)
            and rows == [(run["id"], len(findings))]):
        raise ValueError(f"{kind}: output or history does not match the benchmark workload")
    # Random run ID, wall clock, and per-run policy path differ; compare the
    # remaining inventory, evidence, remediation and decisions across binaries.
    normalized = {k: v for k, v in data.items() if k != "run"}
    for finding in normalized["findings"].values():
        finding.pop("first_seen", None)
        finding.pop("last_seen", None)
    semantic_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    rss_bytes = usage.ru_maxrss * (1024 if sys.platform.startswith("linux") else 1)
    return {"wall_ms": round(wall_ms, 3), "peak_rss_mib": round(rss_bytes / (1024**2), 3),
            "findings": len(findings), "report_bytes": report.stat().st_size,
            "semantic_hash": semantic_hash}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5, help="measured runs after one warmup")
    parser.add_argument("--binary", type=Path, help="use an existing binary instead of building release")
    parser.add_argument("--compare", type=Path, help="also scan with this baseline; alternate execution order")
    parser.add_argument("--compare-revision", help="caller-supplied Git revision of the baseline binary")
    args = parser.parse_args()
    if args.runs < 1 or not (sys.platform == "darwin" or sys.platform.startswith("linux")):
        parser.error("requires macOS/Linux and at least one measured run")
    if args.binary:
        binary = args.binary.resolve()
        build = {"profile": "caller-supplied; verify build provenance separately"}
    else:
        subprocess.run(["cargo", "build", "--locked", "--release", "--bin", "hooray"],
                       cwd=ROOT, check=True, stdout=sys.stderr)
        metadata = json.loads(output("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"))
        binary = Path(metadata["target_directory"]) / "release" / "hooray"
        build = {"profile": "cargo build --locked --release --bin hooray",
                 "checkout_head": output("git", "rev-parse", "HEAD"),
                 "checkout_dirty": bool(output("git", "status", "--porcelain")),
                 "source_sha256": source_digest(),
                 "rustc": output("rustc", "--version"), "cargo": output("cargo", "--version")}
    if args.compare_revision and not args.compare:
        parser.error("--compare-revision requires --compare")
    binaries = {"candidate": binary}
    builds = {"candidate": build}
    if args.compare:
        binaries["baseline"] = args.compare.resolve()
        builds["baseline"] = {"profile": "caller-supplied", "revision": args.compare_revision}
    for label, executable in binaries.items():
        builds[label].update({"binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                              "version": output(executable, "--version")})
    result = {"schema_version": 1, "platform": platform.platform(), "machine": platform.machine(),
              "cpu": (output("sysctl", "-n", "machdep.cpu.brand_string")
                      if sys.platform == "darwin" else platform.processor() or platform.machine()),
              "python": platform.python_version(), "builds": builds, "measured_runs": args.runs,
              "warmup_runs": 1, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="hooray-scan-bench-") as workspace:
        directory = Path(workspace).resolve()
        cases, names, edges = fixtures(directory)
        for kind, fixture in cases:
            samples = {label: [] for label in binaries}
            semantic_hash = None
            for idx in range(args.runs + 1):
                for label in (binaries if idx % 2 == 0 else reversed(binaries)):
                    with tempfile.TemporaryDirectory(dir=directory) as scratch:
                        sample = run_scan(binaries[label], kind, fixture, Path(scratch), names, edges)
                    observed = sample.pop("semantic_hash")
                    if semantic_hash is not None and semantic_hash != observed:
                        raise ValueError(f"{kind}: normalized reports differ, timing comparison refused")
                    semantic_hash = observed
                    if idx:
                        samples[label].append(sample)
            result["cases"][kind] = {
                "fixture": fixture.name, "bytes": fixture.stat().st_size,
                "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                "components": len(names), "edges": len(edges),
                "source_files": SOURCE_FILES if kind == "artifact" else 0,
                "normalized_reports_equal_within_run": True,
                "results": {label: {"samples": values,
                            **{f"median_{key}": statistics.median(s[key] for s in values)
                               for key in ["wall_ms", "peak_rss_mib"]}}
                            for label, values in samples.items()},
            }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
