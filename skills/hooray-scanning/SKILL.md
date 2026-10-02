---
name: hooray-scanning
description: Use Hooray to scan projects, SBOMs, artifacts, and container archives, interpret findings and coverage, apply explicit policies, compare saved runs, and produce CI reports without hiding operational failures.
---

# Scan and triage with Hooray

Work in the target project. Determine input type, existing config/policy,
online/offline intent, report destination, and whether saved history is needed.
Installing this skill does not install the scanner. Read the bundled
[workflow guide](references/workflows.md) for policy, history, and CI details.

## Obtain the scanner

Reuse an approved installed version. Linux x86_64 CI uses the verified release
installer exposed by `openhoo/hooray/actions/setup` or `actions/scan`: pin the
action to a reviewed full commit SHA and select a published release. Hooray is
not on crates.io; `cargo install hooray` is unsupported.

For a local source build, clone `openhoo/hooray`, use its pinned Rust toolchain,
and run `cargo build --locked --release`. The executable is `target/release/hooray`.
On other platforms check available release artifacts or build support rather
than assuming the Linux installer applies.

## Choose input and run

```bash
hooray scan project . --format json --output hooray-report.json
hooray scan sbom bom.cdx.json --format json --output hooray-sbom-report.json
hooray scan artifact release.zip --format sarif --output hooray.sarif
hooray scan container image.tar --format spdx --output inventory.spdx.json
```

Use `scan auto` for supported automatic detection; prefer an explicit type
when known. `scan sbom -` and `scan auto -` accept stdin; project/artifact/
container modes do not. Global configuration precedes the command:
`hooray --config hooray.yaml scan project . --format table`.

For a supplied policy, validate it and pass `--policy hooray-policy.yaml`.
For offline local analysis, add `--offline`; this disables OSV requests and
must not be reported as a complete live advisory check. Scan metadata and
parser coverage determine what the report actually establishes.

The default history store is `hooray.db` in the working directory. Use
`HOORAY_DATABASE_PATH` or configuration to select a dedicated store outside
source inventory when appropriate. Never overwrite/delete another run's history.

## Interpret and fix

1. Preserve command, version, input, policy, online/offline mode, run identity,
   report, and exit status. Exit 0 is a passed decision; 1 a policy denial;
   2 an operational/configuration/report error.
2. Correlate each actionable finding with its exact component/version/source
   location, advisory/rule ID, scope, applicability, confidence, and fix evidence.
   Deduplicate aliases; do not treat similar package names as the same identity.
3. Inspect parser limitations and unknown/skipped inputs. Manifest declarations
   are not always resolved lockfile versions; a clean report cannot establish
   coverage of formats or inputs that were not analyzed.
4. Implement the requested remediation in the consuming project, run its tests,
   and rescan with the same policy and comparable input. Verify the finding is
   resolved without introducing new denials or losing scan coverage.

Secret findings are evidence about exposure: do not reproduce secret values in
summaries or reports beyond the scanner's redacted output. Exceptions require
an explicit owned/time-bounded decision, not an automatic response to a failing
scan. A baseline or new-findings filter must not hide the complete risk inventory.
