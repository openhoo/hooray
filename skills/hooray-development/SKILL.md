---
name: hooray-development
description: Develop and verify Hooray's Rust scanner, parsers, policies, reports, history store, API, and integrations with deterministic fixtures and bounded input/network handling. Use in a Hooray source checkout.
---

# Hooray development

Read `AGENTS.md` and `CONTRIBUTING.md`. Existing issue-execution skills apply
to issue campaigns, not as additional gates for every focused edit. Commands
run at the checkout root using `rust-toolchain.toml` (currently Rust 1.90.0).

## Find the implementation

| Task | Source |
| --- | --- |
| CLI, exit status, orchestration | `src/main.rs`, `src/engine.rs`, `src/config.rs` |
| Input discovery and safe paths | `src/input.rs`, `src/filesystem.rs` |
| Ecosystem dependency parsing | `src/parsers/` |
| Vulnerability queries and enrichment | `src/osv.rs`, `src/analysis.rs`, `src/risk.rs`, `src/remediation.rs` |
| Local source/config scanners | `src/scanners/` |
| Policy and exceptions | `src/policy.rs`, `src/model.rs` |
| Output and SBOMs | `src/report.rs`, `src/sbom.rs`, `src/graph.rs` |
| History and monitoring | `src/store/`, `src/monitor.rs` |
| HTTP/CI integrations | `src/api.rs`, `src/integrations.rs`, `actions/` |
| Parity experiments | `src/parity/`, `tests/parity_harness.rs`, feature `parity` |

## Verify changes

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo deny check advisories bans licenses sources
```

Start with focused module/test names to reproduce a bug, then run the affected
integration checks. `--all-features` includes the optional parity binary;
default builds do not. Existing tests live inline and in `tests/`, including
ingest robustness, release workflow, and action contracts.

For parsers, use minimal local fixtures that prove accepted/rejected input,
scope, purl/version, declared vs resolved dependencies, and relationship edges.
Include malformed/truncated input and archive/path/digest negative controls.
Do not run package managers or fetch remote parents/BOMs to silently turn a
declaration-only parser into a resolver.

Network changes need bounded-body and timeout tests with controlled responders.
Use a temporary database/config for experiments; avoid adding real scan history
or caches to commits. `cargo build --locked --release` yields the local CLI.

## Preserve evidence and security boundaries

- Unknown versions/licenses/applicability remain unknown; absence of data or an
  offline run does not establish vulnerability absence or reachability.
- Preserve dependency scope, source locations, stable component/finding identity,
  advisory aliases, deduplication, and deterministic output ordering.
- Keep strict config/policy parsing and unknown `HOORAY_` rejection. Exceptions
  require exact selectors, ownership, rationale/ticket, and expiry.
- Retain input/expanded-archive/output bounds, no symlink traversal, archive
  traversal/link rejection, and verified OCI content digests.
- Reports preserve redaction, escaping, schema/model invariants, policy decision,
  and exit status. Output failure is operational failure, not a passing scan.
- API non-loopback exposure requires configured authentication. Preserve
  bounded scan concurrency and persistence/poisoned-store recovery.
- Release installation verifies checksums and signing identity. Hooray is not
  published to crates.io; do not document `cargo install hooray` as installation.

README is the main public contract. Update command/format/parser capability
documentation and action inputs with implementation changes. Never weaken
required checks to land a change. Skill-only documentation changes need
validation and installer checks; no new scanner tests are needed.
