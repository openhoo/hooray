# Changelog

## Unreleased

### Breaking Changes

- Reclassified the dependency graph and scanner error changes already present on
  the released 0.6.x line for the next breaking release: `GraphError::Cycle`
  is no longer exposed (and dependency cycles are accepted), while
  `ScanError::Walk::source` now carries `ignore::Error` instead of
  `walkdir::Error`. Consumers with exhaustive `GraphError` matches must remove
  the `Cycle` arm, and consumers inspecting `Walk::source` must update the
  concrete error type. Continue using the released 0.6.x dependency until the
  next breaking release is published.

## 0.6.4 (2026-08-31)

### Bug Fixes

- align Hoostack policy and release supply chain (5726283)
- **release:** honor protected main branch (58dbc8a)

## 0.6.3 (2026-08-30)

### Bug Fixes

- **license:** adopt Apache-2.0 (#12) (f536513)

### Other Changes

- standardize Hoostack dogfood (#11) (3dcdebb)

## 0.6.2 (2026-08-30)

### Bug Fixes

- **scanner:** make Hoostack dogfood reliable (c2fa797)
- **scanner:** emit valid Swift package URLs (d80464e)
- **actions:** default to next release (d07c069)

### Other Changes

- use released Hoostack actions (1f883e4)
- test pull request head commit (1fdd4dd)

## 0.6.1 (2026-08-28)

### Bug Fixes

- harden runtime, persistence, and monitoring (3f3e632)

### Review Hardening

- Activated configured OSV connection/request timeouts and monitor polling.
- Aligned API scans with CLI inventory analyses, including offline operation.
- Redacted sensitive free-form report values before SQLite persistence and
  created new Unix database files with owner-only permissions.
- Fixed quality-aware report negotiation, monitor fingerprint truncation and
  database self-triggering, and safe handling of nested repository symlinks in
  inventory and license passes.
- Made filesystem scanner bound omissions visible to policy and reports.
- Removed a tracked runtime database and stale advisory exception, and replaced
  the yanked lock-only `chacha20` release.

## 0.6.0 (2026-08-26)

### Other Changes

- replace rot-prone test counts with stable coverage wording (e4277c6)
- cut duplication and complexity hotspots (b70ddcf)

### Features

- restructure parsers, add parity harness, land review hardening (f7a0b09)

### Bug Fixes

- bound save-only bench by accumulated window (ece60ae)

### Major Features

- Replaced the original single-purpose CycloneDX/OSV command with a clean-cut enterprise security analysis and policy-enforcement CLI. The previous positional scan interface and severity-only `--fail-on` gate are removed entirely.
- Added explicit `scan project`, `scan sbom`, `scan artifact`, `scan container`, and `scan auto` workflows with bounded input detection for supported project lockfiles, CycloneDX JSON, ZIP/TAR artifacts, OCI image layouts, and OCI/Docker image archives.
- Added normalized inventories with stable identities, provenance, locations, scopes, dependency graphs, direct/transitive classification, bounded dependency paths, and deterministic run metadata.
- Expanded vulnerability analysis with deduplicated and paginated OSV batch queries, bounded concurrent advisory retrieval, applicability context, transparent risk scoring, fixed-version extraction, and ecosystem-specific remediation plans.
- Added license analysis, secret detection with redacted evidence, Terraform/Dockerfile/Kubernetes/CloudFormation checks, focused SAST rules for six language families, malware indicators, archive-bomb heuristics, and provenance-backed operational-risk findings.
- Added schema-versioned YAML/TOML policies with priority ordering, allow/warn/deny outcomes, fail-closed controls, selectors across finding context, and exact, owned, ticketed, expiring exceptions with optional compensating controls.
- Added SQLite-backed scan history, inventory retrieval, run display, baseline comparison, introduced/resolved/unchanged diffs, first/last-seen tracking, and new-findings-only scans.
- Added JSON, YAML, table, SARIF 2.1.0, JUnit XML, HTML, CycloneDX VEX, SPDX 2.3 JSON, GitLab Code Quality, and JSON Lines report rendering with validation, deterministic ordering, output bounds, escaping, and sensitive-field redaction.
- Added the authenticated v1 HTTP API for scans, runs, diffs, findings, inventory, reports, policies, and exceptions, including health/readiness endpoints, bounded request bodies and concurrency, request IDs, timeouts, validated filters, safe CORS behavior, and mandatory bearer authentication for non-loopback binds.
- Added persistent monitoring with source/advisory/policy change detection, conditional rescans and reevaluation, deduplicated alert events, bounded retries, dead-letter handling, retention pruning, one-shot execution, and continuous operation.
- Added integration generation for pre-commit, GitHub Actions, GitLab CI, and GitLab Ultimate security ingestion, plus library payloads for GitHub, GitLab, Slack, VS Code/LSP, pull-request gates, and HTTPS-only signed webhooks.
- Added strict configuration loading from YAML/TOML and `HOORAY_*` environment overrides, offline operation, explicit resource ceilings, symlink/path/archive/OCI validation, distinct policy and operational exit codes, and an MIT-compatible permissive dependency license/source policy.
- Added comprehensive product, command, configuration, security, output, API, integration, quality, and license documentation for the rewritten interface.

## 0.5.1 (2026-08-25)

### Bug Fixes

- harden scanner after full-project agent review (a169b1f)

## 0.5.0 (2026-08-25)

### Features

- close JFrog Xray capability gaps (39c65ff)

## 0.4.0 (2026-07-22)

### Features

- **gitlab:** add native report integrations (c97980f)

## 0.3.4 (2026-07-21)

### Performance

- parallelize file analysis (60a2961)

## 0.3.3 (2026-07-21)

### Performance

- accelerate analysis and reports (8a186de)

## 0.3.2 (2026-07-21)

### Performance

- accelerate reports and persistence (f7147ac)

## 0.3.1 (2026-07-21)

### Performance

- accelerate scanning hot paths (30c922b)

## 0.3.0 (2026-07-21)

### Other Changes

- switch to MIT license (6145bcb)

### Features

- harden enterprise security scanner (826aa07)

## 0.2.1 (2026-07-21)

### Bug Fixes

- **release:** synchronize Cargo lockfile (1dee3c3)

## 0.2.0 (2026-07-21)

### Features

- **hooray:** add fast OSV SBOM scanner (256db41)

### Other Changes

- reduce hosted runner usage (38b0484)

All notable changes to Hooray are recorded here.

## 0.1.0

- Initial CycloneDX and OSV vulnerability scanning CLI.
