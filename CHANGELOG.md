# Changelog

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

## Unreleased

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
- Added integration generation for pre-commit, GitHub Actions, and GitLab CI, plus library payloads for GitHub, GitLab, Slack, VS Code/LSP, pull-request gates, and HTTPS-only signed webhooks.
- Added strict configuration loading from YAML/TOML and `HOORAY_*` environment overrides, offline operation, explicit resource ceilings, symlink/path/archive/OCI validation, distinct policy and operational exit codes, and an MIT-compatible permissive dependency license/source policy.
- Added comprehensive product, command, configuration, security, output, API, integration, quality, and license documentation for the rewritten interface.

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
