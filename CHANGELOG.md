# Changelog

## 0.9.0 (2026-09-22)

### Features

- **scanners:** IaC checks for docker-compose and GitHub Actions (3a6cbe6)

### Bug Fixes

- **parsers:** resolve lockfile edge, scope, and abort defects from audit (985a893)
- **reports:** harden SBOM ingestion, renderers, model, monitor, and store (362111e)
- **parity:** harden corpus loading, comparison keys, gates, and recording validation (7767d39)
- **parsers:** harden archive readers and expose OCI filesystem builder (99a1f78)
- **engine:** harden OSV matching, graph classification, and input handling (0a5caaa)
- **scanners:** close audit findings in secret, IaC, service-config, SAST, and license (9ec9d45)
- **parsers:** resolve quoted and multi-version Yarn classic dependencies (9a7fa8a)
- **store:** require FULL synchronous for commit durability (35e3491)
- **risk:** rank Unknown severity above Low in severity_points (43cee0a)
- **input:** bound serde_yaml alias expansion on untrusted lockfiles (9a24589)
- **parsers:** accept multi-document pnpm-lock.yaml (#337) (2f1cd6f)

### Other Changes

- **ci:** align dependabot naming with hoolicy policy (#116) (de8f062)
- **parity:** harden recording integrity and corpus coverage assertions (54112a3)
- bump actions/github-script from 8.0.0 to 9.0.0 (#117) (847f10b)
- bump rusqlite from 0.37.0 to 0.40.2 (#118) (776a160)
- bump zstd from 0.13.3 to 0.14.0 (#119) (1c59e21)
- bump toml from 0.9.12+spec-1.1.0 to 1.1.6+spec-1.1.0 (#120) (9ed037b)

## 0.8.0 (2026-09-18)

### Features

- **cli:** add --offline flag matching documented behavior (#34) (4097058)
- **parsers:** support Bun text lockfiles (#38) (945dda9)
- **parsers:** add Chart.lock, composer.lock, and NuGet CPM/csproj/packages.config parsers (#52) (3b51a20)
- **parsers:** add Gradle lockfile, Maven pom.xml, and Go stdlib toolchain coverage (#84) (62f91f6)
- **parsers:** inventory Cabal dependencies and freeze pins (#103) (bc68185)
- **parsers:** add Mix lockfile parser for Hex dependencies (#101) (e8ec136)
- **parsers:** inventory Gradle version catalog declarations (#104) (190b85f)

### Bug Fixes

- **scanner:** exclude VCS metadata directories from repository walk (#35) (4a55ccd)
- **scanner:** honor usedforsecurity=False in Python weak-hash rules (#36) (92f1172)
- **parsers:** anchor asset identity to root lockfile (#37) (200232a)
- **scanners:** tolerate JSONC/BOM IaC JSON, detect encrypted PEMs, skip regex literals (#51) (5e275b1)
- **parsers:** pnpm v9 edges/scopes, specifier phantoms, bun asset identity (#53) (191e043)
- **core:** OCI layer decompression, shared dependency-path index, honest introduced:0 (#54) (b5c2ca7)
- **cli:** scope --format enums per subcommand; fix monitor target display and errors (#80) (b5a389c)
- **parsers:** tolerate versionless SBOM entries, ./ tar roots, compressed tarballs (#82) (d3e7f2e)
- **parsers:** indent-aware bundler/pod specs, poetry groups, honest unpinned versions (#81) (3961a76)
- **scanners:** IaC anchoring/coverage, secret placeholder filtering, polyglot and SAST FPs (#83) (e5bb809)
- **parsers:** preserve Composer lockfile licenses (#97) (228d4a8)
- **parsers:** retain versioned yarn descriptor identities (#98) (57ea15f)
- **scanners:** structure-aware PE recognition, escaped PEM detection, credential-shape suppression (#100) (82303be)
- **parsers:** support legacy per-configuration Gradle lockfiles (#99) (f086600)
- **parsers:** preserve Composer lockfile dependency edges (#102) (0c9de34)
- **parsers:** exclude Maven template placeholders and record unresolved declarations (#105) (8d1085a)

### Other Changes

- **issues:** port issue governance and exploratory-smoke campaign skills (#28) (e6533f9)
- **ci:** adopt Hoolicy v0.3.2 action check (#107) (6ed727c)
- **ci:** adopt Hoonarqube v0.8.2 analyze action (#108) (878d667)
- **deps:** bump tower-http from 0.6.11 to 0.7.1 (#109) (25a8cf2)
- **deps:** bump sha2 from 0.10.9 to 0.11.0 (#110) (e3bc6df)
- **deps:** bump spdx from 0.10.9 to 0.13.5 (#111) (cbfe559)
- **deps:** bump jsonschema from 0.47.0 to 0.56.0 (#112) (0575b91)
- **deps:** bump zip from 4.6.1 to 8.6.0 (#113) (cac74fa)
- **release:** adopt Hooversion v1.1.2 for squash-suffix release resume (#114) (91b32d6)

## 0.7.0 (2026-09-18)

### Features

- **cli:** add --offline flag matching documented behavior (#34) (4097058)
- **parsers:** support Bun text lockfiles (#38) (945dda9)
- **parsers:** add Chart.lock, composer.lock, and NuGet CPM/csproj/packages.config parsers (#52) (3b51a20)
- **parsers:** add Gradle lockfile, Maven pom.xml, and Go stdlib toolchain coverage (#84) (62f91f6)
- **parsers:** inventory Cabal dependencies and freeze pins (#103) (bc68185)
- **parsers:** add Mix lockfile parser for Hex dependencies (#101) (e8ec136)
- **parsers:** inventory Gradle version catalog declarations (#104) (190b85f)

### Bug Fixes

- **scanner:** exclude VCS metadata directories from repository walk (#35) (4a55ccd)
- **scanner:** honor usedforsecurity=False in Python weak-hash rules (#36) (92f1172)
- **parsers:** anchor asset identity to root lockfile (#37) (200232a)
- **scanners:** tolerate JSONC/BOM IaC JSON, detect encrypted PEMs, skip regex literals (#51) (5e275b1)
- **parsers:** pnpm v9 edges/scopes, specifier phantoms, bun asset identity (#53) (191e043)
- **core:** OCI layer decompression, shared dependency-path index, honest introduced:0 (#54) (b5c2ca7)
- **cli:** scope --format enums per subcommand; fix monitor target display and errors (#80) (b5a389c)
- **parsers:** tolerate versionless SBOM entries, ./ tar roots, compressed tarballs (#82) (d3e7f2e)
- **parsers:** indent-aware bundler/pod specs, poetry groups, honest unpinned versions (#81) (3961a76)
- **scanners:** IaC anchoring/coverage, secret placeholder filtering, polyglot and SAST FPs (#83) (e5bb809)
- **parsers:** preserve Composer lockfile licenses (#97) (228d4a8)
- **parsers:** retain versioned yarn descriptor identities (#98) (57ea15f)
- **scanners:** structure-aware PE recognition, escaped PEM detection, credential-shape suppression (#100) (82303be)
- **parsers:** support legacy per-configuration Gradle lockfiles (#99) (f086600)
- **parsers:** preserve Composer lockfile dependency edges (#102) (0c9de34)
- **parsers:** exclude Maven template placeholders and record unresolved declarations (#105) (8d1085a)

### Other Changes

- **issues:** port issue governance and exploratory-smoke campaign skills (#28) (e6533f9)

## 0.6.6 (2026-09-08)

### Bug Fixes

- **integrations:** make GitHub and GitLab reporting portable (8fe0ba0)

### Other Changes

- **ci:** converge released tool pins (3cd3646)
- **ci:** adopt Hoonarqube v0.3.1 (9e0d686)

## 0.6.5 (2026-09-03)

### Bug Fixes

- **scanner:** harden structural analysis and monitoring (0e49874)

### Other Changes

- **ci:** update Hoostack tool pins (#16) (d656407)
- **ci:** adopt HooNeedsUpdates v0.3.0 (5118bfa)

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
