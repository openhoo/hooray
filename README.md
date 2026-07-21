# Hooray

Hooray is an automation-first software security analysis and policy-enforcement
engine. It builds a normalized dependency inventory from projects, CycloneDX
SBOMs, archives, and OCI images; queries OSV for known vulnerabilities; adds
license, secret, infrastructure-as-code, SAST, malware-indicator, and
operational-risk findings; evaluates an auditable policy; stores scan history in
SQLite; and renders results for humans, CI systems, and security platforms.

Hooray is designed for deterministic automation rather than silent risk
suppression. Findings carry stable identifiers, evidence, confidence,
applicability, remediation data, risk factors, and policy decisions. Operational
failures are distinct from policy denials through separate exit codes.

## Capabilities

### Inputs and inventory

Hooray accepts explicit input types or auto-detects them:

- project directories containing supported lockfiles or manifests;
- CycloneDX JSON SBOMs with nested components and dependency relationships;
- ZIP and TAR artifacts containing supported dependency files;
- OCI image-layout directories;
- OCI or Docker image TAR files; and
- CycloneDX JSON from standard input for `scan sbom` and `scan auto`.

Inventory components retain package URLs, versions, scopes, provenance,
locations, licenses, and dependency edges. Stable component, location, finding,
and run identifiers make reports and history diffs reproducible.

### Vulnerabilities, context, and remediation

- Deduplicates package URLs before network access.
- Queries OSV in batches of at most 1,000 packages and follows paginated batch
  results.
- Fetches each unique advisory once with bounded concurrency.
- Preserves advisory aliases, references, modified timestamps, fixed versions,
  and severity derived from OSV CVSS or ecosystem metadata.
- Classifies dependencies as direct, transitive, or disconnected and records up
  to 32 dependency paths with a maximum traversal depth of 128.
- Records applicability as `affected`, `not-affected`, `fixed`,
  `under-investigation`, or `unknown`, with an evidence-based rationale.
- Computes a transparent risk score from 0 to 10,000 using severity,
  confidence, applicability, dependency scope and directness, fix availability,
  component age, release cadence, and maintenance evidence.
- Selects the nearest higher fixed version, preferring a same-major release,
  and emits ecosystem-specific upgrade guidance for Cargo, npm/pnpm/Yarn,
  pip/Poetry, Go, Maven/Gradle, and NuGet when the required data is available.

`--offline` disables OSV access. Local inventory, license, filesystem, policy,
history, and report operations remain available; vulnerability findings are not
invented or served from an implicit cache.

### Policy and exceptions

Policies are strict YAML or TOML documents using schema version `1`. Unknown
fields are rejected. Rules can select findings by:

- finding kind;
- minimum severity and confidence;
- applicability status;
- risk-score range;
- exact SPDX license expression;
- dependency scope;
- package-URL glob;
- rule-ID glob; and
- advisory-ID glob.

Rules are evaluated by descending priority and then rule ID. Outcomes are
`allow`, `warn`, or `deny`; if no rule matches, `default_outcome` applies.
Policies can fail closed when applicability or license data is unknown.

Exceptions are deliberately narrow and auditable. Every exception requires an
ID, owner, reason, ticket, RFC 3339 expiry, and at least one exact selector.
Exception selectors cannot contain globs. Optional compensating controls are
recorded with the exception, and expired exceptions do not apply.

Example `hooray-policy.yaml`:

```yaml
version: 1
fail_closed:
  unknown_applicability: true
  unknown_licenses: true
default_outcome: warn
rules:
  - id: deny-critical-runtime
    priority: 100
    outcome: deny
    reason: Critical runtime findings are release blocking
    selectors:
      minimum_severity: critical
      scopes: [runtime]
  - id: allow-mit
    priority: 50
    outcome: allow
    reason: MIT is approved
    selectors:
      kinds: [license]
      license_expressions: [MIT]
exceptions:
  - id: temporary-ghsa-exception
    owner: security@example.com
    reason: Upgrade is being validated
    ticket: SEC-1234
    expires_at: "2026-08-01T00:00:00Z"
    compensating_controls:
      - Service is isolated from untrusted input
    selectors:
      advisory_id: GHSA-example
```

Validate and evaluate policies independently:

```bash
hooray policy validate hooray-policy.yaml
hooray policy evaluate hooray-policy.yaml --run-id 'run:UUID' --format yaml
```

### License analysis

Hooray validates declared SPDX expressions and reports missing or invalid
license metadata. For project directories and OCI layouts, it also examines
bounded `LICENSE`, `LICENCE`, `COPYING`, `NOTICE`, and
`THIRD-PARTY-NOTICES` files without following symbolic links. Recognized text
signatures include MIT, Apache-2.0, GPL-3.0, LGPL-3.0, MPL-2.0, BSD-2-Clause,
BSD-3-Clause, ISC, BSL-1.0, and Unlicense. Detection is evidence, not legal
advice; policy should decide which expressions are acceptable for a deployment.

The Hooray repository itself is MIT licensed. Its dependency policy accepts
only the explicit MIT-compatible permissive SPDX allowlist in `deny.toml`:
Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause,
CDLA-Permissive-2.0, ISC, MIT, Unicode-3.0, Unlicense, Zlib, and
bzip2-1.0.6. Unknown, copyleft, source-available, wildcard-version, yanked,
unknown-registry, and unknown-Git dependencies are rejected by the configured
checks; duplicate dependency versions are reported as warnings.

### Secrets, IaC, SAST, and malware indicators

Filesystem analysis is bounded and deterministic. Project directories and OCI
layouts are traversed without following symbolic links by default. Individual
files, aggregate bytes, file count, traversal depth, archive metadata, and
expanded archive inventory are subject to configured or built-in limits.

Secret detection covers AWS access-key IDs, GitHub and GitLab tokens, Slack
tokens, private-key headers, JWT-shaped values, and high-entropy credential
assignments. Placeholder-like values are ignored. Inline allowlist markers are
`hooray:allow-secret`, `pragma: allowlist secret`, `gitleaks:allow`, and
`nosec`. Secret values are never retained: evidence contains only redacted
classification data, length, entropy, and a SHA-256 fingerprint. Report
rendering also redacts values under sensitive key names.

IaC checks include:

- Terraform unrestricted ingress and explicitly disabled storage encryption;
- Dockerfile remote `ADD`, secret-like `ARG`/`ENV`, and absence of an explicit
  non-root `USER`;
- Kubernetes host networking, privileged containers, and privilege escalation;
- CloudFormation S3 buckets without public-access blocking and RDS instances
  without storage encryption.

SAST rules target concrete dangerous syntax in Rust, JavaScript/TypeScript,
Python, Go, Java, and C#, including dynamic shell execution, dynamic evaluation,
and formatted or concatenated SQL. These are focused static rules, not a
compiler-complete data-flow engine.

Malware analysis supports exact caller-supplied SHA-256 signatures in the
library API, executable/script polyglot indicators, embedded PE/ELF signatures,
and metadata-only ZIP bomb heuristics. The CLI currently uses an empty local
signature set, so it does not download or claim a malware-signature feed.

### Operational risk

When provenance evidence supplies the relevant metadata, Hooray reports
abandoned or unmaintained components, yanked or deprecated releases, stale
release activity, and components excessively behind current releases. It does
not infer these states without supporting evidence. Operational findings use
the same policy, history, and risk-scoring model as other finding kinds.

### History, baselines, and monitoring

Every completed CLI scan is saved to the configured SQLite database. History
commands list runs, return complete reports, and diff introduced, resolved, and
unchanged stable finding IDs:

```bash
hooray history list --limit 50 --offset 0 --format json
hooray history show 'run:UUID' --format yaml
hooray history diff 'run:PREVIOUS' 'run:CURRENT' --format json
hooray inventory --run-id 'run:UUID' --format json
hooray report 'run:UUID' --format html --output hooray-report.html
```

A scan can compare itself with an explicit baseline. `--new-findings-only`
retains only findings absent from that baseline; without `--baseline`, it uses
the latest stored run and fails if none exists.

```bash
hooray scan project . --baseline 'run:UUID' --new-findings-only --format table
```

The monitor service persists targets, inventory snapshots, advisory and policy
digests, finding sets, and alert events in SQLite. It rescans only when source
content changes, reevaluates when source/advisory/policy digests change,
deduplicates events, retries delivery with bounded exponential backoff,
dead-letters exhausted events, and prunes expired records. The current CLI
notifier emits JSON alert events to standard error:

```bash
hooray monitor --once
hooray monitor
```

Monitor targets must already exist in the database; the CLI does not provide a
target-registration command.

### HTTP API

Start the API server with:

```bash
hooray serve
```

The v1 API provides:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Process health |
| `GET` | `/ready` | SQLite readiness |
| `POST` | `/v1/scans` | Scan a submitted normalized inventory with optional policy |
| `GET` | `/v1/runs` | Paginated run history |
| `GET` | `/v1/runs/{run_id}` | Complete stored report |
| `GET` | `/v1/runs/{run_id}/diff/{baseline_run_id}` | Finding-ID diff |
| `GET` | `/v1/runs/{run_id}/findings` | Filtered findings for one run |
| `GET` | `/v1/runs/{run_id}/inventory` | Inventory for one run |
| `GET` | `/v1/findings` | Cross-run finding query |
| `GET` | `/v1/inventory` | Cross-run component query |
| `GET` | `/v1/reports/{run_id}` | JSON or YAML by `Accept` negotiation |
| `POST` | `/v1/policies/validate` | Validate a policy document |
| `POST` | `/v1/policies/evaluate` | Evaluate a policy against a report at an explicit time |
| `POST` | `/v1/exceptions/validate` | Validate one exception |

API requests have a configurable body limit, a 30-second processing timeout,
bounded concurrent scan capacity, validated pagination and filters, structured
error envelopes, and an `x-request-id` response header. CORS permits only GET
and POST with the documented request headers and does not enable arbitrary
origins.

The default bind is `127.0.0.1:8080`. Binding to a non-loopback address is
rejected unless `auth_bearer_sha256` is configured. Authentication compares the
SHA-256 digest of a supplied bearer token without storing or logging the raw
token. Hooray provides HTTP, not TLS termination; deploy a trusted TLS reverse
proxy when exposing the service beyond a host boundary.

### Integrations

The CLI can generate bounded templates for pre-commit, GitHub Actions, and
GitLab CI:

```bash
hooray integrations generate pre-commit --output .pre-commit-config.yaml
hooray integrations generate github-actions --output hooray.yml
hooray integrations generate gitlab-ci --output hooray.gitlab-ci.yml
```

Review generated templates before adoption and adapt their scan input and policy
paths to the repository. The integration library also renders GitHub SARIF and
check-run payloads, GitLab Code Quality and dependency-scanning payloads, Slack
summaries, VS Code/LSP diagnostics, pull-request gates, and HTTPS-only signed
webhooks. Webhook signatures are versioned, payloads and annotations are
bounded, secrets must be 16–4,096 bytes, URLs cannot contain credentials, and
signature verification uses constant-time comparison.

## Installation

Hooray requires Rust 1.90 or later to build from source.

```bash
cargo install hooray --locked
```

For repository development:

```bash
git clone https://github.com/openhoo/hooray.git
cd hooray
cargo build --locked --release
```

## CLI reference

The top-level syntax is:

```text
hooray [--config FILE] <COMMAND>
```

Commands and subcommands:

```text
hooray scan project INPUT [--policy FILE] [--baseline RUN_ID] [--new-findings-only] [--format FORMAT] [--output FILE]
hooray scan sbom INPUT    [--policy FILE] [--baseline RUN_ID] [--new-findings-only] [--format FORMAT] [--output FILE]
hooray scan artifact INPUT [--policy FILE] [--baseline RUN_ID] [--new-findings-only] [--format FORMAT] [--output FILE]
hooray scan container INPUT [--policy FILE] [--baseline RUN_ID] [--new-findings-only] [--format FORMAT] [--output FILE]
hooray scan auto INPUT    [--policy FILE] [--baseline RUN_ID] [--new-findings-only] [--format FORMAT] [--output FILE]
hooray policy validate FILE
hooray policy evaluate FILE --run-id RUN_ID [--format json|yaml] [--output FILE]
hooray inventory [--run-id RUN_ID] [--format json|yaml] [--output FILE]
hooray history list [--limit 1..1000] [--offset N] [--format json|yaml] [--output FILE]
hooray history show RUN_ID [--format json|yaml] [--output FILE]
hooray history diff PREVIOUS_RUN_ID CURRENT_RUN_ID [--format json|yaml] [--output FILE]
hooray report RUN_ID [--format FORMAT] [--output FILE]
hooray serve
hooray monitor [--once]
hooray integrations generate pre-commit|github-actions|gitlab-ci [--output FILE]
```

`INPUT` must match the selected scan subcommand. Use `-` as input only with
`scan sbom` or `scan auto`. Output defaults to JSON on standard output; use
`--output FILE` for a file. The default policy is `hooray-policy.yaml` and the
default history database is `hooray.db`.

Examples:

```bash
hooray scan project . --policy hooray-policy.yaml --format table
hooray scan sbom bom.cdx.json --format cyclonedx-vex --output result.cdx.json
cat bom.cdx.json | hooray scan sbom - --format json-lines
hooray scan artifact release.zip --format sarif --output hooray.sarif
hooray scan container image.tar --format spdx --output inventory.spdx.json
hooray scan auto ./input --format gitlab-code-quality --output gl-code-quality-report.json
```

## Output formats

Full scan and stored-report commands support every format below. Inventory,
history, and standalone policy-evaluation commands support JSON and YAML only.

| CLI value | Content |
| --- | --- |
| `json` | Canonical structured scan report |
| `yaml` | Canonical report serialized as YAML |
| `table` | Deterministic human-readable text table |
| `sarif` | SARIF 2.1.0 for code-scanning ingestion |
| `junit` | JUnit XML for CI test-report ingestion |
| `html` | Standalone escaped HTML report |
| `cyclonedx-vex` | CycloneDX JSON with vulnerability analysis |
| `spdx` | SPDX 2.3 JSON inventory |
| `gitlab-code-quality` | GitLab Code Quality JSON |
| `json-lines` | NDJSON envelopes for run, component, finding, policy, and summary records |

Rendered reports validate model invariants, enforce item/text/output bounds, sort
stable collections deterministically, escape format-specific content, and
redact sensitive property names before serialization. The canonical report
format version is `1.0.0`; scan reports currently use schema version `1`.

## Configuration

Pass a YAML or TOML file with global `--config FILE`. Files reject unknown
fields. Environment variables with the `HOORAY_` prefix override the loaded file
or defaults; unknown `HOORAY_` variables are errors.

```yaml
max_concurrency: 32
max_request_bytes: 1048576
max_input_bytes: 104857600
max_archive_bytes: 536870912
max_archive_entries: 100000
database_path: hooray.db
osv_url: https://api.osv.dev
osv_connect_timeout_secs: 10
osv_request_timeout_secs: 30
policy_path: hooray-policy.yaml
monitor_interval_secs: 300
api_bind: 127.0.0.1:8080
auth_bearer_sha256: null
offline: false
```

Environment names are the uppercase field names, for example
`HOORAY_DATABASE_PATH`, `HOORAY_OSV_URL`, `HOORAY_API_BIND`,
`HOORAY_AUTH_BEARER_SHA256`, and `HOORAY_OFFLINE`.

Security and resource defaults:

- 32 concurrent OSV/API scan slots;
- 1 MiB API request bodies;
- 100 MiB input and standard-input bound;
- 512 MiB expanded archive bound;
- 100,000 archive entries;
- configuration values of 10 seconds for OSV connect timeout and 30 seconds for OSV request timeout;
- loopback-only API binding unless bearer authentication is configured;
- no symbolic-link traversal for inventory and license collection;
- path traversal, archive links, OCI digest mismatches, malformed documents, and
  model-invariant violations fail closed; and
- maximum accepted configuration values are validated before execution.

The OSV URL must use HTTP or HTTPS, include a host, and must not contain embedded
credentials, a query, or a fragment. Prefer the default HTTPS endpoint.

The timeout and `monitor_interval_secs` fields are validated configuration
values, but the current CLI OSV client uses reqwest's client defaults and the
monitor service polls every 30 seconds. Do not rely on those three fields as
active runtime overrides in this release.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed and policy produced no denied decisions |
| `1` | Scan, stored report, or standalone policy evaluation contained denied decisions |
| `2` | Configuration, input, network, storage, validation, rendering, or other operational error |

Warnings do not produce exit code `1`. Policy controls the gate; there is no
legacy severity-only `--fail-on` interface.

## Supported project formats

| Ecosystem | Recognized files | Inventory behavior |
| --- | --- | --- |
| Rust | `Cargo.lock`, optional sibling `Cargo.toml` | Packages, checksums, direct dependency hints, Cargo purls |
| npm | `package-lock.json` | Package graph, dev/optional scope, npm purls |
| Python | `requirements.txt` | Pinned `name==version` requirements, PyPI purls |
| Go | `go.sum` | Module/version entries, Go purls |
| NuGet | `packages.lock.json` | Framework dependency graph, direct/transitive hints, NuGet purls |
| CycloneDX | JSON SBOM with versioned purls | Nested and declared dependency edges, scope, provenance |
| OCI/Docker | OCI layout or OCI/Docker TAR | Layer application with whiteouts, digest validation, supported lockfiles from final filesystem |
| Generic artifact | `.zip` or `.tar` | Supported lockfiles discovered in the bounded archive |

Project-directory detection requires at least one supported lockfile. Files with
similar names are not treated as supported inputs, and malformed supported files
fail rather than being silently skipped.

## Quality and security verification

The repository CI runs the following commands:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo llvm-cov --locked --all-targets --all-features --fail-under-lines 90
cargo deny check advisories bans licenses sources
```

The implemented test suite currently contains 234 tests and the current measured
line coverage is 93.52%. CI enforces a 90% line-coverage floor. Commit messages
are linted as Conventional Commits, and dependency advisories, bans, licenses,
and sources are checked on every pull request and push to `main`.

## Releases

Hooversion derives releases from Conventional Commits on `main`, updates the
manifest, lockfile, and changelog, creates the release commit and `v<version>`
tag, and publishes a GitHub Release. The release workflow attaches the optimized
Linux x86_64 binary, archive, and checksums.

## License

Hooray is licensed under the [MIT License](LICENSE).
