# Hooray

Hooray is an automation-first software security analysis and policy-enforcement
engine. It builds a normalized dependency inventory from projects, CycloneDX
and SPDX 2.x SBOMs, archives, and OCI images; queries OSV for known
vulnerabilities; adds
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
- SPDX 2.x JSON SBOMs, detected by their `spdxVersion` key;
- ZIP and TAR artifacts containing supported dependency files;
- OCI image-layout directories;
- OCI or Docker image TAR files; and
- CycloneDX or SPDX 2.x JSON from standard input for `scan sbom` and `scan auto`.

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
- rule-ID glob;
- advisory-ID glob;
- fix availability; and
- exact CVE or advisory identifiers matched against advisory IDs and aliases.

Rules are evaluated by descending priority and then rule ID. Outcomes are
`allow`, `warn`, or `deny`; if no rule matches, `default_outcome` applies.
Policies can fail closed when applicability or license data is unknown.
Exceptions can override these denials only when their selectors explicitly
name the fail-closed policy id (`fail-closed-applicability` or
`fail-closed-license`).

Exceptions are deliberately narrow and auditable. Every exception requires an
ID, owner, reason, ticket, RFC 3339 expiry, and at least one exact selector.
Secret findings can be pinned exactly by the SHA-256 fingerprint recorded in
their evidence.
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
  - id: deny-unfixed-cves
    priority: 90
    outcome: deny
    reason: Known CVEs without available fixes block release
    selectors:
      cves: [CVE-2026-1234]
      fix_available: false
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
signatures include MIT, Apache-2.0, GPL-3.0-only/or-later, LGPL-3.0-only, MPL-2.0, BSD-2-Clause,
BSD-3-Clause, ISC, BSL-1.0, and Unlicense. Detection is evidence, not legal
advice; policy should decide which expressions are acceptable for a deployment.

The Hooray repository itself is Apache-2.0 licensed. Its dependency policy accepts
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
  without storage encryption;
- nginx and Apache weak TLS protocol lists plus server-version disclosure;
- PostgreSQL `pg_hba.conf` trust authentication and `postgresql.conf` SSL
  disabled with md5/plain password encryption;
- Redis disabled protected mode and empty `requirepass`; and
- sshd root login, password authentication, protocol version 1, and empty
  passwords permitted.

SAST rules target concrete dangerous syntax in Rust, JavaScript/TypeScript,
Python, Go, Java, and C#, including dynamic shell execution, dynamic evaluation,
formatted or concatenated SQL, MD5/SHA-1 digest selection, and unsafe
deserialization such as `pickle.loads`, unrestricted `yaml.load`,
`ObjectInputStream.readObject`, and `BinaryFormatter.Deserialize`. These are
focused static rules, not a compiler-complete data-flow engine.

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

Every completed CLI scan is saved to the configured SQLite database. Newly
created database files use owner-only permissions on Unix. History commands
list runs, return complete reports, and diff introduced, resolved, and
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
dead-letters exhausted events, and prunes expired records.

Targets register through the CLI. `monitor targets add TARGET_ID --source
SOURCE --interval-seconds SECONDS` stores a watch entry, `list` paginates
registered targets, and `remove` deletes a target together with its queued
events.

```bash
hooray monitor --once
hooray monitor
hooray monitor targets add webapp --source ./webapp --interval-seconds 300
hooray monitor targets list --limit 50 --offset 0 --format json
hooray monitor targets remove webapp
```

The CLI notifier emits JSON alert events to standard error by default. Passing
`--webhook-url URL` together with `--webhook-secret-env VAR` switches delivery
to an HTTPS-only webhook signed with the shared integration HMAC scheme. The
secret is resolved from the named environment variable before the loop starts
and never appears in errors or logs; the flags are required as a pair, and
omitting both keeps standard-error delivery.

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
| `POST` | `/v1/scans` | Analyze a submitted normalized inventory with optional policy |
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

Submitted inventories receive vulnerability, declared-license, operational-risk,
scoring, remediation, and policy passes. Offline mode skips only OSV access;
the local inventory analyses and report persistence remain available.

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

The CLI generates bounded templates for pre-commit, GitHub Actions, universal
GitLab CI, and GitLab 19.2+ Ultimate security ingestion:

```bash
hooray integrations generate pre-commit --output .pre-commit-config.yaml
hooray integrations generate github-actions --output hooray.yml
hooray integrations generate gitlab-ci --output hooray.gitlab-ci.yml
hooray integrations generate gitlab-security --output hooray.gitlab-security.yml
```

Both GitLab templates run one scan and publish Code Quality, JUnit, and dotenv
reports before enforcing policy in a later `security-gate` stage. The
`gitlab-security` template additionally declares SARIF security ingestion and
CycloneDX SBOM ingestion for GitLab 19.2+ Ultimate. SARIF is the vulnerability,
SAST, and supported secret-detection feed; CycloneDX populates GitLab's
dependency list and continuous dependency scanning. Consumers with an existing
top-level `stages` list must merge the `security-gate` stage.

`HOORAY_IMAGE` is required and has no mutable fallback. Set it to the verified
`ghcr.io/openhoo/hooray@sha256:<digest>` recorded in the matching GitHub Release.
Before merging template support, an OpenHoo owner must bootstrap the GHCR package
from this repository's Dockerfile, link it to `openhoo/hooray`, make it public,
remove local credentials, and prove an anonymous digest pull, `--version`, and
UID 1000 execution. Keep that bootstrap image until a normal release image is
published and anonymously verified. The templates default `HOORAY_INPUT` to `.`
and `HOORAY_POLICY` to `hooray-policy.yaml`; that policy file must exist because
the scan engine always loads policy. Set `HOORAY_DISABLED=true` to skip both
jobs.

Review generated templates before adoption. The integration library also
renders bounded GitHub SARIF and check-run payloads, GitLab Code Quality, Slack
summaries, VS Code/LSP diagnostics, pull-request gates, Jira create-issue
payloads with escaped wiki markup and capped finding lists, and HTTPS-only
signed webhooks. Webhook signatures are versioned, secrets must be 16–4,096
bytes, URLs cannot contain credentials, and verification uses constant-time
comparison.

## Installation

Hooray requires Rust 1.90 or later to build from source.

```bash
cargo install hooray --version 0.6.4 --locked
```

For repository development:

```bash
git clone https://github.com/openhoo/hooray.git
cd hooray
cargo build --locked --release
```

## Library usage

Hooray is also a library crate. Add it to a project with:

```toml
[dependencies]
hooray = "0.6"
```

The minimum supported Rust version is 1.90, enforced through the repository's
`rust-toolchain.toml`. The only feature flag is the optional `parity`, which
gates the JFrog Xray record-replay harness module and its `hooray-parity`
binary; it is disabled by default.

A minimal scan pipeline:

```rust
use hooray::config::Config;
use hooray::engine::{Engine, ScanRequest};
use hooray::input::ScanInput;
use hooray::report::{ReportFormat, render_to_string};
use hooray::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(None)?;
    let mut store = Store::open("hooray.db")?;

    let input = ScanInput::detect("./my-project", &config)?;
    let request = ScanRequest::new(input, std::path::PathBuf::from("hooray-policy.yaml"));
    let report = Engine::new(&config, &mut store, None).scan(request).await?;

    store.save_report(&report)?;
    print!("{}", render_to_string(&report, ReportFormat::Json)?);
    Ok(())
}
```

`ScanInput::detect` auto-detects the input kind and builds the normalized
inventory; every scan loads and evaluates a policy document, so
`ScanRequest::new` takes its path. Passing `None` as the engine's provider
selects the built-in OSV client; supply a custom `VulnerabilityProvider`
implementation instead for deterministic or offline behavior.
`render_to_string` supports the same formats as the CLI, and `save_report`
persists the completed report to SQLite history.

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
hooray monitor [--once] [--webhook-url URL --webhook-secret-env VAR]
hooray monitor targets add TARGET_ID --source SOURCE --interval-seconds SECONDS
hooray monitor targets list [--limit 1..1000] [--offset N] [--format json|yaml|table] [--output FILE]
hooray monitor targets remove TARGET_ID
hooray integrations generate pre-commit|github-actions|gitlab-ci|gitlab-security [--output FILE]
```

`INPUT` must match the selected scan subcommand. Use `-` as input only with
`scan sbom` or `scan auto`. Output defaults to JSON on standard output; use
`--output FILE` for a file. `gitlab-artifacts` instead requires a new directory
path. The default policy is `hooray-policy.yaml` and the default history database
is `hooray.db`.

Examples:

```bash
hooray scan project . --policy hooray-policy.yaml --format table
hooray scan sbom bom.cdx.json --format cyclonedx-vex --output result.cdx.json
cat bom.cdx.json | hooray scan sbom - --format json-lines
hooray scan artifact release.zip --format sarif --output hooray.sarif
hooray scan container image.tar --format spdx --output inventory.spdx.json
hooray scan auto ./input --format gitlab-code-quality --output gl-code-quality-report.json
hooray scan auto ./input --format gitlab-sarif --output gl-sarif-report.sarif
hooray scan auto ./input --format gitlab-cyclonedx --output gl-sbom-hooray.cdx.json
hooray scan auto ./input --format gitlab-artifacts --output .hooray-gitlab
```

## Output formats

Full scan and stored-report commands support every format below. Inventory,
history, and standalone policy-evaluation commands support JSON and YAML only.

| CLI value | Content |
| --- | --- |
| `json` | Canonical structured scan report |
| `yaml` | Canonical report serialized as YAML |
| `table` | Deterministic human-readable text table |
| `sarif` | Generic SARIF 2.1.0 |
| `gitlab-sarif` | GitLab 19.2+ SARIF 2.1.0 security ingestion |
| `junit` | JUnit XML for CI test-report ingestion |
| `html` | Standalone escaped HTML report |
| `cyclonedx-vex` | CycloneDX JSON with vulnerability analysis |
| `gitlab-cyclonedx` | CycloneDX 1.6 inventory for GitLab dependency ingestion |
| `spdx` | SPDX 2.3 JSON inventory |
| `gitlab-code-quality` | GitLab Code Quality JSON |
| `json-lines` | NDJSON envelopes for run, component, finding, policy, and summary records |
| `csv` | RFC 4180 flat finding rows with fixed columns from `stable_finding_id` through `first_location_path` |
| `gitlab-artifacts` | Atomic directory bundle containing all five GitLab artifacts |

The `gitlab-artifacts` directory contains exactly
`gl-code-quality-report.json`, `gl-sarif-report.sarif`,
`gl-sbom-hooray.cdx.json`, `gl-junit-report.xml`, and `hooray.env`. The
destination parent must already exist and the destination itself must not.

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
- no symbolic-link traversal for inventory and license collection; root links
  are rejected and safe nested links are skipped;
- path traversal, archive links, OCI digest mismatches, malformed documents, and
  model-invariant violations fail closed; and
- maximum accepted configuration values are validated before execution.

The OSV URL must use HTTPS unless the host is a loopback address, include a
host, and must not contain embedded credentials, a query, or a fragment. The
default endpoint is HTTPS.

OSV connection and request operations use the configured timeout values. The
monitor service uses `monitor_interval_secs` as its polling interval; each
target's own interval still determines when that target becomes due.

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
| Yarn | `yarn.lock` classic or Berry | Locked packages with dependency edges, npm purls |
| pnpm | `pnpm-lock.yaml` | Locked packages with dev/optional scope, npm purls |
| Python pip | `requirements.txt` | Pinned `name==version` requirements, PyPI purls |
| Python Poetry | `poetry.lock` | Locked PyPI packages, PyPI purls |
| Python Pipenv | `Pipfile.lock` | Pinned default/develop packages, PyPI purls |
| Ruby | `Gemfile.lock` | `GEM`-section specs, gem purls |
| Go | `go.mod` requirements | Module/version entries, Go purls |
| Swift | `Package.resolved` v1 or v2 | Pinned identities and versions, Swift purls |
| Dart | `pubspec.lock` | Locked pub packages, pub purls |
| CocoaPods | `Podfile.lock` | Pod entries, CocoaPods purls |
| PHP | `composer.json` | Declared `require`/`require-dev` packages, composer purls; platform packages skipped |
| Conda | `environment.yml` | Dependency list entries, conda purls |
| Helm | `Chart.yaml` | Declared chart dependencies, Helm purls |
| NuGet | `packages.lock.json` | Framework dependency graph, direct/transitive hints, NuGet purls |
| CycloneDX | JSON SBOM with versioned purls | Nested and declared dependency edges, scope, provenance |
| SPDX | 2.x JSON detected by `spdxVersion` | Packages, checksums, declared `DEPENDS_ON` relationships |
| OCI/Docker | OCI layout or OCI/Docker TAR | Layer application with whiteouts, digest validation, supported lockfiles from final filesystem |
| Generic artifact | `.zip` or `.tar` | Supported lockfiles discovered in the bounded archive |

Project-directory detection requires at least one supported lockfile. Files with
similar names are not treated as supported inputs, and malformed supported files
fail rather than being silently skipped. If filesystem-analysis admission bounds
omit files, the report includes a high-severity `scanner:coverage-incomplete`
operational-risk finding with scanned and skipped counters.

## Quality and security verification

The repository CI runs the following commands:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo llvm-cov --locked --all-targets --all-features --fail-under-lines 90
cargo deny check advisories bans licenses sources
```

The test suite covers every module with focused unit and end-to-end tests;
CI measures line coverage on every run and enforces a 90% floor. Commit messages
are linted as Conventional Commits, and dependency advisories, bans, licenses,
and sources are checked on every pull request and push to `main`.

Dependency-comparison claims against JFrog Xray are backed by a measured
record-replay harness; see [JFrog Xray parity testing](#jfrog-xray-parity-testing).

## JFrog Xray parity testing

Hooray claims capability parity with JFrog Xray at the commit level since
version 0.5.0. The optional `parity` harness turns that claim into a measured,
repeatable differential test instead of an assertion: an identical
deterministic corpus is scanned by Hooray and by a real JFrog Xray
installation through the JFrog CLI, both outputs are normalized into one
canonical model, and explicit overlap metrics compare the two sides.

### Architecture

The harness is record-replay. A deterministic corpus of about 21 cases under
`tests/fixtures/parity/corpus/<case_id>/`, described by
`corpus/manifest.json`, covers every supported input format kind: project
directories, CycloneDX SBOMs, SPDX SBOMs, and ZIP archives. Each case is
scanned twice - once with Hooray and once with real JFrog Xray invoked via
`jf audit` - and both outputs are normalized into canonical model version 1:
components sorted by package URL with scope, directness, and licenses;
vulnerabilities sorted with aliases, fixed versions, and severity labels;
license findings; and parse errors. A recording under
`tests/fixtures/parity/recordings/<case_id>.recording.json` commits both
sides together with provenance, so every later comparison replays offline
without network access.

Comparison runs on two tiers:

- Tier 1 (CI, offline) replays committed recordings. It verifies corpus
  detect/parse coverage against the manifest, applies a drift guard that
  re-scans each case offline and compares components, licenses, license
  findings, and parse errors exactly against the recorded Hooray side, and
  computes the scorecard from recordings, applying enforcement thresholds
  where a recording declares them.
- Tier 2 (operator refresh) runs in a licensed environment where a real Xray
  installation exists: capture fresh `jf audit` output per case, run `record`
  to commit refreshed recordings, and land those recordings with the change.

Determinism is pinned for replayability: scans use run ID
`run:00000000-0000-4000-8000-000000000000` and advisory date
`2026-01-01T00:00:00Z`.

### Building and running

Build the harness binary behind the `parity` feature:

```bash
cargo build --locked --features parity --bin hooray-parity
```

Scan one corpus case, normalize raw Xray output into the canonical model, or
commit a recording that stores both sides:

```bash
hooray-parity scan-case \
  --case tests/fixtures/parity/corpus/npm-package-lock-basic \
  --offline --policy tests/fixtures/parity/policy/minimal-policy.yaml \
  --format json

hooray-parity normalize-xray --case npm-package-lock-basic \
  --xray-json xray-audit.json --xray-sbom xray-sbom.json

hooray-parity record \
  --case tests/fixtures/parity/corpus/npm-package-lock-basic \
  --out tests/fixtures/parity/recordings/npm-package-lock-basic.recording.json \
  --xray-json xray-audit.json --xray-sbom xray-sbom.json
```

`normalize-xray` and `record` accept one or both of `--xray-json FILE` and
`--xray-sbom FILE`; both also take optional `--xray-cli-version VERSION` and
`--xray-db-date DATE` provenance flags.

Tier-2 refreshes capture Xray reality in a licensed environment with the JFrog
CLI; its JSON output feeds `--xray-json` and its CycloneDX SBOM feeds
`--xray-sbom`:

```bash
jf audit --format json --licenses > xray-audit.json
jf audit --format cyclonedx > xray-sbom.json
```

The CI gate checks the whole corpus against the recordings directory:

```bash
hooray-parity check --corpus tests/fixtures/parity/corpus \
  --recordings tests/fixtures/parity/recordings \
  --format table \
  --min-purl-recall 0.95 --min-purl-precision 0.95 --min-cve-jaccard 0.8
```

`check` also accepts `--format json`; per-recording enforcement thresholds
apply automatically when present, and the optional `--min-*` flags supply
global floors. Exit codes follow the house convention: `0` when comparisons
pass or a case is skipped, `1` for a parity violation, and `2` for
operational errors such as missing files or unparseable input. The
integration suite runs through Cargo:

```bash
cargo test --test parity_harness
```

### Recording provenance

A vulnerability comparison is only meaningful against a pinned database
state, because Xray's vulnerability database moves daily. Every recording
therefore records provenance:

- `hooray_version` - required;
- the Xray server version and JFrog CLI version - required;
- `xray_db_date` - required, pinning the database the comparison was made
  against; and
- enforcement thresholds (`min_purl_recall`, `min_purl_precision`,
  `min_cve_jaccard`) - optional per recording.

### Metrics

All metrics compare the Hooray side with the Xray side using the shared match
key `pkg:<type>/<namespace>/name@version`: type and namespace/name are
lowercased except golang, qualifiers and fragments are stripped, and the
version is kept verbatim.

- PURL recall divides matched purls by all Xray purls; precision divides
  matched purls by all Hooray purls.
- CVE Jaccard similarity over the two advisory sets; two empty sets score
  1.0.
- Severity agreement over matched CVEs at the label level only (`unknown`,
  `low`, `medium`, `high`, `critical`).
- License agreement as Jaccard similarity over licenses of shared components.

### Limitations

Parity is bounded by what each side can know, and the scorecard measures
overlap rather than identity:

- `composer.json` yields constraint-style versions (there is no
  `composer.lock` support), so PHP inventory parity is specifier-level
  rather than resolved-version-level.
- Formats without dependency edges (`requirements.txt`, `go.mod`,
  `Pipfile.lock`, `Gemfile.lock`, `Package.resolved`, `pubspec.lock`,
  `Podfile.lock`, `composer.json`, `environment.yml`, `Chart.yaml`) classify
  all components as disconnected; direct/transitive parity is comparable
  only for npm, Yarn, pnpm, Poetry, Cargo, and NuGet cases.
- Hooray derives severity as bucketed labels from OSV while Xray exposes
  numeric CVSS scores; severity agreement compares label buckets only.
- Vulnerability sets can never be identical because OSV and Xray curate
  different databases. Metrics are overlap measures, not exact-match
  assertions, and recordings pin `xray_db_date` to keep overlaps
  interpretable across refreshes.
- License parity is meaningful mainly for SBOM-input and license-file cases:
  lockfile parsers rarely carry license data while Xray's database does.
- SBOM ingestion takes purls verbatim while Xray canonicalizes qualifier and
  case variants; the match key normalizes case, but diffs report verbatim
  identifiers.

## Releases

Hooversion derives releases from Conventional Commits on `main`, updates the
manifest, lockfile, and changelog, creates the release commit and `v<version>`
tag, and publishes a GitHub Release. The release workflow attaches the optimized
Linux x86_64 archive, SPDX SBOM, checksums, Sigstore bundles, and GitHub artifact
attestations. The GHCR image digest is independently signed and attested; release
notes retain its immutable digest for readback and recovery.

## License

Hooray is licensed under the [Apache License 2.0](LICENSE).
