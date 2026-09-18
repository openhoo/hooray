---
name: exploratory-smoke
description: Run a bounded, evidence-first Hooray exploration over pinned public projects against reference scanners and publish only confirmed, immediately triaged issue or coverage handoffs.
version: 1
disable-model-invocation: true
---

# Hooray exploratory smoke

Use `/skill:exploratory-smoke` for a finite real-project campaign. The skill
starts from immutable public source pins, runs the native scanner and
applicable reference scanners under explicit resource limits, reviews
discrepant behavior at the source/evidence seam, and publishes only an
actionable result. It is a campaign workflow, not a release qualification, a
parity claim, or permission to change scanner source.

This file is portable: it uses repository-local contracts and the standard
`git`, `gh`, `podman`, `flock`, `sha256sum`, Node, and Python tooling available
to the caller. It does not require a global skill, an unpublished helper
script, or a pre-existing temporary directory. Read the current repository
files and tool help before using a command; do not copy historical command
lines, identities, or counts as current defaults.

## Non-negotiable boundaries

- The scope is finite. Use the explicit matrix below as the default only when
  the invocation does not provide another finite matrix. An explicit invocation
  may replace or narrow it with named public projects or images; record that
  override. Do not add repositories, ecosystems, rules, or follow-up scans
  implicitly.
- Use only public GitHub repositories and detached, immutable full-commit
  pins. Record the resolved 40-hex commit for every checkout before scanning.
  A branch, moving tag, shallow tip, or unverified archive is not a source
  pin. For OCI inputs, pin by `@sha256:` digest, never a tag.
- Scan unchanged source. Build the scanner in an isolated worktree and do not
  rewrite a project to make a detector fire, make a parser accept input, or
  make a reference comparison look equal. Do not install or run a public
  project's arbitrary build/install scripts unless the manifest records the
  command, trust decision, network policy, and bounded result.
- Default to observation and issue/coverage handoff. Do not edit Hooray
  source, mutate the pinned source checkout, close issues, merge, release, or
  publish an artifact. Explicit fix authorization is a separate handoff to
  either [`skill://fix-issue`](../fix-issue/SKILL.md) for one selected issue
  or [`skill://work-issues`](../work-issues/SKILL.md) for a finite queue
  (which composes `fix-issue`).
- Issue creation, reopening, body/comment publication, and label/state changes
  require explicit publication authority in the campaign invocation. Without
  that authority, retain candidates and evidence maps only; do not mutate the
  live issue tracker.
- A complete result, an incomplete result, a failure, an unsupported route,
  and an unavailable reference are different outcomes. An empty report after
  a crash, timeout, parser failure, or query failure is never a clean
  negative. Hooray exit codes: `0` success, `1` policy denial (findings are
  still emitted — a valid scan result), `2` operational failure (never a
  clean scan).
- Keep all output English, except source snippets, commands, diagnostics, and
  tool output, which remain byte-for-byte as observed. Redact credentials,
  private paths, and secrets as `<REDACTED>` before a public issue or durable
  handoff. Never paste a real secret value found by a scan into an issue;
  cite rule, file, line, and the SHA-256 fingerprint from its evidence only.
- Suspected security vulnerabilities use the repository's private reporting
  path in [`SECURITY.md`](../../../SECURITY.md). Never infer a vulnerability
  from a rule name, a scanner hit, scan silence, or a count.

## Bounded project matrix

This is the campaign's explicit, repeatable starting matrix. The repositories
are examples of stable public surfaces, not a promise that their current heads
are suitable. Every row requires a new immutable commit pin at invocation
time; the placeholder is intentional and must be replaced in the source
manifest before checkout. The manifest MUST verify the declared
lockfile/manifest actually exists at the pinned commit; if absent, retain the
row as `unsupported: no applicable input` — never substitute another project
silently.

| Ecosystem | Public repository | Required source pin | Hooray input route | Reference runners |
| --- | --- | --- | --- | --- |
| npm | `axios/axios` | `<immutable commit resolved at run start>` | `scan project` on checkout; verify `package-lock.json` present | Trivy fs, Grype dir, OSV-Scanner, `jf audit` (Xray) |
| pnpm | `colinhacks/zod` | `<pin>` | `scan project`; verify `pnpm-lock.yaml` present | Trivy fs, Grype, OSV-Scanner, Xray |
| yarn | `yarnpkg/berry` | `<pin>` | `scan project`; verify `yarn.lock` and release format (classic vs berry) | Trivy fs, Grype, OSV-Scanner, Xray |
| Python | `psf/requests` | `<pin>` | `scan project`; verify `requirements*.txt`/`Pipfile.lock`/poetry lock actually committed | Trivy fs, Grype, OSV-Scanner, Xray |
| Go | `spf13/cobra` | `<pin>` | `scan project`; `go.mod`/`go.sum` | Trivy fs, Grype, OSV-Scanner, Xray |
| Rust | `BurntSushi/ripgrep` | `<pin>` | `scan project`; `Cargo.lock` | Trivy fs, Grype, OSV-Scanner, Xray |
| NuGet | `DapperLib/Dapper` | `<pin>` | `scan project`; verify `packages.lock.json`/`packages.config` presence | Trivy fs, Grype, OSV-Scanner, Xray |
| Ruby | `ruby/rake` | `<pin>` | `scan project`; verify `Gemfile.lock` committed | Trivy fs, Grype, OSV-Scanner |
| PHP | `composer/composer` | `<pin>` | `scan project`; `composer.lock` | Trivy fs, Grype, OSV-Scanner |
| Swift | `apple/swift-argument-parser` | `<pin>` | `scan project`; verify `Package.resolved` committed | Trivy fs, Grype |
| Dart | `dart-lang/http` | `<pin>` | `scan project`; verify `pubspec.lock` committed | Trivy fs, Grype |
| Helm | `helm/helm` | `<pin>` | `scan project`; verify `Chart.yaml`/`Chart.lock` inputs | Trivy fs (config), Checkov |
| SBOM | `CycloneDX/bom-examples` | `<pin>` | `scan sbom` / `scan auto` on selected CycloneDX and SPDX 2.x documents | Syft/Grype on the same SBOM; record document digest |
| OCI image | `ghcr.io/openhoo/hooray@sha256:<digest>` or `docker.io/library/redis@sha256:<digest>` | `<immutable digest>` | `scan container` / `scan artifact` on exported image tar | Trivy image, Grype image, Xray |
| Secrets/SAST/IaC | `gitleaks/gitleaks` | `<pin>` | `scan project`; committed testdata exercises secret rules; `.go` exercises SAST; service configs exercise IaC | Gitleaks (secrets), CodeQL or SonarQube (SAST), Checkov (IaC) |

The matrix is intentionally finite, but source availability, lockfile
presence, and runner support are not assumed. If a row or runner cannot be
used, retain the row with `unsupported`, `failed`, or `unverified` status and
an exact reason. Never silently substitute another project or call a
different scanner's output equivalent.

## Reference runner contract

Hooray surfaces and their reference oracles are separate contracts; never
merge them:

| Hooray surface | Reference runners | What to record |
| --- | --- | --- |
| Dependency inventory + OSV vulnerabilities | `jf audit` (Xray; feeds the `hooray-parity` record-replay harness), Trivy (`trivy fs`/`trivy image`), Grype, OSV-Scanner | CLI/image identity and version, vulnerability DB snapshot date, exact command, scope, exit status, raw output digest |
| Secrets (`secret.*` rules) | Gitleaks, TruffleHog | Version, config/ruleset identity, command, exit status, finding count and digest; never record secret bytes |
| SAST (`sast.*` rules: rs, js/jsx/ts/tsx, py, go, java, cs) | CodeQL CLI (database plus `code-scanning`/`security-and-quality` suites), SonarQube CE scanner | CodeQL CLI/bundle identity, extractor, database status, suite paths, per-query state, SARIF digest; Sonar server/scanner/profile/active-rule digest |
| IaC (`iac.*` rules: nginx, apache, pg_hba, postgres, redis, sshd) | Checkov, KICS | Version, framework selection, command, exit status, output digest |
| License detection | ScanCode toolkit | Version, command, license output digest |
| SBOM generation | Syft | Version, command, output digest |

Every reference run records: tool identity (binary SHA-256 or pinned image
digest), version, DB/ruleset snapshot identity, exact command, environment
allowlist, scope, start/end, exit code, and raw-output digest. A reference
outage, missing DB, failed extraction, or unavailable licensed analyzer is an
explicit non-pass; keep its expected denominator and never replace it with
zero.

Advisory-source differences are expected: Hooray queries OSV only;
Trivy/Grype/Xray use their own databases. A CVE present in a reference but
absent from OSV (or vice versa) is `reference_different`/`unverified`, not a
native defect, unless a common source proves Hooray mishandled data it
actually received.

## Identity, checkout, and source manifest

At campaign start allocate two caller-owned paths:

- `CAMPAIGN_ROOT`: disposable per-run work area, chosen by the caller rather
  than assumed by this skill; and
- `PERSISTENT_EVIDENCE_ROOT`: durable storage outside any disposable scratch
  path, including `/tmp`, where redacted evidence and cleanup proof survive.

Refuse to proceed if either path is ambiguous, shared with another campaign,
or contains credentials that the campaign does not own. Keep the working
checkout and source clones below `CAMPAIGN_ROOT`; copy only redacted, hashed
proof to the persistent root before cleanup.

Create one `source-manifest.json` per project before analysis. It must
include at least:

- repository URL, resolved commit, checkout tree/object identity, clone
  method, checkout status, license/notice location, and source-archive digest
  if used;
- analysis root, exact included roots/files, path normalization,
  test/generated/vendor policy, exclusions, and the manifest's own digest;
- every selected input file's normalized relative path, byte length, SHA-256,
  detected input kind (lockfile/manifest/SBOM/archive/config/source), and
  classification;
- native source revision, toolchain identity, executable path and SHA-256,
  command, format, options, limits, exit code, and report digest; and
- reference identities, DB snapshots, exact commands, environment allowlist,
  raw-output digests, and status for every attempted cell.

Use detached checkouts and `git status --porcelain`/tree identity checks
before and after scans. Do not mutate lockfiles, generated sources, package
manifests, or line endings. Preserve exact source snippets and immutable
GitHub links at `<repository>/blob/<commit>/<path>#L<start>-L<end>`; the link
must resolve to the recorded commit, not a moving branch.

### Native identity is not a release identity

Build or select the unchanged-source native executable in an isolated
worktree. Record the source commit, worktree status, Rust/toolchain identity,
executable SHA-256, `--version` output, build command, and build result as a
`native_build` identity. If the source was dirty, the executable was copied
from an unknown build, or the command cannot be reproduced, mark native
provenance `unverified`; do not infer it from a release label.

A downloaded release asset or `ghcr.io/openhoo/hooray` image is a separate
`release_asset` identity: record its official URL, asset name,
checksum/signature/attestation evidence, version, OCI labels
(`org.opencontainers.image.version`, `.revision`, `.source`, `.licenses`),
and downloaded bytes' SHA-256. Use the release binary only when the campaign
explicitly requests a release comparison. Never label a local source build as
a release asset, or use a release checksum as the source-build identity.

## Existing repository oracle patterns

Reuse Hooray's current normalization and fail-closed patterns; inspect their
schemas and flags at run time:

- `src/parity/` (`xray.rs`, `normalize.rs`, `compare.rs`, `recording.rs`,
  `corpus.rs`) — canonical report model, Xray normalization, scorecard, and
  record-replay;
- `src/bin/hooray-parity.rs` — `scan-case`, `normalize-xray`, `record`, and
  `check` subcommands behind the `parity` feature;
- `tests/parity_harness.rs` — tier-1 corpus/normalization and tier-2
  scorecard/drift gates;
- `tests/fixtures/parity/` — corpus manifest, minimal policy, and recordings
  directory;
- `tests/ingest_robustness.rs` — malformed-input fail-closed contract;
- `benches/performance.rs` — benchmark harness.

When a campaign case is worth keeping, prefer feeding it into the parity
corpus (`tests/fixtures/parity/corpus/<case>` plus a manifest row plus a
`hooray-parity record` output under `recordings/`) over ad-hoc JSON dumps;
that makes the evidence replayable in CI. Keep SCA, secrets, SAST, IaC,
license, and report-format results as distinct contracts.

## Bounded execution

### 1. Prepare one immutable slice

For each matrix row, record a slice owner and a unique case key. Clone or
checkout the exact source pin into its isolated directory. Generate the
source manifest and a redacted `commands.json` before running anything.
Verify that all roots passed to native and reference scanners resolve to the
same manifest scope; if a runner requires a different physical root, record
the deliberate mapping and compare only normalized manifest-relative paths.

Run the full project scope first. A per-file or partitioned run may be used
to localize a failure, but it is a `partial_isolation` supplemental result
and cannot replace the full-project status, denominator, or finding
inventory.

### 2. Keep heavy scanners bounded and serialized

Declare limits in the campaign manifest before execution: per-run wall time,
CPU time, address space/RAM, worker count, output size, and retained-source
byte budget. Put CodeQL database creation, SonarQube scans, container image
pulls/exports, and other heavy scanners behind one caller-owned `flock` lock.
Independent project slices may prepare manifests and run lightweight native
work concurrently, but they acquire the shared lock for heavy phases and
release it on timeout or signal.

Use read-only source mounts where possible and unique working/database/
output folders. Capture the command, limits, start/end times, PID/process
group, stdout, stderr, exit code, signal, timeout, and report hash. Do not
retry a failed heavy scan until it becomes a pass, silently increase limits,
or delete an incomplete report.

If a full project crashes (including a stack overflow or abort), preserve the
original signal, stderr, core/diagnostic metadata when safe, and incomplete
scope. Do not raise limits, split the source, or use another workaround and
count that result as a full-project success. A bounded partition can identify
the triggering input only as supplemental `partial_isolation`; the original
full-project crash remains actionable failure evidence.

### 3. Run native routes separately

For every applicable input kind, run the native scan as distinct invocations
and artifacts:

```text
hooray scan project <checkout> --policy <policy> --format json --output <file>
hooray scan sbom <document> --format json --output <file>
hooray scan artifact <archive> --format json --output <file>
hooray scan container <image-tar-or-layout> --format json --output <file>
hooray scan auto <input> --format sarif --output <file>
```

Use the actual CLI syntax shown by the current binary; the placeholders are
not shell commands. Offline mode is `HOORAY_OFFLINE=true` or config
`offline: true` (the `hooray-parity` binary's `--offline` flag is separate).
An offline run produces no vulnerability findings by contract; never count
that as zero-CVE evidence. Record `unsupported` when an input kind is outside
the contract, `failed` for exit 2/crash/timeout, `denied` for exit 1 with its
findings retained, and `complete` only after validating the report and scope.
Preserve all findings, inventory, diagnostics, and policy decisions.

For Xray comparison, capture `jf audit --format json --licenses` and
`jf audit --format cyclonedx` on the same scope, then `hooray-parity record`
both sides into a recording; `hooray-parity check` enforces corpus
expectations and scorecard gates.

### 4. Run reference scanners on every applicable row

Run each applicable reference scanner against the same source manifest scope.
Keep raw output, pagination completeness, DB snapshot identity, and exit
status. If a matching Hooray surface does not exist, still retain the
reference observation as reference-only/unverified and say why; do not call
the absence a native bug.

## Comparison and semantic review

### Complete per-surface union/difference inventory

After all runner results exist, create a full inventory, not a headline
count. For each project, surface, and finding retain:

- native and reference presence, multiplicity, and complete finding identity:
  - SCA: purl + advisory ID + introduced/fixed versions;
  - secrets: rule ID + file + line + SHA-256 fingerprint (never the secret);
  - SAST/IaC: rule ID + file + primary range + message;
  - license: purl/file + SPDX expression;
- the source commit/tree, native executable identity, reference identity, DB
  snapshot, options, and completeness status; and
- a disposition such as `exact_identity`, `native_only`, `reference_only`,
  `reference_different`, `unsupported`, `failed`, `incomplete`, or
  `unverified`, with the preserved raw record and reason.

Use a multiset of complete finding identity, not just rule presence or
totals. Counts can prioritize review but never establish parity. Keep SCA,
secrets, SAST, IaC, and license results as separate surfaces. Do not map
CodeQL query IDs or Trivy rule names to Hooray rule IDs by name, infer
implementation from a docs URL, or call a native empty result a security
pass. Reference false positives, DB coverage differences, and reference-only
behavior remain `reference_different`, `unverified`, or rejected dispositions
unless an independent native contract and control prove a native defect.

### Source-semantic and executable counterexamples

For each high-signal discrepancy or crash candidate:

1. Read the rule implementation (`src/scanners/`), parser (`src/parsers/`),
   or input path (`src/input.rs`), documentation, and callers. Confirm the
   detector is actually registered for the input kind. A README capability
   row is not detector evidence.
2. Link the exact real-project source span at its immutable commit, preserve
   the exact snippet/command/output, and explain the expected semantics
   without rewriting the original. Keep source and diagnostics unchanged in
   evidence.
3. Make a smallest bounded counterexample that preserves the triggering
   input and a clean or near-miss control. Run the native CLI and, when
   applicable, the reference scanner on the same declared scope. Do not call
   a reference-only result a native defect.
4. Where behavior depends on a registry response, OSV data, or archive/image
   structure, capture the actual response bytes (digest-recorded) or build a
   minimal fixture; a plausible-looking input alone is not proof.

Use the smallest supported conclusion:

- `Bug` only for a reproducible violation of an existing native contract,
  including a confirmed false positive, false negative, regression, crash, or
  fail-open parse.
- `Coverage request` only when the desired behavior is justified and the
  current parsers/scanners lack it. Group related future surface requests by
  a coherent ecosystem/rule boundary, retaining every occurrence.
- `Enhancement` or `Documentation` only for a concrete requested behavior or
  documentation contract, not to disguise a scanner mismatch.
- `needs-info`/`needs-triage` for missing evidence, unresolved semantics,
  unavailable reference/context, or unsupported claims. A reference/native
  mismatch alone is rejected or recorded as `reference_different`, not filed
  as a bug.

Keep speculative candidates in `candidate-inventory.json` with their evidence
and rejection reason. Do not create bogus tickets for scan silence, metadata,
counts, unsupported input routes, or unverified security concerns.

## Deduplication and publication

Before creating or changing any issue, query the live repository and read the
complete record for every possible root match: body, every comment and event,
linked pull requests, current labels, and current state. Search by root
cause, rule IDs, distinctive symptom, source path, and linked evidence rather
than title alone. An existing issue owns all occurrences of the same root;
append evidence only when authorized and preserve its public discussion.

A closed issue is reopened only when current pinned evidence demonstrates a
regression against the prior resolved behavior. Preserve the old resolution,
show the comparable source/input/context, and run the immediate triage flow
again. Do not duplicate an open issue or reinterpret a closed issue merely
because a reference scanner changed.

### Canonical issue body

For every confirmed actionable defect or justified grouped future coverage
request, render the current repository issue form at
[`.github/ISSUE_TEMPLATE/issue.yml`](../../../.github/ISSUE_TEMPLATE/issue.yml)
and use its actual field IDs and descriptions. Before creating, updating, or
reopening an issue, and again after its live API readback, run the canonical
`validateIssueBody` check documented by
[`skill://triage`](../triage/SKILL.md) against the rendered body and actual
field values. Validate the form contract, not merely a count of headings; do
not implement a duplicate validator. The rendered English body must contain
exactly these top-level headings, in this order:

1. `### Summary`
2. `### Classification`
3. `### Version and provenance`
4. `### Reproduction`
5. `### Expected and actual behavior`
6. `### Evidence and scope`
7. `### Acceptance criteria`

Populate the form's `summary`, `classification`, `version-and-provenance`,
`reproduction`, `expected-and-actual-behavior`, `evidence-and-scope`, and
`acceptance-criteria` fields; do not invent a parallel schema or leave a
required field blank. The `classification` field's entire value must be one
plain choice—exactly `Bug`, `Coverage request`, `Enhancement`, or
`Documentation`—with no Markdown, rationale, labels, or state appended; put
rationale in the other fields and state in labels. Preserve exact fenced
snippets, commands, numbers, output, source hashes, and immutable links. Do
not publish temporary `/tmp` paths as the only proof.

Classification is exactly one of `Bug`, `Coverage request`, `Enhancement`, or
`Documentation`. Use the live `.github/labels.json` manifest at invocation,
and apply exactly one category and one state:

- `Bug` -> `bug`; `Coverage request` -> `enhancement` plus `coverage`;
  `Enhancement` -> `enhancement`; `Documentation` -> `enhancement` plus
  `documentation`.
- State is exactly one of `needs-triage`, `needs-info`, `ready-for-agent`, or
  explicitly authorized `wontfix`. Keep unsupported, incomplete, and
  unverified cases in the appropriate state with the precise missing fact.
- Add only evidence-based symptom labels (`false-positive`, `false-negative`,
  `regression`, `crash`). Add ecosystem, area, and priority only when
  justified, using the canonical prefixed names `ecosystem:npm`,
  `ecosystem:pypi`, `ecosystem:go`, `ecosystem:cargo`, `ecosystem:nuget`,
  `ecosystem:rubygems`, `ecosystem:php`, `ecosystem:other`, `area:sca`,
  `area:secrets`, `area:sast`, `area:iac`, `area:license`, `area:reports`,
  `area:policy`, `area:monitor`, `area:ci`, and `priority:critical`,
  `priority:high`, `priority:normal`, or `priority:low`.
- Preserve unrelated existing labels. Never create bare ecosystem/area/
  priority aliases, `ready-for-human`, `human-review`, or another queue
  label. Never close an issue as part of exploration.

### Immediate triage is part of publication

Do not accumulate an untriaged publication backlog. After each create or
reopen, in the same bounded work item:

1. Read the live body, comments, labels, timeline, and linked PR context
   again.
2. Invoke [`skill://triage`](../triage/SKILL.md) for that exact issue. The
   campaign authorization includes the durable public triage brief and the
   evidence-based label/state synchronization, but never source edits, fixes,
   closure, or release. Triage must not repeat a question already answered by
   the body or comments.
3. Post at most one idempotent comment containing the marker
   `<!-- hooray:triage-brief:v1 -->` and a durable brief with behavior,
   invariants, acceptance criteria, non-goals, exact evidence/reproduction,
   risks, and blockers. A `ready-for-agent` brief requires decisive confirmed
   behavior, concrete acceptance, and no unresolved semantic or dependency
   decision; it is not awarded for a native/reference mismatch alone.
4. Apply the corrected category/state/supplemental labels, then perform a
   live API readback of body, labels, and comments. If triage or readback
   fails, stop before publishing another item and retry or record the exact
   blocked state; do not leave a silent backlog or duplicate the marker
   comment.

Record each publication in a durable `publication-map.json` with issue
number, URL, root ID, classification, final state, exact labels, brief
comment URL, source/project evidence digests, dedup decision, and readback
timestamp. Keep reopened regressions, grouped coverage requests, rejected
candidates, and unverified records distinguishable. The map is an evidence
index, not a replacement for the issue's public discussion.

## Completion and cleanup contract

A campaign is complete only when every matrix row has a source manifest and a
recorded result for every applicable native and reference cell; every
failure, unsupported route, incomplete denominator, crash, context limit, and
reference-unverified state is retained; the full per-surface union/difference
inventory is written; and every candidate is either:

- published or reopened with the canonical seven-heading body and immediately
  triaged with a durable brief;
- grouped into a justified future coverage request and handled by that same
  publication/triage flow; or
- retained as a speculative/rejected/unverified candidate with exact evidence
  and a reason not to publish.

Before removing any owned checkout, container, database, server, process, or
credential:

1. Copy redacted manifests, raw-output hashes, normalized inventories,
   publication maps, issue API readbacks, and a `cleanup.json` to
   `PERSISTENT_EVIDENCE_ROOT` outside `/tmp` and other disposable paths. Keep
   crash logs and incomplete reports; do not replace them with summaries.
2. Revoke campaign-created tokens/credentials through their owning service
   while that service is still available; verify revocation, remove owned
   token files, check restrictive permissions, and record proof without
   retaining secret bytes. Search redacted artifacts for accidental
   credential material before stopping the service.
3. Stop only campaign-owned process groups and containers, wait for exit, and
   record each PID/container identity, signal, exit result, and timestamp.
   Do not kill an unverified process or delete another campaign's work.
4. Remove only disposable paths owned by this campaign after proof is copied.
   If a process, credential, or artifact cannot be cleaned safely, mark
   cleanup blocked and disclose the exact owned resource and residual risk
   rather than claiming completion.

Do not report success from a green native build, a reference count, a partial
slice, a release label, or a passing test-only fixture. The final campaign
record must name the native and release identities separately, preserve scope
and denominator limits, and link the next explicit authorization boundary.
