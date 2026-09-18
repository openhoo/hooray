---
name: triage
description: 'Evidence-bound Hooray issue triage: read complete reports, check scanner contracts and redundancy, classify and state tickets, and write durable agent briefs without implementing fixes.'
version: 1.0.0
disable-model-invocation: true
---

# Hooray issue triage

This repository-tracked skill is an independent Hooray workflow. It is
inspired by the workflow ideas in [Matt Pocock's triage skill](https://github.com/mattpocock/skills/blob/main/skills/engineering/triage/SKILL.md),
but it does not copy that skill, require its companion files, or assume any
global installation. The repository's scanner contracts, evidence formats,
and intake form always take precedence.

## Invocation and safety defaults

OMP discovers this file from `.agents/skills/triage/SKILL.md`. Invoke it with
`/skill:triage` when skill commands are enabled. In prose, `/triage #92` means
"triage issue 92"; it is request notation, not a separate OMP slash command.
A campaign request may use the same notation, for example
`/triage campaign batch for reports created before 2026-09-12T12:00Z`.

Triage is read-only by default. First gather evidence and present a proposed
classification, state, labels, questions, and brief. Do not edit source or
implement a fix. A user request to migrate or create-and-triage a bounded
issue may authorize only the scoped issue body, public brief, category/state,
and label writes named in that request; it never authorizes source fixes,
closure, or a public security report. Otherwise do not post comments or mutate
labels. Preview authorized changes before applying them and report the UTC
snapshot cutoff. Other agents may publish issues after the cutoff, so tell the
integrator which later items require a final catch-up.

After the required post-publication assessment below, do not repeat triage for
an issue already in `ready-for-agent` unless there is new reporter activity,
new evidence, or an explicit re-triage request. Never make an issue ready
merely because it is old, easy to describe, or found in a batch.

Every campaign-published issue requires an immediate read-only readiness
assessment after publication. The campaign author may perform this assessment;
same-author ownership is not a reason to skip it. Read the final public body,
any publication comments, and linked evidence, then report whether the
existing state and brief satisfy this skill. If the same publication or
migration request explicitly authorizes a scoped body/brief and category/state
label synchronization, perform those writes after the assessment; otherwise
keep them as recommendations. The assessment itself never makes an issue
ready.
For an explicitly authorized campaign publication, complete the same bounded
handoff without asking the caller to re-authorize each step: reread the live
body, comments, labels, timeline, and linked PR context; post at most one
idempotent comment marked `<!-- hooray:triage-brief:v1 -->` beginning with
the AI disclaimer and carrying the durable brief; then apply the corrected
category, state, and evidence-based supplemental labels and read back the live
body, labels, and comments. If triage or readback fails, stop and record the
exact blocker; never leave a silent backlog or duplicate the marker comment.


## Intake contract

Use the canonical [issue form](../../../.github/ISSUE_TEMPLATE/issue.yml) and
[labels manifest](../../../.github/labels.json). Blank issues are disabled. A
new issue created through the web form, CLI, API, or another agent must render
these headings in this order, with these exact names:

1. `Summary`
2. `Classification`
3. `Version and provenance`
4. `Reproduction`
5. `Expected and actual behavior`
6. `Evidence and scope`
7. `Acceptance criteria`

Use this canonical-field checklist for web forms, `gh`/CLI commands, and API
payloads; each surface maps to the same field name rather than inventing an
alias:

| Field | Required evidence |
| --- | --- |
| `Summary` | One observable problem or request and its affected rule, command, export, metric, or documentation. |
| `Classification` | Exactly one of the four form choices. |
| `Version and provenance` | Source commit/pin, native binary or version identity, reference image/version when used, OS, and toolchain/runtime versions. |
| `Reproduction` | Exact input and scope, command, configuration, profile and format, compiler context, exit status, and bounded limits. |
| `Expected and actual behavior` | Finding rule/file/message and complete primary range, diagnostics/output, and the clean or refusal control where relevant. |
| `Evidence and scope` | Artifact links and hashes, source/test/generated/vendor scope, completeness, source/profile/range equality, and safe security-report routing. |
| `Acceptance criteria` | Observable behavior, compatibility, proof controls, and bounded non-goals; never a source-only implementation assertion. |

The `Classification` section's entire trimmed value must be exactly one plain
choice: `Bug`, `Coverage request`, `Enhancement`, or `Documentation`. Do not
put rationale, markdown emphasis, metadata, state, or labels in that value;
put those details in the other sections or the triage brief. `gh`/CLI, API,
and agent creation cannot be blocked by this form contract: default-branch
intake should flag missing or malformed sections while preserving the
maintainer's state, and form completeness does not certify semantic truth.
Before any `gh`/CLI/API create or update, save the proposed body and run this
validator; run it again on the body read back from the live issue. A nonzero
exit or error stops the operation; do not substitute heading-count checks:

```sh
node -e 'const fs=require("node:fs");const m=require("./.github/scripts/issue-intake.cjs");const r=m.validateIssueBody(fs.readFileSync(process.argv[1],"utf8"));if(!r.valid){console.error(JSON.stringify(r,null,2));process.exit(1)}' body.md
```

Keep legacy campaign issues as evidence unless the user explicitly asks for a
targeted correction. All public issue text and comments written during this
workflow are English.

When an authorized AI-generated issue or comment is posted publicly, begin it
with this disclaimer before the canonical headings or note:

> *This was generated by AI during triage.*

Do not post it automatically; the mutation authorization above still applies.

Never put suspected vulnerability details in a public issue. Follow the
repository's [private security policy](../../../SECURITY.md) and use GitHub
private vulnerability reporting instead. Do not infer a vulnerability from a
rule name, a rule definition, a static pattern, or a reporter's concern.

## Canonical taxonomy

After triage, propose or apply exactly one category and exactly one state. Keep
unrelated existing labels, including historical `duplicate`, `invalid`, and
`question`; those labels are not silently deleted or used as substitutes for
the canonical state.

### Category

The issue-form choice maps to one category label as follows:

| Form classification | Category | Optional supplemental label |
| --- | --- | --- |
| `Bug` | `bug` | evidence-based `false-positive`, `false-negative`, `regression`, or `crash` |
| `Coverage request` | `enhancement` | `coverage` |
| `Enhancement` | `enhancement` | none unless separately established |
| `Documentation` | `enhancement` | `documentation` |

Never apply both `bug` and `enhancement`. A false positive (a finding on a
clean control) and a false negative (a missed finding on a violating control)
are both bugs; do not call either a coverage request merely because the rule
is difficult to reproduce. `regression` requires a known-good and bad result
under a comparable setup. `crash` requires observed evidence, not a severity
guess.

Optional labels are evidence-driven and may include the exact ecosystem
(`ecosystem:npm`, `ecosystem:pypi`, `ecosystem:go`, `ecosystem:cargo`,
`ecosystem:nuget`, `ecosystem:rubygems`, `ecosystem:php`, or
`ecosystem:other`), area (`area:sca`, `area:secrets`, `area:sast`,
`area:iac`, `area:license`, `area:reports`, `area:policy`, `area:monitor`,
or `area:ci`), and priority (`priority:critical`, `priority:high`,
`priority:normal`, or `priority:low`). Do not invent a priority or infer
severity from a title. Use the manifest as the source of truth for spelling.

### State

The only canonical state labels are:

- `needs-triage`: evidence and scope have not yet been assessed.
- `needs-info`: one or more specific reporter facts are required; list the
  questions in the issue text.
- `ready-for-agent`: the behavior, scope, evidence, acceptance criteria, and
  risks are sufficiently bounded for the next implementation skill.
- `wontfix`: an explicitly authorized resolution, with a reason recorded in
  the issue.

Never auto-ready an issue. Never set `wontfix` or close an issue without an
explicit authorization. Do not create substitute states for judgment,
external access, or other blockers; explain those blockers in the issue text.
An open triaged issue has exactly one of the four states above, while
supplemental labels remain independent.

## Bounded triage procedure

### 1. Establish the work boundary

For a single issue, record its number, URL, author, timestamps, current
labels, and the repository revision being inspected. For a campaign, record
the query, inclusion/exclusion rules, UTC snapshot cutoff, and the list of
items seen. Do not silently include issues created after the cutoff.

Read the complete issue body and every relevant comment, including previous
triage notes, bot evidence, and linked issue references. Read each linked PR's
complete body, comments, diff, status, and relevant artifacts when the issue
relies on it. Do not re-ask a question that the reporter already answered.
Acknowledge a reporter's observation as an observation; do not rerun a command
solely to dispute it. Run a bounded reproducer only when a missing triage fact
requires it, and record the exact command, input, exit status, output identity,
and limits.

### 2. Check redundancy and the current contract

Search for the requested behavior by domain concept, not only by the issue's
wording. Inspect the relevant rule file, explicit executable registry,
profile/dispatch path, tests and fixtures, documentation, and all meaningful
callers. Record exact repository paths and line ranges for the contract and
for any existing implementation. An apparently similar catalog row or help
page is not an implementation.

Compare related open and closed issues and linked PRs. If the behavior already
exists, distinguish "already implemented" from "not reproduced" and explain
which source path and caller prove that conclusion. Do not close or relabel
without the authorization required above.

### 3. Use authoritative scanner evidence

For a detector or coverage claim, use the executable rule tables and a
bounded scan run. README capability lists and documentation describe intent,
not detector evidence. Check `src/scanners/mod.rs` (secret rules),
`src/scanners/sast.rs` (SAST rule table), `src/scanners/service_config.rs`
(IaC rules), `src/parsers/` (lockfile/manifest support), and an actual
`hooray scan` CLI run. Documented capabilities and runtime coverage are
separate contracts.

When comparing a report with a reference or a prior run, preserve equality of:

- source commit and binary identity;
- analysis roots, source/test/generated/vendor scope, exclusions, and file set;
- profile, format, rule selection, configuration, and project/compiler context;
- language/runtime/tool versions and relevant snapshots; and
- finding identity: rule key, file, message, and complete primary range.

A failed, timed-out, malformed, or incomplete scan is not a clean negative.
Exit `2`, missing compiler/helper/runtime facts, unavailable reference data,
and empty output after a failed run must remain incomplete or unverified, not
"no finding" evidence. Record the failure and its scope instead of filling in
zeros or claiming parity.

For a proposed automatic fix, require a compiler/runtime or executable
control where the behavior depends on one. Compare behavior, diagnostics,
output, and exit status before and after; use both a positive application and
a clean/refusal control. A target finding disappearing alone is not proof when
an independent regression appears. Triage may request these controls but does
not implement the fix.

### 4. Classify honestly

Use the smallest supported conclusion:

- **Bug:** shipped behavior violates a documented contract or a reproducible
  expected behavior. Add `false-positive`, `false-negative`, or `regression`
  only when the corresponding control proves it.
- **Coverage request:** a desired detector or supported behavior is not in the
  executable rule tables, and no existing contract promises it. Add
  `coverage` after checking the actual rule tables, not merely documentation.
- **Enhancement:** a new or changed behavior that is not a defect in an
  existing contract.
- **Documentation:** documentation is wrong or missing; map it to the
  `enhancement` category and add `documentation`.
- **Unsupported:** the requested language, format, profile, semantic context,
  or trust boundary is outside the current contract. Explain the boundary;
  do not call it a false negative.
- **Unverified:** evidence is unavailable, failed, or insufficient to decide.
  Ask precise questions or retain `needs-triage`; do not manufacture a bug,
  severity, vulnerability, or clean result.

Security concerns use the private reporting path even when the public issue
would otherwise look like a bug or coverage request.

### 5. Recommend, then mutate only when authorized

The default result is a read-only recommendation. State the proposed category,
state, supplemental labels, evidence, unresolved questions, and why. If a
user explicitly requests label changes, apply only the requested canonical
changes after showing the before/after label set; preserve unrelated labels
and report any conflict such as multiple existing states. If the user has not
authorized a public comment, do not post one.

A `needs-info` request must ask specific, actionable questions such as the
exact binary/source revision, input file, command and profile, expected
finding/range, compiler or runtime version, or a minimal clean control. Do not
write "please provide more information" without saying which fact is missing
and why it changes the decision.

## Durable handoff brief

When recommending `ready-for-agent`, write a brief that another repository
agent can use without reconstructing the entire investigation. Keep transient
reproduction evidence separate from durable implementation requirements:

```markdown
## Agent brief

**Behavior and contract:**
- ...

**Invariants:**
- ...

**Acceptance criteria:**
- ...

**Non-goals:**
- ...

**Evidence and exact reproduction:**
- Source contract: `path/to/file.rs:line-line` at commit `...`.
- Reproduction input/command, profile, scope, runtime, exit status, and report hash: ...
- Known controls, failed or incomplete runs, and their limits: ...

**Risks and blockers:**
- ...
```

Path/line locations and command output describe the observed revision; they do
not silently become implementation requirements. Acceptance criteria must say
what a consumer can observe, while non-goals prevent scope creep. Keep
unverified assumptions, unavailable external services, and failed scans in
risks/blockers rather than hiding them behind a ready state.

The next workflow is [the fix-issue skill](skill://fix-issue) for one selected
ready ticket, followed by [the work-issues skill](skill://work-issues) for a
bounded ready backlog. Triage itself never implements the change and never
turns a recommendation into an automatic fix.

## Compact output checklist

Before finishing a triage pass, confirm:

- full body, comments, linked PR context, and prior notes were read;
- redundancy and prior decisions were checked against current source and
  callers;
- reporter observations were not rerun merely to dispute them;
- classification and state are each singular and evidence-based;
- exact source commit, scope, profile, runtime, range, and completeness limits
  are recorded for scanner claims;
- rule definitions were not mistaken for executable coverage;
- no failed scan was presented as clean and no vulnerability was inferred;
- the brief separates observed reproduction from durable requirements;
- changes are read-only unless specifically authorized; and
- campaign snapshot cutoff and later-item catch-up responsibility are clear.
