# Policies, history, reports, and CI

## Strict policy

Hooray policies use version 1 YAML/TOML and reject unknown fields. This minimal
example denies critical findings while leaving others visible as warnings:

```yaml
version: 1
default_outcome: warn
rules:
  - id: deny-critical
    priority: 100
    outcome: deny
    reason: Critical findings block release
    selectors:
      minimum_severity: critical
```

```bash
hooray policy validate hooray-policy.yaml
hooray scan project . --policy hooray-policy.yaml --format json --output report.json
```

Rules sort by descending priority then ID; default outcome applies if none
match. `fail_closed.unknown_applicability` and `unknown_licenses` are available
when those unknowns should block. Exceptions have ID, owner, reason, ticket,
RFC3339 expiry, and at least one exact selector; selector globs are forbidden.
Overriding fail-closed denial needs its exact fail-closed policy ID. Never invent
an approval owner/ticket or silently disable fail-closed behavior.

## Comparable history

Use actual run IDs from this store, not literal placeholder values:

```bash
hooray history list --limit 50 --format json
hooray history show 'run:UUID' --format json
hooray history diff 'run:PREVIOUS' 'run:CURRENT' --format json
hooray inventory --run-id 'run:UUID' --format json
hooray report 'run:UUID' --format html --output hooray-report.html
```

`scan project . --baseline 'run:UUID' --new-findings-only --format table` focuses
review on new findings. Keep the full report and disclose the baseline/filter;
a filtered result is not proof that all existing findings were repaired.

## Reports and CI

Hooray's GitLab Code Quality format is `gitlab-code-quality`. Hoolicy uses a
different spelling. Supported full-report formats include JSON/YAML/table,
SARIF, JUnit, HTML, CycloneDX-VEX, SPDX, CSV, and JSON-lines. Inventory/history/
standalone policy evaluation support JSON/YAML only.

The `gitlab-artifacts` format creates an atomic directory bundle on Linux/
Android only; the destination parent must exist and destination must not.
Do not call an unsupported platform/output result a successful scan.

Use the release-verified scan action or a generated integration, review the
resulting workflow, and preserve scanner exit status while uploading reports.
An upload success does not imply policy success. Generated integration files
are produced with `hooray integrations generate github-actions|gitlab-ci|pre-commit`
and `--output FILE`; do not overwrite existing project pipelines without review.

Configuration fields use snake_case; known `HOORAY_` variables override them,
and unknown prefixed variables fail. Keep database/cache paths and authentication
outside committed fixtures. API serving and recurring monitoring are separate
requested operations, not prerequisites for a one-off scan.
