# Hooray actions

Use immutable action revisions in consuming repositories. The scan action
requires Bash and Python 3 on Linux or macOS. The release installer supports Linux X64 runners;
`executable` allows another supported platform to use its own built binary.

```yaml
- uses: openhoo/hooray/actions/scan@<full-commit-sha>
  id: hooray
  with:
    version: 0.9.0
    policy: hooray-policy.yaml
    additional-formats: json,junit,html
```

`actions/setup` verifies the selected Linux X64 release archive and
`SHA256SUMS` against their published Sigstore bundles, pinned certificate
identity `https://github.com/openhoo/hooray/.github/workflows/release.yml@refs/heads/main`,
and OIDC issuer `https://token.actions.githubusercontent.com`, then checks the
installed binary version.

## Scan once and reuse the reports

`actions/scan` validates the required policy and scans the project with a new
isolated SQLite database. It writes SARIF by default. `additional-formats`
accepts a comma-separated list without spaces or duplicate entries; these
reports render the same persisted run, including its policy decisions, without
repeating scans or OSV queries. Supported additional formats are `json`, `yaml`,
`table`, `sarif`, `gitlab-sarif`, `junit`, `html`, `cyclonedx-vex`,
`gitlab-cyclonedx`, `spdx`, `gitlab-code-quality`, `json-lines`, `csv`,
`gitlab-artifacts`, and `markdown`. When explicitly requested, the Markdown
report is also appended to the job summary, with large details bounded to keep
the summary within GitHub's size limit.

The default installed release remains **0.9.0**. Its existing report formats,
policy outputs, and summary work with this action. `markdown` and the new
`integrations export` command require a supporting release or a binary built
from the source revision that introduced them. Repository tests can set
`executable: ./target/debug/hooray`; normal consumers can select a supporting
verified `version` after that release is available.

| Input | Default | Purpose |
| --- | --- | --- |
| `version` | `0.9.0` | Verified release to install. |
| `executable` | empty | Use a supplied binary instead of installation. |
| `working-directory` | `.` | Directory where Hooray runs. |
| `input` | `.` | Project to scan, relative to the working directory. |
| `config` | empty | Optional Hooray configuration file. |
| `policy` | `hooray-policy.yaml` | Required policy, validated before scanning. |
| `offline` | `false` | Disable OSV queries while retaining local analysis. |
| `format` | `sarif` | Primary report format. |
| `output` | `hooray.sarif` | Primary report path; empty prints the CLI report. |
| `additional-formats` | empty | Extra formats rendered from the same run. |
| `summary` | `true` | Append policy and finding counts to the job summary. |
| `fail-on-policy` | `true` | Fail on denied policy; `false` permits denial only. |

A primary file report replaces an existing regular file only after a completed
scan and valid run metadata. Symlink destinations and symlink ancestors are
rejected. A failed scan leaves an existing file untouched and keeps `report`
empty, so a later step can avoid uploading stale results. The `gitlab-artifacts`
format requires a nonempty path to a new directory and uses the CLI's atomic,
no-clobber bundle publication. Parent directories for `output` must exist.
Inputs reject leading option characters and newlines; report paths also reject
other control characters. CLI text remains visible with workflow command
processing suspended, preventing repository-controlled text from creating
GitHub annotations or commands.

## Outcomes and outputs

A successful scan exits `0`; a policy denial exits `1`; configuration, execution,
metadata, and report publication errors exit `2`. Set `fail-on-policy: false`
explicitly for advisory scans: a denied scan then exits `0` while
`policy-status: denied`, `scan-exit-code: 1`, and the denial counts remain
visible. Operational errors still exit `2`. An additional report failure also
fails the action and preserves references to reports already produced by the
current run.

| Output | Meaning |
| --- | --- |
| `report` | Configured primary report path, after current report publication. |
| `exit-code` | Effective action exit status (`0`, `1`, or `2`). |
| `scan-exit-code` | Original scanner status; empty if scanning never began. |
| `policy-status` | `passed`, `denied`, or `error`. |
| `run-id` | Validated persisted scan run identifier. |
| `database` | Isolated SQLite database path for reuse within the current job. |
| `allowed`, `warned`, `denied` | Policy decision counts from the persisted run. |
| `finding-count` | Number of findings in the persisted run. |
| `reports` | JSON object mapping formats to completed report paths. |
| `artifacts-directory` | Directory of completed additional reports. |

The database contains scan history and is an internal job resource. Upload the
report outputs for review; retain the database only if your workflow explicitly
needs that history. All report output references are absolute paths anchored to the action's
working directory, so later uploader steps resolve subproject reports correctly.
Additional reports live under the runner's temporary directory. Empty `output` keeps the primary CLI stdout behavior and still
provides policy, run, and additional-report outputs.

## GitHub code scanning and retained artifacts

Run upload steps even when policy denies, and condition them on a produced
report. Give the SARIF upload job `security-events: write` alongside the
workflow permissions it otherwise needs. Fork pull requests and repository
code-scanning availability may limit that permission; artifact upload remains
a separate workflow step. Pin the upload actions to reviewed full revisions.

```yaml
- uses: openhoo/hooray/actions/scan@<full-commit-sha>
  id: hooray
  with:
    policy: hooray-policy.yaml
    additional-formats: json,junit,html

- name: Upload Hooray SARIF
  if: ${{ always() && steps.hooray.outputs.report != '' }}
  uses: github/codeql-action/upload-sarif@<full-commit-sha>
  with:
    sarif_file: ${{ steps.hooray.outputs.report }}
    category: hooray

- name: Retain Hooray reports
  if: ${{ always() && steps.hooray.outputs.run-id != '' }}
  uses: actions/upload-artifact@<full-commit-sha>
  with:
    name: hooray-reports
    if-no-files-found: error
    path: |
      ${{ steps.hooray.outputs.report }}
      ${{ steps.hooray.outputs.artifacts-directory }}
```

The scan action creates reports and
local outputs. The workflow selects authenticated publication steps and their
permissions.

## Export a GitHub Check or other integration payload

With a supporting binary, a later step can reuse the action's run for the
Checks API, Slack, Jira, VS Code, LSP, or a pull request gate. For example:

```yaml
- name: Prepare GitHub Check payload
  if: ${{ always() && steps.hooray.outputs.run-id != '' }}
  env:
    HOORAY_DATABASE_PATH: ${{ steps.hooray.outputs.database }}
    HR_RUN_ID: ${{ steps.hooray.outputs.run-id }}
    HR_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
  run: |
    hooray integrations export "$HR_RUN_ID" --kind github-check --head-sha "$HR_HEAD_SHA" --output hooray-check.json
```

Use the installed Hooray command or the same `executable` supplied to the scan
action. Payload export does not submit API requests or require credentials.
To render another ordinary report in the job, use
`hooray report "$HR_RUN_ID" --format json --output hooray.json` with the same
database environment; report generation preserves policy exit status `1` for
a denied run.
