# Hooray actions

Use immutable action revisions in consuming repositories.

```yaml
- uses: openhoo/hooray/actions/scan@<full-commit-sha>
  with:
    version: 0.8.1
    policy: hooray-policy.yaml
```

`actions/setup` verifies the selected Linux X64 release archive and
`SHA256SUMS` against their published Sigstore bundles, pinned certificate
identity `https://github.com/openhoo/hooray/.github/workflows/release.yml@refs/heads/main`,
and OIDC issuer `https://token.actions.githubusercontent.com`, then checks the
installed binary version. `actions/scan`
requires an explicit policy, validates it, uses an isolated temporary SQLite
database, and writes a SARIF report by default. Set `offline: true` only when
CI intentionally excludes OSV access.
The `output` input is a report file path when non-empty. The action rejects
`-` and carriage-return/newline characters so its `report` output remains a
safe single-line file reference; leave it empty only when the caller
intentionally consumes CLI output instead of a report file. A policy denial
keeps the scanner's exit status 1, while operational failures remain status 2.
Repository self-tests may set `executable` to a freshly built local binary;
normal consumers should omit it so the verified release installer runs.
