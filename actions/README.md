# Hooray actions

Use immutable action revisions in consuming repositories.

```yaml
- uses: openhoo/hooray/actions/scan@<full-commit-sha>
  with:
    version: 0.6.5
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
Repository self-tests may set `executable` to a freshly built local binary;
normal consumers should omit it so the verified release installer runs.
