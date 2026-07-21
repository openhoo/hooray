# Hooray

Hooray is a fast, automation-first software composition analysis scanner. The
initial release reads CycloneDX JSON SBOMs, deduplicates package queries, uses
OSV's batch API, fetches vulnerability details concurrently, and emits stable
human or JSON output.

## Scan an SBOM

```bash
cargo run --release -- bom.cdx.json
```

Fail CI when a high or critical vulnerability is present:

```bash
hooray bom.cdx.json --fail-on high
```

Produce machine-readable output:

```bash
hooray bom.cdx.json --format json
```

The input must be CycloneDX JSON containing components with a name, version, and
versioned package URL (`purl`). Nested components are supported. Hooray exits
with status `0` when the configured gate passes, `1` when findings meet the
threshold, and `2` for operational errors.

## Performance model

- One OSV batch request per 1,000 unique packages.
- Duplicate package URLs are removed before network I/O.
- Vulnerability details are fetched once per unique advisory with bounded
  concurrency.
- Findings are sorted deterministically for reproducible CI output.

## Development

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo deny check
```

## Releases

Commits use Conventional Commits. Hooversion derives the next version from
commits on `main`, updates `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`, creates
a `chore(release):` commit and `v<version>` tag, and publishes the GitHub
Release. The release workflow attaches the optimized Linux x86_64 binary,
archive, and checksums.

## License

Licensed under either Apache License 2.0 or the MIT license, at your option.
