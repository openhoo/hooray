# Contributing

Open an issue before a large scanner, policy, persistence, or public-API change.
Small fixes may go directly to a pull request.

For the current scan architecture, measured bottlenecks and Xray qualification
criteria, see the [engineering assessment](docs/engineering-assessment.md).

## Development

Use the repository Rust toolchain.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo deny check advisories bans licenses sources
```

Scanner changes need deterministic fixtures for accepted, rejected, truncated,
and fail-closed inputs. Network behavior needs bounded responses and timeout
coverage.

Commits use Conventional Commits. Pull requests must explain compatibility and
security impact. Maintainers squash-merge using the Conventional Commit pull
request title. Lockfile changes must accompany manifest changes.

## Recovering a container release

After an interrupted container publication, dispatch the Release workflow on
`main` with the existing tag and version (for example, `image_tag=v0.10.0`
and `image_version=0.10.0`). It reuses the original image. The digest identifies
the full manifest or image index, including its platform and attestation entries.

When the workflow runs from a newer commit, recovery requires the original
signature and build provenance for the release commit. If either is missing,
recovery stops before changing the release notes or public tags. Only the
current GitHub release may update the container's `latest` tag.
