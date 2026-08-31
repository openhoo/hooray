# Contributing

Open an issue before a large scanner, policy, persistence, or public-API change.
Small fixes may go directly to a pull request.

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
