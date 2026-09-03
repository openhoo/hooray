#!/usr/bin/env bash
set -euo pipefail

version="$INPUT_VERSION"
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "::error::Hooray version must be an unprefixed semantic version."
  exit 2
fi
if [[ "$RUNNER_OS_VALUE" != Linux || "$RUNNER_ARCH_VALUE" != X64 ]]; then
  echo "::error::Hooray v${version} publishes binaries only for Linux X64 runners."
  exit 2
fi

stem="hooray-${version}-x86_64-unknown-linux-gnu"
archive_name="${stem}.tar.gz"
base_url="https://github.com/openhoo/hooray/releases/download/v${version}"
signature_identity="https://github.com/openhoo/hooray/.github/workflows/release.yml@refs/heads/main"
signature_issuer="https://token.actions.githubusercontent.com"
download_dir="$(mktemp -d "${RUNNER_TEMP}/hooray-download.XXXXXXXX")"
archive="${download_dir}/${archive_name}"
checksums="${download_dir}/SHA256SUMS"
archive_bundle="${archive}.sigstore.json"
checksums_bundle="${checksums}.sigstore.json"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$archive" "${base_url}/${archive_name}"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$checksums" "${base_url}/SHA256SUMS"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$archive_bundle" "${base_url}/${archive_name}.sigstore.json"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$checksums_bundle" "${base_url}/SHA256SUMS.sigstore.json"

if ! command -v cosign >/dev/null 2>&1; then
  echo "::error::Pinned Cosign verifier is unavailable."
  exit 1
fi
cosign verify-blob "$archive" --bundle "$archive_bundle" \
  --certificate-identity "$signature_identity" --certificate-oidc-issuer "$signature_issuer"
cosign verify-blob "$checksums" --bundle "$checksums_bundle" \
  --certificate-identity "$signature_identity" --certificate-oidc-issuer "$signature_issuer"

expected="$(awk -v name="$archive_name" '$2 == name { print $1 }' "$checksums")"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::error::SHA256SUMS contains no unique digest for ${archive_name}."
  exit 1
fi
actual="$(sha256sum "$archive" | awk '{ print $1 }')"
if [[ "$actual" != "$expected" ]]; then
  echo "::error::Checksum mismatch for ${archive_name}."
  exit 1
fi

extract_dir="$(mktemp -d "${RUNNER_TEMP}/hooray-extract.XXXXXXXX")"
tar -xzf "$archive" -C "$extract_dir"
source_binary="${extract_dir}/${stem}/hooray"
if [[ ! -f "$source_binary" ]]; then
  echo "::error::Archive ${archive_name} contains no hooray binary at the expected path."
  exit 1
fi

bin_dir="$(mktemp -d "${RUNNER_TEMP}/hooray-bin.XXXXXXXX")"
cp "$source_binary" "${bin_dir}/hooray"
chmod +x "${bin_dir}/hooray"
"${bin_dir}/hooray" --version | grep -F "hooray ${version}"
echo "$bin_dir" >> "$GITHUB_PATH"
echo "version=$version" >> "$GITHUB_OUTPUT"
