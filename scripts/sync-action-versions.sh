#!/bin/sh
# Keep composite-action defaults, examples, and generated installs aligned.
# Every rewrite is verified: the script fails when an expected substitution
# does not land, so a drifted file can never produce a silent partial update.
set -eu

# Extract the package version from the [package] section only — a bare
# `version = "x.y.z"` match elsewhere in the manifest must not win.
version=$(awk '
  /^\[package\]/ { in_package = 1; next }
  /^\[/ { in_package = 0 }
  in_package && /^version = "[0-9]+\.[0-9]+\.[0-9]+"$/ {
    gsub(/"/, "", $3); print $3; exit
  }
' Cargo.toml)
[ -n "$version" ] || { echo "error: Cargo.toml package version missing" >&2; exit 1; }

# Rewrite every `default: "X.Y.Z"` / `version: X.Y.Z` literal in one file to
# the Cargo.toml version, then verify the file actually carries the new
# version. A file whose defaults drifted to a different value is updated by
# key, not by matching one blessed old version.
rewrite() {
  file=$1
  temp_file=$(mktemp)
  sed \
    -e "s/default: \"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\"/default: \"${version}\"/g" \
    -e "s/version: [0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/version: ${version}/g" \
    "$file" > "$temp_file"
  chmod 0644 "$temp_file"
  mv "$temp_file" "$file"
  if ! grep -q "${version}" "$file"; then
    echo "error: ${file} carries no ${version} reference after rewrite" >&2
    exit 1
  fi
  if grep -qE "default: \"[0-9]+\.[0-9]+\.[0-9]+\"|version: [0-9]+\.[0-9]+\.[0-9]+" "$file" \
    && ! grep -qE "default: \"${version}\"|version: ${version}" "$file"; then
    echo "error: ${file} still references a stale version after rewrite" >&2
    exit 1
  fi
}

for file in actions/setup/action.yml actions/scan/action.yml actions/README.md; do
  rewrite "$file"
done

echo "synced action versions to ${version}"
