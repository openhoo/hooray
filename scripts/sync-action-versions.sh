#!/bin/sh
# Keep composite-action defaults, examples, and generated installs aligned.
set -eu

version=$(sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || { echo "error: Cargo.toml package version missing" >&2; exit 1; }

setup_file=actions/setup/action.yml
old_version=$(sed -n 's/^    default: "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' "$setup_file" | head -n 1)
[ -n "$old_version" ] || { echo "error: action version default missing" >&2; exit 1; }

rewrite() {
  file=$1
  temp_file=$(mktemp)
  sed \
    -e "s/default: \"${old_version}\"/default: \"${version}\"/g" \
    -e "s/version: ${old_version}/version: ${version}/g" \
    -e "s/hooray --version ${old_version} --locked/hooray --version ${version} --locked/g" \
    "$file" > "$temp_file"
  chmod 0644 "$temp_file"
  mv "$temp_file" "$file"
}

for file in actions/setup/action.yml actions/scan/action.yml actions/README.md src/integrations.rs; do
  rewrite "$file"
done
