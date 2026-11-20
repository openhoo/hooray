#!/usr/bin/env bash
# Exercise the installer with local archives and a stand-in for the external
# signature verifier. Real public signatures are checked during release acceptance.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export ASSETS="$work/assets" RUNNER_TEMP="$work/runner" GITHUB_PATH="$work/path" GITHUB_OUTPUT="$work/output"
export RUNNER_OS_VALUE=Linux RUNNER_ARCH_VALUE=X64
mkdir -p "$ASSETS" "$RUNNER_TEMP" "$work/tools"
cat > "$work/tools/curl" <<'SH'
#!/usr/bin/env bash
set -eu
while [[ "$1" != --output ]]; do shift; done
cp "$ASSETS/${3##*/}" "$2"
SH
cat > "$work/tools/cosign" <<'SH'
#!/usr/bin/env bash
set -eu
[[ "$1" == verify-blob && -s "$2" && "$3" == --bundle && "$4" == "$2.sigstore.json" ]]
[[ "$5" == --certificate-identity && "$6" == https://github.com/openhoo/hooray/.github/workflows/release.yml@refs/heads/main ]]
[[ "$7" == --certificate-oidc-issuer && "$8" == https://token.actions.githubusercontent.com ]]
grep -Fx fixture-accepted "$4" > /dev/null
SH
if ! command -v sha256sum > /dev/null; then
  # macOS developers may only have the system-provided shasum.
  cat > "$work/tools/sha256sum" <<'SH'
#!/bin/sh
exec shasum -a 256 "$@"
SH
fi
chmod +x "$work/tools/"*
export PATH="$work/tools:$PATH"

make_archive() {
  export INPUT_VERSION="$1"
  local stem="hooray-$1-x86_64-unknown-linux-gnu"
  local payload="$work/payload/$stem"
  rm -rf "$work/payload"
  mkdir -p "$payload/licenses"
  echo license > "$payload/LICENSE"
  echo notice > "$payload/licenses/NOTICE"
  local name version
  for name in hooray hooray-parity; do
    version="$1"
    if [[ "$name" == hooray-parity ]]; then
      version="$2"
      if [[ -z "$version" ]]; then continue; fi
    fi
    cat > "$payload/$name" <<SH
#!/bin/sh
case "\$1" in
  --version) echo "$name $version";;
  --help) echo usage;;
  *) exit 1;;
esac
SH
  done
  tar -czf "$ASSETS/$stem.tar.gz" -C "$work/payload" "$stem"
  (cd "$ASSETS" && sha256sum "$stem.tar.gz" > SHA256SUMS)
  echo fixture-accepted > "$ASSETS/$stem.tar.gz.sigstore.json"
  echo fixture-accepted > "$ASSETS/SHA256SUMS.sigstore.json"
}

install_fixture() {
  : > "$GITHUB_PATH"
  : > "$GITHUB_OUTPUT"
  bash actions/setup/install.sh
}
must_reject() {
  if install_fixture > "$work/rejected.log" 2>&1; then
    echo "Unexpected successful installation: $1" >&2
    exit 1
  fi
  test ! -s "$GITHUB_PATH" && test ! -s "$GITHUB_OUTPUT"
}

make_archive 0.9.0 ''
install_fixture
bin="$(cat "$GITHUB_PATH")"
test "$("$bin/hooray" --version)" = 'hooray 0.9.0'
test ! -e "$bin/hooray-parity"
make_archive 0.10.0 0.10.0
install_fixture
bin="$(cat "$GITHUB_PATH")"
test "$("$bin/hooray-parity" --version)" = 'hooray-parity 0.10.0'
test "$(cat "$GITHUB_OUTPUT")" = 'version=0.10.0'
cmp "$bin/LICENSE" "$work/payload/hooray-0.10.0-x86_64-unknown-linux-gnu/LICENSE"
grep -Fx notice "$bin/licenses/NOTICE" > /dev/null
echo rejected > "$ASSETS/SHA256SUMS.sigstore.json"
must_reject 'unverified checksum list'
make_archive 0.10.0 0.10.0
echo corrupt >> "$ASSETS/hooray-0.10.0-x86_64-unknown-linux-gnu.tar.gz"
must_reject 'archive checksum mismatch'
make_archive 0.10.0 ''
must_reject 'missing parity CLI'
make_archive 0.10.0 0.10.01
must_reject 'wrong parity version with the same prefix'
