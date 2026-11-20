# Repository promotion pilot

This check runs a real Git artifact repository on loopback. A private writer
holds two staged ZIP files. A separate Git client can download an archive
only after the writer publishes it. The decision applies to the crates.io
`zip` coordinate in a Cargo lockfile and the supplied policy. It does not
certify every dependency or the payload of a general-purpose release.

## Reproduce

Use a full Hooray checkout, the repository's Rust toolchain, Python 3.11+,
and Git with `git-http-backend` installed. Build the gate-enabled CLI from
this source. The Hooray v0.10.0 release is a **sample input**; its shipped CLI
predates the gate.

```sh
cargo build --locked --bin hooray
python3 scripts/repository_gate/pilot.py --binary target/debug/hooray > repository-gate.json
```

The pilot uses no external feed, package installation or production service.
It reads the original Git objects without checking out or running either
project. Every run creates a new SQLite database, private staging directory,
public bare repository and recipient clone, then removes them. Exit zero means
all assertions passed. The JSON contains the executable hash, original file
hashes, complete evaluation and lookup receipts, HTTP results, Git commit
retrieved by the recipient and SHA-256 of the downloaded ZIP.

## Inputs and results

Each archive contains the exact root `Cargo.lock` and `Cargo.toml` bytes at
the named commit. Entry order, timestamps, permissions and storage method are
fixed. Both commits have identical `hooray-policy.yaml` bytes:
`0e3904806071dbaacf90c6268562ffb01d5f10eaaa0f721060b18ca6096f5659`.

| Input commit | Artifact SHA-256 | Covered dependency | Observed outcome |
| --- | --- | --- | --- |
| `0361fda09da6d49d477b127a64624e52aef3969e` | `1fdc416fd196afc341ec8f3d02bc2f88a30250dc4a3a983f5c83c36a2a52730e` | `zip@8.6.0` | Deny; 32 applicable publisher advisories |
| v0.10.0, `9ab514a590002bbb0b8990d60c97d5d9e71c7d8d` | `e4bb19ec1684f1d77718f3582ebf3eb16bd5bfee436efbc457203eaff1b87a62` | `zip@9.8.1` | Allow; no applicable advisory in the pinned snapshot and no policy denial |

The [archived maintainer metadata](zip-maintainer-coordinates.tsv) has SHA-256
`a5d4c51106a5734a8deed3c94836fe99dd251d50e56a1a415c6ec022a4e0334d`.
On November 20, 2026 at 21:50 UTC, we compared it with the ZIP maintainers'
[published repository advisories](https://api.github.com/repos/zip-rs/zip2/security-advisories).
We excluded withdrawn entries and selected records explicitly naming the Rust
package `zip`. All 38 IDs matched, along with their CVE (where present),
affected range, first patched version, publication and update timestamps,
and URL. No ID appeared on only one side. This is a dated check of metadata;
the gate reads the pinned file and never silently refreshes it.

An applicable publisher match independently blocks release even if its severity
is absent. The [historical online controls](release-controls.md) tested a different
decision: Hooray plus online OSV and the policy, without this promotion gate.

| Control | Observable requirement |
| --- | --- |
| Never evaluated; changed ZIP comment; changed policy bytes | `require` returns unknown (1). No public ref or Git object containing the submitted archive appears. |
| Denied upload | `require` returns the stored deny (1). The reader cannot discover the ref or fetch the known Git object ID, including after the fixed upload is published. |
| Unavailable decision database | An operational error (2) stops publication even for the previously allowed input. |
| Reader submits a purported allow, requests a staged upload, or requests a loose object directly | HTTP 404. The denied ZIP really exists in the private staging directory at the time. |
| Allowed upload | The publisher calls `require` (0) and publishes those exact bytes. A fresh HTTP clone retrieves a ZIP with the expected independent SHA-256. |
| Reader tries to publish | Git receive-pack and an actual `git push` receive HTTP 403. The published refs stay unchanged. |

All controls passed on November 20, 2026 at 21:56 UTC using Git 2.50.1
and a locally built gate executable (SHA-256
`9169dbe297daab101e192afa0adce82efaa19b12c0cfaa787031e94bf79a60cb`).
The old scan recorded 330 policy warnings; the 32 publisher matches triggered
the gate denial. The fixed scan recorded 295 warnings and no denial.
The recipient cloned Git commit `efd828085357c4484620307960f3a61159d5c8c5`;
its ZIP hash matched the v0.10.0 artifact above. Git explicitly refused to
serve the old object's ID, and the old blob was absent from both repositories.
Fresh runs create a new commit because Git timestamps the publication.

## Trust boundary

Only the local promotion process writes to the public repository. It passes a
private copy to `gate require` and publishes the same byte string only on a
matching allow. The process re-reads the resulting Git blob before creating a
ref. Staging and SQLite are outside the Git server's project root. The HTTP
listener exposes only smart Git discovery and upload-pack (Git's **read**
service); it has no promotion, staging, raw file or database endpoint.
The client never supplies the policy or decision used by the writer.

The pilot models one trusted local operator and remote HTTP readers. The
temporary processes share an OS account; this does not isolate a hostile
local process. Concurrent policy changes during publication, multi-node
coordination, high availability, throughput and administrator access controls
require qualification against the intended repository. Changing a decision
can stop future promotion. It cannot recall previously downloaded bytes, and
this harness does not remove earlier public refs. It is a Git pilot, with no
Artifactory/OCI deployment or licensed Xray comparison.
