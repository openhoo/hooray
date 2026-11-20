# Independent controls for two real Hooray lockfiles

**November 20, 2026.** On the old lockfile Hooray matched all 48 RustSec package/version/advisory records returned by `cargo audit`. However, it reported only **8 of 32** applicable advisory IDs published directly by the `zip` maintainers for the locked `zip@8.6.0`. The other 24 were absent from both tool reports. This is an open detection gap. Agreement between two consumers of related feeds does not establish complete coverage. Neither test establishes exploitability or deployment exposure.

## Full-lockfile check

The two inputs are the unmodified `Cargo.lock` objects at the commits below. Hooray queried live OSV. We separately ran the official [cargo-audit 0.23.0](https://github.com/RustSec/rustsec/releases/tag/cargo-audit%2Fv0.23.0) against [RustSec index f291af9](https://github.com/RustSec/advisory-db/tree/f291af9b1cc0d21dfcea1709d6b037963cef262b), containing 1,555 advisories. We disabled the yanked-crate check and database refresh, used no ignores or target filter, and included unsound and unmaintained warnings. Those warnings are distinct from RustSec's vulnerability class. The scanner is independent; RustSec data also flows into OSV.

| Input | Locked packages | cargo-audit: vulnerability / unsound / unmaintained | Raw Hooray findings of kind `vulnerability` | RustSec rows matched by Hooray |
|---|---:|---:|---:|---:|
| `0361fda09da6d49d477b127a64624e52aef3969e` | 298 | 25 / 22 / 1 | 57 | 48 / 48 |
| `e7c066700df3c8910cbba0e0f913165fe7345c2d` | 295 | 3 / 1 / 0 | 4 | 4 / 4 |

[All 48 reference rows, including the four that persist](cargo-rustsec-coordinates.tsv) list the package, locked version, RustSec ID and class, known CVE/GHSA aliases, fixed ranges, the two Hooray results and source links. We matched the **exact package and version** plus an intersecting primary ID or alias. No Hooray finding was unmatched or ambiguous. The base had 35 distinct RustSec IDs; some affected two locked versions. Twelve rows carry 11 distinct CVEs: CVE-2026-111943 applies to both `webpki-roots` and `rustls-webpki`. The remaining rows do not have a CVE alias in this index. Blank candidate version means the package was removed; a blank candidate finding means no match for that advisory, not that the package has no security issues.

The nine extra base findings were alias duplicates: four each counted under both GHSA and RustSec for `rustls@0.23.45`, and five for `zip@8.6.0`. `cargo deny` 0.19.8 with the repository's policy and all features independently emitted 22 vulnerability diagnostics on the base and none on the foundation. It inspected the selected package graph (285 / 283 entries in its audit-compatible output), so a green policy check did not disprove the four remaining lockfile matches. Nothing here claims that every locked dependency is in the shipped binary.

## Maintainer and CVE controls

- The [Rustls 0.23.46 release](https://github.com/rustls/rustls/releases/tag/v%2F0.23.46) identifies the same four GHSAs as fixed. `rustls@0.23.45` matched all four; `rustls@0.23.46` matched none. This is a maintainer release record; the CVE aliases in the TSV come from the pinned RustSec index.
- For `libsqlite3-sys`, both project manifests enable bundled SQLite. The released crates' `sqlite3/sqlite3.c` identifies SQLite 3.53.2 in [0.38.2](https://docs.rs/crate/libsqlite3-sys/0.38.2/source/sqlite3/sqlite3.c) and 3.54.1 in [0.39.1](https://docs.rs/crate/libsqlite3-sys/0.39.1/source/sqlite3/sqlite3.c). The [CVE-2026-119375 CNA record](https://www.cve.org/CVERecord?id=CVE-2026-119375) covers SQLite versions below 3.54.0 and links the [SQLite fix](https://sqlite.org/src/info/f9b4ee369557c36c). This checks the underlying C version separately from RustSec's crate mapping. Both scanners flagged 0.38.2 and cleared that finding at 0.39.1.
- Both lockfiles retained `quinn-proto@0.11.18` ([publisher advisory 1](https://github.com/quinn-rs/quinn/security/advisories/GHSA-53rm-773f-4q8c), [2](https://github.com/quinn-rs/quinn/security/advisories/GHSA-wppq-2f6r-wfvm)), `quinn-udp@0.5.15` ([publisher advisory](https://github.com/quinn-rs/quinn/security/advisories/GHSA-6pp4-4cxf-xf88)), and `rustix@1.1.5` ([publisher advisory](https://github.com/bytecodealliance/rustix/security/advisories/GHSA-jh2m-fhpj-3vr7)). The two Quinn 0.11 reports give 0.11.19 as the fix; the Quinn UDP 0.5 line gives 0.5.16. The Rustix publisher range includes 1.1.5 but leaves its patched-version field empty; RustSec gives `>=1.1.6`. None of the four has a CVE alias in this RustSec snapshot.

### Independent ZIP coverage check

We queried the [public repository advisory list](https://api.github.com/repos/zip-rs/zip2/security-advisories?per_page=100) separately from the feed used by the scanner. Of 41 publisher records, 38 named both ecosystem `rust` and package `zip`. Three unnamed or differently labelled records were excluded. For each included record, a version must satisfy its affected range **and** precede the published first patch. Some publisher ranges give only a lower bound. Each GHSA counts once; these are distinct publisher advisory IDs, not a count of independently confirmed defects.

| ZIP coordinate | Inside published range | Reported by Hooray | Inside range but absent | Outside range with no finding |
|---|---:|---:|---:|---:|
| `zip@8.6.0` | 32 | 8 | **24** | 6 |
| `zip@9.8.1` | 0 | 0 | 0 | 38 |

[All 38 publisher records](zip-maintainer-coordinates.tsv) include their timestamps, version ranges, patch versions and source links. For example, [GHSA-c9rm-qm35-rhqf](https://github.com/zip-rs/zip2/security/advisories/GHSA-c9rm-qm35-rhqf) names `<= 8.6.0`, patched in `9.0.1`; neither scanner identified it. For a reported advisory, [GHSA-4684-h2q9-2vcp](https://github.com/zip-rs/zip2/security/advisories/GHSA-4684-h2q9-2vcp), the maintainer gives `9.0.1` while [RustSec](https://github.com/RustSec/advisory-db/blob/f291af9b1cc0d21dfcea1709d6b037963cef262b/crates/zip/RUSTSEC-2026-0369.md) gives `>=9.0.0`. Both agree about the two tested versions; the difference matters for advice about intermediate versions. The ZIP coverage gap should remain open until a rerun accounts for the 24 missing IDs. A separate engineering decision is how to adjudicate differences between sources.

## Reproduce

Use Python 3.11+, Git, `cargo audit` 0.23.0 and the two Hooray JSON reports for these exact lockfiles. From this repository, choose new paths for `rustsec-index` and `receipts`:

```sh
git fetch origin refs/pull/362/head
python3 scripts/verify_release_controls.py --binary /path/to/hooray \
  --candidate-ref e7c066700df3c8910cbba0e0f913165fe7345c2d --save-reports pilot-reports
git clone https://github.com/RustSec/advisory-db.git rustsec-index
git -C rustsec-index checkout --detach f291af9b1cc0d21dfcea1709d6b037963cef262b
python3 docs/verification/recheck_cargo.py --db rustsec-index \
  --base-report pilot-reports/base-report.json --foundation-report pilot-reports/candidate-report.json \
  --out receipts
diff -u docs/verification/cargo-rustsec-coordinates.tsv receipts/cargo-rustsec-coordinates.tsv
diff -u docs/verification/zip-maintainer-coordinates.tsv receipts/zip-maintainer-coordinates.tsv
```

[The comparison script](recheck_cargo.py) verifies both lockfile SHA-256s and the clean advisory index revision, runs `cargo audit` on each lockfile, and regenerates both TSVs. It reads public publisher metadata directly and never uploads a project or calls OSV. A replay on November 20, 2026 regenerated both tables byte-for-byte from the two captured reports. The RustSec index is immutable at the named revision; new OSV scans and the publisher API can change. A diff then provides records to investigate. The upstream links in the RustSec TSV are references declared by RustSec or corresponding maintainer advisories; their presence alone is not independent verification of every version range.
