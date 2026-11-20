# Release controls without an Xray installation

On November 20, 2026, we checked the public Hooray Cargo manifest and lockfile with the policy already committed to Hooray. We used two kinds of reference: a separate scanner over a dated RustSec database, and security advisories published directly by the ZIP and TLS maintainers. There was no licensed Xray reference or repository enforcement test.

| Immutable input | Inventory (packages / edges) | Hooray findings from live OSV | Result with the same policy |
| --- | ---: | ---: | --- |
| Original main, `0361fda` | 298 / 751 | 57 rows; 48 unique package/version/advisory matches after joining aliases | Exit 1: 9 deny rows, 346 warnings |
| Foundation, `e7c0667` | 295 / 744 | 4 rows; 4 unique matches | Exit 0: 299 warnings |
| Patched lockfile, `87b42fc` | 295 / 744 | 0 rows at the time of the check | Exit 0: 295 license warnings |

**Which part is independently verified?** cargo-audit found all the same 48 and 4 advisory matches on the first two inputs. Hooray uses OSV, which ingests RustSec, so agreement with cargo-audit tests our matching and inventory but cannot establish advisory coverage. The positive policy control ties CVE-2026-115905 to `zip@8.6.0`; the patched control contains `zip@9.8.1`. Neither control asserts that all features were enabled in a production binary.

The ZIP maintainers' own published version ranges exposed a coverage gap: 32 of 38 advisories with an explicit Rust `zip` coordinate apply to 8.6.0, and 24 of those advisory IDs appeared in neither result. None of the 38 ranges includes 9.8.1. Distinct published advisories need not be distinct underlying flaws. See the [independent reference check](cargo-advisory-controls.md), [ZIP advisory rows](zip-maintainer-coordinates.tsv) and [Cargo/RustSec matches](cargo-rustsec-coordinates.tsv). The four remaining Hooray findings on the foundation input concerned `quinn-proto`, `quinn-udp` and `rustix`; the patched input updates these to 0.11.19, 0.5.16 and 1.1.6 respectively. No rule or exception was relaxed.

## Repeat the allow and deny controls

Use the shipped Linux scanner, Python 3.11 or later and a checkout containing the relevant Git objects. The command below checks the old deny and current nonblocking input together, confirms the policy file is unchanged and compares the scan inventory with every Cargo.lock package coordinate. It sends public package identifiers to OSV and does not build the sample projects.

```sh
python3 scripts/verify_release_controls.py --binary /path/to/hooray \
  --candidate-ref v0.10.0 > controls.json
```

Exit 0 means both controls matched; 1 is an observed disagreement; 2 is an operational or input error. The reference policy issues warnings by default, so the nonblocking control is not the same as explicit approval of every finding. Changing the feed, policy, or the exact known-fixed ZIP coordinate may change a future outcome. Review that change rather than masking it. [Sample receipts](hooray-online-controls.json) include input and executable hashes, policy outcomes and all advisory/package coordinates, without publishing private paths or scan databases.

The historical foundation commits are available from the implementation PR. If a clone only contains squashed main history, fetch its head with `git fetch origin refs/pull/362/head` to reproduce those inputs. Use the maintainer and RustSec [recheck script](recheck_cargo.py) for the source comparison. The next detection milestone is to reconcile directly published advisories with the aggregated feed while retaining affected versions, feature conditions and aliases. A product replacement still requires tests of the intended repository gate and its policy.
