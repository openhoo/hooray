//! JFrog Xray parity record–replay harness.
//!
//! # Record/replay flow
//!
//! 1. `hooray-parity scan-case --case <DIR>` runs a pinned, deterministic
//!    in-process scan (memory store, fixed run id and `as_of`) and prints the
//!    hooray side in canonical form ([`normalize::normalize_hooray`]).
//! 2. The operator captures Xray output for the same inputs (`jf audit
//!    --format json` and optionally the CycloneDX SBOM variant) and records
//!    both sides into one replay file with `hooray-parity record`
//!    ([`recording::Recording`]).
//! 3. `hooray-parity check` re-runs every recorded case offline and enforces:
//!    corpus tier-1 expectations ([`crate::engine`]-driven normalization),
//!    an always-on drift guard (fresh offline scan must reproduce the
//!    recorded hooray components/licenses/license findings/parse errors
//!    exactly; vulnerabilities are exempt because offline scans produce
//!    none), and the scorecard thresholds chosen by the operator
//!    ([`compare::scorecard`]).

pub mod compare;
pub mod corpus;
pub mod model;
pub mod normalize;
pub mod recording;
pub mod xray;
