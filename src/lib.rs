//! hooray: fast software composition analysis and vulnerability scanning.
//!
//! Library surface for hooray's scan pipeline:
//!
//! - [`input`]: detection and inventory building from lockfiles and manifests
//!   (leaf parsers are private internals of this module); [`sbom`] ingests CycloneDX/SPDX.
//! - [`scanners`]: content analyzers (secrets, IaC/service config, SAST, malware).
//! - [`osv`]: OSV.org query client; [`analysis`] evaluates affected ranges.
//! - [`graph`] / [`risk`] / [`remediation`]: dependency-graph context, operational
//!   risk, and upgrade planning.
//! - [`engine`]: scan orchestration (`finalize_scan` shared report assembly).
//! - [`policy`]: threshold/exception evaluation with fail-closed defaults.
//! - [`report`]: 14 output formats; [`store`]: SQLite persistence;
//!   [`api`]: HTTP service; [`monitor`]: scheduled re-scan daemon.
//! - [`integrations`]: GitLab bundle artifacts.
//!
//! The `parity` module (feature-gated) is a JFrog Xray record-replay harness
//! driven by the `hooray-parity` binary.
pub mod analysis;
pub mod api;
pub mod config;
pub mod engine;
pub mod graph;
pub mod input;
pub mod integrations;
pub mod license;
pub mod model;
pub mod monitor;
pub mod osv;
#[cfg(feature = "parity")]
pub mod parity;
pub mod policy;
pub mod remediation;
pub mod report;
pub mod risk;
pub mod sbom;
pub mod scanners;
pub mod store;
pub mod util;
