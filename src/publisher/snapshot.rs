//! The snapshot contains package metadata, ranges and references only. Its digest
//! pins the exact bytes reviewed in the original maintainer comparison.
use std::{collections::BTreeSet, sync::OnceLock};

use super::{PublisherError, metadata};
use crate::{model::PackageEcosystem, remediation::VersionKey, util::sha256_hex};

const DATA: &str = include_str!("../../docs/verification/zip-maintainer-coordinates.tsv");
const HEADER: &str = "ghsa_id\tpublisher_cve\tpublished_at\tupdated_at\tpublisher_range\tpublisher_first_patched\tbase_8.6.0_in_range\tbase_reported_by_hooray\tfoundation_9.8.1_in_range\tfoundation_reported_by_hooray\tpublisher_url";
const URL_PREFIX: &str = "https://github.com/zip-rs/zip2/security/advisories/";

/// Unlike an OSV range boundary, a fully resolved Cargo coordinate must
/// contain all three numeric parts. Reuse the scanner's Cargo ordering,
/// including SemVer prerelease and build metadata handling.
pub(super) fn version(s: &str) -> Option<VersionKey> {
    let core = s.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    for _ in 0..3 {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    if parts.next().is_some() || s.trim() != s {
        return None;
    }
    VersionKey::parse(PackageEcosystem::Cargo, s)
}

#[derive(Clone, Copy)]
enum Op {
    Less,
    LessEqual,
    Equal,
    GreaterEqual,
    Greater,
}
struct Bound(Op, VersionKey);
impl Bound {
    fn parse(expr: &str) -> Option<Self> {
        let s = expr.trim();
        for (prefix, op) in [
            ("<=", Op::LessEqual),
            (">=", Op::GreaterEqual),
            ("<", Op::Less),
            (">", Op::Greater),
            ("=", Op::Equal),
            ("", Op::Equal),
        ] {
            if let Some(v) = s.strip_prefix(prefix) {
                return Some(Self(op, version(v.trim())?));
            }
        }
        None
    }
    fn contains(&self, candidate: &VersionKey) -> bool {
        match self.0 {
            Op::Less => candidate < &self.1,
            Op::LessEqual => candidate <= &self.1,
            Op::Equal => candidate == &self.1,
            Op::GreaterEqual => candidate >= &self.1,
            Op::Greater => candidate > &self.1,
        }
    }
}

pub(super) struct Advisory {
    pub id: &'static str,
    pub cve: Option<&'static str>,
    pub range: &'static str,
    pub patch: &'static str,
    pub url: &'static str,
    pub modified: &'static str,
    bounds: Vec<Bound>,
    first_patch: VersionKey,
}
impl Advisory {
    pub fn applies(&self, candidate: &VersionKey) -> bool {
        // Several published ranges contain only a lower bound even though a
        // separate first-patched version is provided.
        candidate < &self.first_patch && self.bounds.iter().all(|b| b.contains(candidate))
    }
}

fn load() -> Result<Vec<Advisory>, PublisherError> {
    if sha256_hex(DATA.as_bytes()) != metadata().sha256 {
        return Err(PublisherError::Snapshot("digest mismatch"));
    }
    let mut lines = DATA.lines();
    if lines.next() != Some(HEADER) {
        return Err(PublisherError::Snapshot("unexpected columns"));
    }
    let mut seen = BTreeSet::new();
    lines
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            let [id, cve, _, modified, range, patch, _, _, _, _, url] = fields.as_slice() else {
                return Err(PublisherError::Snapshot("invalid record"));
            };
            if !id.starts_with("GHSA-")
                || !seen.insert(*id)
                || url.strip_prefix(URL_PREFIX) != Some(*id)
            {
                return Err(PublisherError::Snapshot("unexpected advisory identity"));
            }
            let bounds = range
                .split(',')
                .map(Bound::parse)
                .collect::<Option<Vec<_>>>()
                .ok_or(PublisherError::Snapshot("invalid affected range"))?;
            let first_patch =
                version(patch).ok_or(PublisherError::Snapshot("invalid patched version"))?;
            Ok(Advisory {
                id,
                cve: (!cve.is_empty()).then_some(*cve),
                range,
                patch,
                url,
                modified,
                bounds,
                first_patch,
            })
        })
        .collect()
}

pub(super) fn advisories() -> Result<&'static [Advisory], PublisherError> {
    static SNAPSHOT: OnceLock<Result<Vec<Advisory>, PublisherError>> = OnceLock::new();
    SNAPSHOT.get_or_init(load).as_deref().map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_cargo_version_boundaries() {
        for bad in [
            "",
            "1.2",
            "1.02.3",
            "v1.2.3",
            "1.2.3.4",
            "1.2.3-01",
            "1.2.3-alpha..1",
            "1.2.3+",
            "8.6.*",
            " 8.6.0 ",
        ] {
            assert!(version(bad).is_none(), "{bad}");
        }
        assert!(Bound::parse("~1.2.3").is_none());
        assert!(Bound::parse(">=1.2").is_none());
        let pre = Bound::parse("<= 9.0.0-pre3").unwrap();
        assert!(pre.contains(&version("9.0.0-pre2").unwrap()));
        assert!(pre.contains(&version("9.0.0-pre3+build.10").unwrap()));
        assert!(!pre.contains(&version("9.0.0-pre4").unwrap()));
        assert!(!pre.contains(&version("9.0.0").unwrap()));
        let all = advisories().unwrap();
        let bounded = all.iter().find(|r| r.id == "GHSA-83cq-wjh8-gm47").unwrap();
        for (v, want) in [
            ("6.0.0", false),
            ("6.0.1", true),
            ("9.0.5", true),
            ("9.0.6", false),
        ] {
            assert_eq!(bounded.applies(&version(v).unwrap()), want);
        }
        let first_patch = all.iter().find(|r| r.id == "GHSA-5qh5-c9fp-66jm").unwrap();
        assert!(first_patch.applies(&version("9.0.0-rc.1").unwrap()));
        assert!(!first_patch.applies(&version("9.0.0+vendor.1").unwrap()));
    }
}
