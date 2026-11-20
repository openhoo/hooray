//! Verify the source in the original Cargo.lock: inventory PURLs currently
//! merge same-name/version Cargo packages from different registries.
use crate::{
    model::{ScanReport, SourceKind},
    publisher::{self, PublisherCoverage},
};
use anyhow::{Result, ensure};
use std::{fs::File, io::Read, path::Path};

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

pub(super) enum Coverage {
    Unknown(&'static str),
    Reviewed { purl: String, matched: usize },
}

pub(super) fn inspect(path: &Path, max_lock: u64, report: &ScanReport) -> Result<Coverage> {
    let mut archive = zip::ZipArchive::new(File::open(path)?)?;
    if !(1..=2).contains(&archive.len()) || archive.has_duplicate_names() || archive.offset() != 0 {
        return Ok(Coverage::Unknown(
            "archive is outside the Cargo lockfile ZIP profile",
        ));
    }
    if archive.validate_header_consistency().is_err() {
        return Ok(Coverage::Unknown(
            "ZIP member headers do not give an unambiguous inventory",
        ));
    }
    let mut has_lock = false;
    for i in 0..archive.len() {
        let e = archive.by_index_data(i)?;
        if !e.is_file()
            || e.is_symlink()
            || e.encrypted()
            || !matches!(e.unix_mode().unwrap_or(0) & 0o170000, 0 | 0o100000)
        {
            return Ok(Coverage::Unknown(
                "expected regular unencrypted ZIP members",
            ));
        }
        match e.name_raw() {
            b"Cargo.lock" => has_lock = true,
            b"Cargo.toml" => (),
            _ => {
                return Ok(Coverage::Unknown(
                    "only root Cargo.lock and optional Cargo.toml are supported",
                ));
            }
        }
    }
    if !has_lock {
        return Ok(Coverage::Unknown("root Cargo.lock is missing"));
    }
    let lock = archive.by_name("Cargo.lock")?;
    ensure!(
        lock.size() <= max_lock,
        "Cargo.lock exceeds gate input limit"
    );
    let mut buf = String::new();
    lock.take(max_lock.saturating_add(1))
        .read_to_string(&mut buf)?;
    ensure!(
        buf.len() as u64 <= max_lock,
        "Cargo.lock exceeds gate input limit"
    );
    let data: toml::Value = toml::from_str(buf.trim_start_matches('\u{feff}'))?;
    let mut targets = data
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p.get("name")
                .and_then(toml::Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case("zip"))
        });
    let Some(pkg) = targets.next() else {
        return Ok(Coverage::Unknown("no zip package in Cargo.lock"));
    };
    if targets.next().is_some() {
        return Ok(Coverage::Unknown("more than one zip package in Cargo.lock"));
    }
    if pkg.get("source").and_then(toml::Value::as_str) != Some(CRATES_IO) {
        return Ok(Coverage::Unknown(
            "zip package is not locked to the crates.io registry",
        ));
    }
    let version = pkg.get("version").and_then(toml::Value::as_str);
    let mut components = report
        .inventory
        .components
        .values()
        .filter(|c| c.name == "zip");
    let Some(component) = components.next() else {
        return Ok(Coverage::Unknown("native scan did not inventory zip"));
    };
    if components.next().is_some()
        || Some(component.version.as_str()) != version
        || !component
            .provenance
            .iter()
            .any(|s| s.kind == SourceKind::Lockfile && s.locator == "Cargo.lock")
    {
        return Ok(Coverage::Unknown(
            "native inventory does not match the locked zip coordinate",
        ));
    }
    let PublisherCoverage::Evaluated { matched_advisories } = publisher::classify(component)?
    else {
        return Ok(Coverage::Unknown(
            "publisher cannot classify the locked zip coordinate",
        ));
    };
    let snapshot = publisher::metadata();
    let actual: std::collections::BTreeSet<_> = report
        .findings
        .values()
        .filter(|f| f.component_id.as_ref() == Some(&component.identity))
        .flat_map(|f| &f.evidence)
        .filter(|e| {
            e.properties
                .get("publisher.snapshot_sha256")
                .map(String::as_str)
                == Some(snapshot.sha256)
        })
        .filter_map(|e| e.properties.get("publisher.advisory"))
        .collect();
    ensure!(
        actual.len() == matched_advisories,
        "publisher evidence count disagrees with native scan"
    );
    Ok(Coverage::Reviewed {
        purl: component.purl.clone(),
        matched: matched_advisories,
    })
}
