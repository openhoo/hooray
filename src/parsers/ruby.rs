use std::collections::BTreeSet;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_gemfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    scan_lock_section(path, bytes, "Gemfile.lock", "GEM", "gem", out, |spec| {
        if spec == "specs:" || spec.starts_with("remote:") {
            return Ok(None);
        }
        let Some(open) = spec.find(" (") else {
            return Err(format!("invalid gem spec {spec:?}"));
        };
        let name = &spec[..open];
        let versions = spec[open + 2..].trim_end_matches(')');
        let version = versions.split(", ").next().unwrap_or(versions);
        let version = version.split('-').next().unwrap_or(version);
        if name.is_empty() || version.is_empty() {
            return Err(format!("invalid gem spec {spec:?}"));
        }
        Ok(Some((name.to_owned(), version.to_owned())))
    })
}

pub(crate) fn parse_podfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    scan_lock_section(
        path,
        bytes,
        "Podfile.lock",
        "PODS",
        "cocoapods",
        out,
        |line| {
            let Some(entry) = line.strip_prefix("- ") else {
                return Ok(None);
            };
            let Some(open) = entry.find(" (") else {
                return Err(format!("pod entry missing version {entry:?}"));
            };
            let full_name = &entry[..open];
            let name = full_name.split('/').next().unwrap_or(full_name);
            let versions = entry[open + 2..].trim_end_matches(')');
            let version = versions.split(", ").next().unwrap_or(versions);
            if name.is_empty() || version.is_empty() {
                return Err(format!("pod entry missing version {entry:?}"));
            }
            Ok(Some((name.to_owned(), version.to_owned())))
        },
    )
}

/// Walks a bundler/CocoaPods-style lockfile, feeding indented lines inside
/// `section` to `parse_entry` and recording accepted `name`/`version` pairs
/// as `ecosystem` components; `Err` details surface as malformed-input errors.
fn scan_lock_section(
    path: &str,
    bytes: &[u8],
    label: &'static str,
    section: &str,
    ecosystem: &str,
    out: &mut InventoryBuilder,
    parse_entry: impl Fn(&str) -> Result<Option<(String, String)>, String>,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, label)?;
    let mut current = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim_end().trim();
        if trimmed.is_empty() {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            current = trimmed.trim_end_matches(':').to_owned();
            continue;
        }
        if current != section {
            continue;
        }
        let Some((name, version)) =
            parse_entry(trimmed).map_err(|detail| malformed_msg(path, label, detail))?
        else {
            continue;
        };
        entry_bound(out.components.len() + 1, path, label)?;
        out.add(
            ecosystem,
            &name,
            &version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}
