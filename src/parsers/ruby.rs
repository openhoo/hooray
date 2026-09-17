use std::collections::{BTreeMap, BTreeSet};

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};

/// Bundler lockfile sections whose `specs:` blocks carry resolved
/// `name (version)` entries: remote gems plus `git:`/`path:` sources (a
/// PATH-sourced gem such as a repo's own fastlane checkout is a real
/// component, not a nested dependency).
const GEMFILE_SPEC_SECTIONS: &[&str] = &["GEM", "GIT", "PATH", "PLUGIN SOURCE"];

pub(crate) fn parse_gemfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    scan_lock_section(
        path,
        bytes,
        "Gemfile.lock",
        GEMFILE_SPEC_SECTIONS,
        "gem",
        out,
        SectionGrammar {
            entry: |spec| {
                // Source metadata lines (`remote:`, `revision:`, `ref:`,
                // `specs:`) end their first token in ':'; spec lines never do.
                if spec
                    .split_whitespace()
                    .next()
                    .is_some_and(|token| token.ends_with(':'))
                {
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
            },
            dep: |dep| {
                // Nested bundler deps are `name` or `name (constraint)`; only
                // the name resolves to a component.
                let name = dep.split(" (").next().unwrap_or(dep).trim();
                (!name.is_empty()).then(|| name.to_owned())
            },
        },
    )
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
        &["PODS"],
        "cocoapods",
        out,
        SectionGrammar {
            entry: |line| {
                let Some(entry) = line.strip_prefix("- ") else {
                    return Ok(None);
                };
                // A spec with nested deps ends in `):`; strip the colon before
                // the closing paren so the version stays clean.
                let entry = entry.strip_suffix(':').unwrap_or(entry);
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
            dep: |dep| {
                // Nested pod deps are `- name` or `- name (constraint)`;
                // subspec names (`libwebp/webp`) collapse to the parent pod.
                let dep = dep.strip_prefix("- ").unwrap_or(dep);
                let name = dep
                    .split(" (")
                    .next()
                    .unwrap_or(dep)
                    .split('/')
                    .next()
                    .unwrap_or(dep)
                    .trim();
                (!name.is_empty()).then(|| name.to_owned())
            },
        },
    )
}

/// Result of parsing one spec line: `Some((name, version))` for an entry,
/// `None` for a non-entry line (headers, metadata), `Err` fails closed.
type EntryParse = Result<Option<(String, String)>, String>;

/// Line grammar for a bundler/CocoaPods-style lockfile section.
struct SectionGrammar {
    /// Parses a spec line at entry depth.
    entry: fn(&str) -> EntryParse,
    /// Maps a nested dependency line to the component name it references.
    dep: fn(&str) -> Option<String>,
}

/// Walks a bundler/CocoaPods-style lockfile. Indented lines inside the
/// `sections` blocks are classified by indent depth: lines deeper than the
/// most recent accepted entry are nested dependency declarations and become
/// dependency edges (never components), while lines at entry depth are fed
/// to `grammar.entry`. `grammar.dep` maps a nested line to the component
/// name it references; unresolved references are dropped. `Err` details from
/// `grammar.entry` surface as malformed-input errors.
fn scan_lock_section(
    path: &str,
    bytes: &[u8],
    label: &'static str,
    sections: &[&str],
    ecosystem: &str,
    out: &mut InventoryBuilder,
    grammar: SectionGrammar,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, label)?;
    let mut current = String::new();
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    let mut entry_depth: Option<usize> = None;
    let mut last_entry: Option<ComponentId> = None;
    let mut pending: Vec<(ComponentId, String)> = Vec::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let depth = raw.len() - raw.trim_start().len();
        if depth == 0 {
            current = trimmed.trim_end_matches(':').to_owned();
            entry_depth = None;
            last_entry = None;
            continue;
        }
        if !sections.contains(&current.as_str()) {
            continue;
        }
        if entry_depth.is_some_and(|d| depth > d) {
            // Deeper than the current entry: a nested dependency line.
            if let (Some(from), Some(dep)) = (last_entry.clone(), (grammar.dep)(trimmed)) {
                pending.push((from, dep));
            }
            continue;
        }
        match (grammar.entry)(trimmed).map_err(|detail| malformed_msg(path, label, detail))? {
            Some((name, version)) => {
                entry_bound(out.components.len() + 1, path, label)?;
                let id = out.add(
                    ecosystem,
                    &name,
                    &version,
                    Scope::Runtime,
                    path,
                    BTreeSet::new(),
                )?;
                entry_depth = Some(depth);
                last_entry = Some(id.clone());
                ids.entry(name).or_insert(id);
            }
            // A non-entry line at or above entry depth ends the current
            // entry context (e.g. `specs:` headers, `trunk:` repo keys).
            None => {
                entry_depth = None;
                last_entry = None;
            }
        }
    }
    for (from, dep) in pending {
        if let Some(to) = ids.get(&dep) {
            out.edge(&from, to, Scope::Runtime, false);
        }
    }
    Ok(())
}
