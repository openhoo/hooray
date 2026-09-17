//! Per-ecosystem lockfile and container-image parsers shared by the
//! `input` dispatch layer.

pub(crate) mod archive;
pub(crate) mod bun;
pub(crate) mod cargo;
pub(crate) mod conda;
pub(crate) mod dart;
pub(crate) mod elixir;
pub(crate) mod go;
pub(crate) mod gradle;
pub(crate) mod helm;
pub(crate) mod image;
pub(crate) mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod php;
pub(crate) mod pnpm;
pub(crate) mod python;
pub(crate) mod ruby;
pub(crate) mod swift;
pub(crate) mod yarn;

use std::collections::BTreeMap;

use crate::model::ComponentId;

/// Resolved lockfile components keyed by (lowercased) name, then resolved
/// version; version maps are ordered so first-value lookups pick the
/// lexically smallest version, matching prior flat-map scan semantics.
pub(crate) type LockComponents = BTreeMap<String, BTreeMap<String, ComponentId>>;
/// Resolves a lockfile dependency reference against the recorded versions of
/// one component name: the exact requested version when present, otherwise
/// the first (lexically smallest) recorded version.
pub(crate) fn resolve_lock_component(
    versions: &BTreeMap<String, ComponentId>,
    requested: Option<&str>,
) -> Option<ComponentId> {
    requested
        .and_then(|requested| versions.get(requested))
        .or_else(|| versions.values().next())
        .cloned()
}
/// Splits an npm-style `name@locator` descriptor into package name and locator,
/// honoring `@scope/name` packages and optional pnpm `/`-prefixed lockfile keys.
pub(crate) fn split_descriptor(descriptor: &str) -> Option<(&str, &str)> {
    let rest = descriptor.strip_prefix('/').unwrap_or(descriptor);
    if let Some(scoped) = rest.strip_prefix('@') {
        let at = scoped.find('@')?;
        Some((&rest[..at + 1], &rest[at + 2..]))
    } else {
        let at = rest.find('@')?;
        Some((&rest[..at], &rest[at + 1..]))
    }
}

/// Parses an XML manifest document, tolerating a UTF-8 byte-order mark
/// (Visual Studio and Maven tooling write BOM-prefixed project files) and
/// failing closed on any malformed XML.
pub(crate) fn xml_doc<'a>(
    text: &'a str,
    path: &str,
    format: &'static str,
) -> Result<roxmltree::Document<'a>, crate::input::InputError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    roxmltree::Document::parse(text).map_err(|e| crate::input::malformed(path, format, e))
}

/// Text of the first direct child element named `name`, trimmed; `None`
/// when absent, empty, or mixed-content.
pub(crate) fn child_text<'a>(node: &roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}
