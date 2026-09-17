use std::collections::BTreeSet;

use serde_json::json;
use toml::{Table, Value as Toml};

use crate::input::{
    InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, package_url, utf8,
};
use crate::model::Scope;

const FORMAT: &str = "Gradle version catalog";

/// Catalogs declare dependencies, not a resolved graph. Preserve the strongest
/// declaration (strictly > require > prefer), never substitute a preferred
/// point for a range, and retain the entire declaration in asset metadata.
pub(crate) fn parse_gradle_catalog(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let document: Table = toml::from_str(utf8(bytes, path, FORMAT)?)
        .map_err(|error| malformed(path, FORMAT, error))?;
    check_keys(
        &document,
        &["metadata", "versions", "libraries", "bundles", "plugins"],
        path,
    )?;
    let empty = Table::new();
    let versions = section(&document, "versions", &empty, path)?;
    let libraries = section(&document, "libraries", &empty, path)?;
    let bundles = section(&document, "bundles", &empty, path)?;
    let plugins = section(&document, "plugins", &empty, path)?;
    let mut entries = versions.len() + libraries.len() + bundles.len() + plugins.len();
    entry_bound(entries, path, FORMAT)?;
    for value in versions.values() {
        // A named version is a string or a rich declaration, never another ref.
        version(value, None, path, &mut entries)?;
    }
    for value in bundles.values() {
        let aliases = value
            .as_array()
            .ok_or_else(|| invalid(path, "bundle must be an array of library aliases"))?;
        entries += aliases.len();
        entry_bound(entries, path, FORMAT)?;
        for alias in aliases {
            let alias = string(alias, path)?;
            if !libraries.contains_key(alias) {
                return Err(invalid(
                    path,
                    format!("bundle references missing library {alias}"),
                ));
            }
        }
    }

    let mut declarations = Vec::with_capacity(libraries.len());
    for (alias, value) in libraries {
        let (group, artifact, raw_version) = if let Some(coordinate) = value.as_str() {
            let mut parts = coordinate.split(':');
            let group = parts.next().unwrap_or_default();
            let artifact = parts.next().unwrap_or_default();
            let declared = parts
                .next()
                .ok_or_else(|| invalid(path, "library string must be group:artifact:version"))?;
            if parts.next().is_some() {
                return Err(invalid(
                    path,
                    "library string must be group:artifact:version",
                ));
            }
            (group, artifact, Some(Toml::String(declared.to_owned())))
        } else {
            let table = value.as_table().ok_or_else(|| {
                invalid(path, format!("library {alias} must be a string or table"))
            })?;
            check_keys(table, &["module", "group", "name", "version"], path)?;
            let (group, artifact) = if let Some(module) = table.get("module") {
                if table.contains_key("group") || table.contains_key("name") {
                    return Err(invalid(path, "module cannot be combined with group/name"));
                }
                let module = string(module, path)?;
                let (group, artifact) = module
                    .split_once(':')
                    .ok_or_else(|| invalid(path, "module must be group:artifact"))?;
                (group, artifact)
            } else {
                (
                    required_string(table, "group", path)?,
                    required_string(table, "name", path)?,
                )
            };
            (group, artifact, table.get("version").cloned())
        };
        if !coordinate_part(group) || !coordinate_part(artifact) {
            return Err(invalid(
                path,
                format!("library {alias} has an invalid group/artifact"),
            ));
        }
        let selected = raw_version
            .as_ref()
            .map(|value| version(value, Some(versions), path, &mut entries))
            .transpose()?;
        let declared = selected.as_ref().map_or("*", |value| value.0);
        let constrained = selected.as_ref().is_some_and(|value| value.1);
        let name = format!("{group}/{artifact}");
        if constrained || dynamic(declared) {
            out.add_with_purl(
                &name,
                declared,
                package_url("maven", &name, "*"),
                Scope::Unknown,
                path,
                BTreeSet::new(),
            )?;
        } else {
            out.add(
                "maven",
                &name,
                declared,
                Scope::Unknown,
                path,
                BTreeSet::new(),
            )?;
        }
        let reference = raw_version
            .as_ref()
            .and_then(|value| value.get("ref"))
            .and_then(Toml::as_str);
        declarations.push(json!({
            "alias": alias,
            "identity": format!("{group}:{artifact}"),
            "declaredVersion": raw_version,
            "referencedVersion": reference.and_then(|reference| versions.get(reference)),
            "selectedConstraint": declared,
        }));
    }
    let mut skipped_plugins = Vec::with_capacity(plugins.len());
    for (alias, value) in plugins {
        if let Some(coordinate) = value.as_str() {
            let (id, declared) = coordinate
                .split_once(':')
                .ok_or_else(|| invalid(path, "plugin string must be id:version"))?;
            if id.is_empty() || declared.contains(':') {
                return Err(invalid(path, "plugin string must be id:version"));
            }
            version(&Toml::String(declared.to_owned()), None, path, &mut entries)?;
        } else {
            let table = value
                .as_table()
                .ok_or_else(|| invalid(path, "plugin must be a string or table"))?;
            check_keys(table, &["id", "version"], path)?;
            required_string(table, "id", path)?;
            let declared = table
                .get("version")
                .ok_or_else(|| invalid(path, "plugin is missing version"))?;
            version(declared, Some(versions), path, &mut entries)?;
        }
        skipped_plugins.push(json!({"alias": alias, "reason": "plugin marker resolution is outside catalog library inventory"}));
    }
    out.asset
        .metadata
        .entry("gradle.catalogs".to_owned())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("catalog metadata is an array")
        .push(json!({
            "path": path,
            "versionSemantics": "declared constraints, not resolved lockfile pins",
            "libraries": declarations,
            "skippedPlugins": skipped_plugins,
        }));
    Ok(())
}

fn invalid(path: &str, message: impl ToString) -> InputError {
    malformed_msg(path, FORMAT, message)
}

fn section<'a>(
    document: &'a Table,
    name: &str,
    empty: &'a Table,
    path: &str,
) -> Result<&'a Table, InputError> {
    document.get(name).map_or(Ok(empty), |value| {
        value
            .as_table()
            .ok_or_else(|| invalid(path, format!("{name} must be a table")))
    })
}

fn check_keys(table: &Table, allowed: &[&str], path: &str) -> Result<(), InputError> {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(path, format!("unsupported catalog field {key}")));
        }
    }
    Ok(())
}

fn string<'a>(value: &'a Toml, path: &str) -> Result<&'a str, InputError> {
    value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(path, "expected nonempty string"))
}

fn required_string<'a>(table: &'a Table, key: &str, path: &str) -> Result<&'a str, InputError> {
    string(
        table
            .get(key)
            .ok_or_else(|| invalid(path, format!("missing {key}")))?,
        path,
    )
}

fn coordinate_part(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, ':' | '/' | '\\' | '@')
        })
}

/// Return the strongest declaration and whether rejection rules prevent its
/// representation as a single version. Ref lookup is deliberately one level:
/// Gradle's [versions] values cannot themselves contain version references.
fn version<'a>(
    value: &'a Toml,
    versions: Option<&'a Table>,
    path: &str,
    entries: &mut usize,
) -> Result<(&'a str, bool), InputError> {
    if value.is_str() {
        return Ok((string(value, path)?, false));
    }
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, "version must be a string or rich-version table"))?;
    check_keys(
        table,
        &[
            "ref",
            "require",
            "strictly",
            "prefer",
            "reject",
            "rejectAll",
        ],
        path,
    )?;
    if let Some(reference) = table.get("ref") {
        if table.len() != 1 {
            return Err(invalid(
                path,
                "version.ref cannot be combined with rich-version fields",
            ));
        }
        let reference = string(reference, path)?;
        let target = versions
            .and_then(|versions| versions.get(reference))
            .ok_or_else(|| invalid(path, format!("unresolvable version.ref {reference}")))?;
        return version(target, None, path, entries);
    }
    // Validate every field, including those shadowed by a stronger declaration.
    for key in ["strictly", "require", "prefer"] {
        if let Some(value) = table.get(key) {
            string(value, path)?;
        }
    }
    let mut constrained = false;
    if let Some(reject) = table.get("reject") {
        let rejected = reject
            .as_array()
            .ok_or_else(|| invalid(path, "reject must be an array of versions"))?;
        *entries += rejected.len();
        entry_bound(*entries, path, FORMAT)?;
        for rejected in rejected {
            string(rejected, path)?;
        }
        constrained = !rejected.is_empty();
    }
    if let Some(reject_all) = table.get("rejectAll") {
        constrained |= reject_all
            .as_bool()
            .ok_or_else(|| invalid(path, "rejectAll must be boolean"))?;
    }
    let selected = ["strictly", "require", "prefer"]
        .into_iter()
        .find_map(|key| table.get(key).and_then(Toml::as_str))
        .unwrap_or("*");
    Ok((selected, constrained))
}

fn dynamic(version: &str) -> bool {
    version.starts_with("latest.") || version.contains(['+', '[', ']', '(', ')', '!'])
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use crate::model::{Inventory, Scope};
    use std::fs;
    use tempfile::tempdir;

    fn scan(contents: &str) -> Result<Inventory, InputError> {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("custom.versions.toml"), contents).unwrap();
        scan_path(dir.path(), &config())
    }

    #[test]
    fn catalogs_resolve_coordinates_refs_without_inventing_bom_versions() {
        let inventory = scan(
            r#"
[versions]
okio = "3.18.2"
[libraries]
okio = { group = "com.squareup.okio", name = "okio", version.ref = "okio" }
bom = "org.bouncycastle:bc-jdk15to18-bom:1.85.2"
provider = { module = "org.bouncycastle:bcprov-jdk15to18" }
[bundles]
all = ["okio", "provider"]
[plugins]
kotlin = { id = "org.jetbrains.kotlin.jvm", version = "2.2.21" }
"#,
        )
        .unwrap();
        let tuples: BTreeSet<_> = inventory
            .components
            .values()
            .map(|component| (component.purl.as_str(), component.version.as_str()))
            .collect();
        assert_eq!(
            tuples,
            BTreeSet::from([
                ("pkg:maven/com.squareup.okio/okio@3.18.2", "3.18.2"),
                (
                    "pkg:maven/org.bouncycastle/bc-jdk15to18-bom@1.85.2",
                    "1.85.2"
                ),
                ("pkg:maven/org.bouncycastle/bcprov-jdk15to18", "*"),
            ])
        );
        assert!(
            inventory
                .components
                .values()
                .all(|component| component.scope == Scope::Unknown)
        );
        assert!(inventory.dependencies.is_empty());
        let diagnostics = &inventory.asset.metadata["gradle.catalogs"][0];
        assert_eq!(diagnostics["skippedPlugins"][0]["alias"], "kotlin");
    }

    use std::collections::BTreeSet;

    #[test]
    fn rich_precedence_preserves_ranges_and_all_constraints() {
        let inventory = scan(
            r#"
[versions]
rich = { strictly = "[1,3[", require = "1.5", prefer = "2" }
[libraries]
strict = { module = "g:strict", version.ref = "rich" }
required = { module = "g:required", version = { require = "2", prefer = "1" } }
preferred = { module = "g:preferred", version = { prefer = "3" } }
rejected = { module = "g:rejected", version = { require = "2", reject = ["2"] } }
dynamic = { module = "g:dynamic", version = "1.+" }
latest = { module = "g:latest", version = "latest.release" }
"#,
        )
        .unwrap();
        let tuples: BTreeSet<_> = inventory
            .components
            .values()
            .map(|component| (component.purl.as_str(), component.version.as_str()))
            .collect();
        assert_eq!(
            tuples,
            BTreeSet::from([
                ("pkg:maven/g/strict", "[1,3["),
                ("pkg:maven/g/required@2", "2"),
                ("pkg:maven/g/preferred@3", "3"),
                ("pkg:maven/g/rejected", "2"),
                ("pkg:maven/g/dynamic", "1.+"),
                ("pkg:maven/g/latest", "latest.release"),
            ])
        );
        let declarations = inventory.asset.metadata["gradle.catalogs"][0]["libraries"]
            .as_array()
            .unwrap();
        let strict = declarations
            .iter()
            .find(|declaration| declaration["alias"] == "strict")
            .unwrap();
        assert_eq!(strict["referencedVersion"]["prefer"], "2");
        assert_eq!(strict["referencedVersion"]["require"], "1.5");
    }

    #[test]
    fn catalogs_refuse_malformed_and_dangling_refs_even_in_skipped_plugins() {
        for contents in [
            "[libraries\nx = 'g:a:1'",
            "[libraries]\nx = {module='g:a',version.ref='missing'}",
            "[versions]\nv='1'\n[libraries]\nx = {module='g:a',version.ref=''}",
            "[versions]\nv={ref='other'}\n[libraries]\nx={module='g:a',version.ref='v'}",
            "[libraries]\nx={module='g:a',version={ref='v',require='1'}}",
            "[libraries]\nx={module='g:a',version={strictly='1',prefer=2}}",
            "[libraries]\nx={module='g:a',version={strictly='1',reject='2'}}",
            "[libraries]\nx='g:a'",
            "[libraries]\nx={group='g',version='1'}",
            "[libraries]\nx={module='g:a',group='other',version='1'}",
            "[plugins]\nx={id='a.plugin',version.ref='missing'}",
            "[libraries]\nx={module='g:a',version='1'}\n[bundles]\nb=['missing']",
        ] {
            assert!(
                matches!(scan(contents), Err(InputError::Malformed { .. })),
                "accepted: {contents}"
            );
        }
    }
}
