use std::collections::BTreeSet;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{License, Scope};

use super::{LockComponents, resolve_lock_component};
pub(crate) fn parse_cargo_lock(
    path: &str,
    bytes: &[u8],
    manifest: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "Cargo.lock")?;
    let value: toml::Value = toml::from_str(text).map_err(|e| malformed(path, "Cargo.lock", e))?;
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| malformed_msg(path, "Cargo.lock", "missing package array"))?;
    entry_bound(packages.len(), path, "Cargo.lock")?;
    let manifest_package = manifest
        .and_then(|b| utf8(b, path, "Cargo.toml").ok())
        .and_then(|text| toml::from_str::<toml::Value>(text).ok())
        .and_then(|v| v.get("package").cloned());
    let manifest_field = |field: &str| manifest_package.as_ref()?.get(field)?.as_str();
    let manifest_name = manifest_field("name");
    let manifest_version = manifest_field("version");
    // Root-anchored identity: the crate name/version claims the asset like
    // the manifest-name claims of the npm/maven/bun parsers.
    if manifest_package.is_some() {
        out.claim_asset_identity(
            path,
            manifest_name.map(str::to_owned),
            manifest_version.map(str::to_owned),
        );
    }
    // Component identity currently merges Cargo sources at the same name/version.
    // Only credit the manifest's declaration when that coordinate identifies a
    // single local lock entry. A stale sidecar cannot license a registry crate.
    let licensed_root = manifest_name
        .zip(manifest_version)
        .zip(manifest_field("license"))
        .filter(|((name, version), _)| {
            let mut candidates = packages.iter().filter(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(*name)
                    && entry.get("version").and_then(toml::Value::as_str) == Some(*version)
            });
            candidates
                .next()
                .is_some_and(|entry| entry.get("source").is_none())
                && candidates.next().is_none()
        });
    let mut ids = LockComponents::new();
    for package in packages {
        let name = required_toml(package, "name", path)?;
        let version = required_toml(package, "version", path)?;
        let licenses = licensed_root
            .filter(|(coordinate, _)| *coordinate == (name, version))
            .map(|(_, expression)| {
                BTreeSet::from([License {
                    expression: Some(expression.to_owned()),
                    name: None,
                    url: None,
                }])
            })
            .unwrap_or_default();
        let id = out.add("cargo", name, version, Scope::Runtime, path, licenses)?;
        ids.entry(name.to_owned())
            .or_default()
            .insert(version.to_owned(), id);
    }
    for package in packages {
        let name = required_toml(package, "name", path)?;
        let version = required_toml(package, "version", path)?;
        let from = &ids[name][version];
        for dependency in package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(spec) = dependency.as_str() else {
                continue;
            };
            let mut parts = spec.split_whitespace();
            let Some(name) = parts.next() else { continue };
            let version = parts.next();
            let target = ids
                .get(name)
                .and_then(|versions| resolve_lock_component(versions, version));
            if let Some(to) = target {
                out.edge(from, &to, Scope::Runtime, false);
            }
        }
    }
    Ok(())
}
fn required_toml<'a>(
    value: &'a toml::Value,
    field: &'static str,
    path: &str,
) -> Result<&'a str, InputError> {
    value
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| malformed_msg(path, "Cargo.lock", format!("package missing {field}")))
}
#[cfg(test)]
mod tests {

    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;
    #[test]
    fn scans_cargo_graph_and_declared_license() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='app'\nversion='1.0.0'\nlicense='MIT'\n",
        )
        .unwrap();
        fs::write(dir.path().join("Cargo.lock"), "version = 3\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['dep 2.0.0']\n[[package]]\nname='dep'\nversion='2.0.0'\n").unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 2);
        assert_eq!(inventory.dependencies.len(), 1);
        let licensed: Vec<_> = inventory
            .components
            .values()
            .flat_map(|component| {
                component
                    .licenses
                    .iter()
                    .map(move |license| (component.purl.as_str(), license.expression.as_deref()))
            })
            .collect();
        assert_eq!(licensed, [("pkg:cargo/app@1.0.0", Some("MIT"))]);
    }

    #[test]
    fn cargo_manifest_cannot_license_an_unrelated_or_ambiguous_package() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='app'\nversion='1.0.0'\nlicense='MIT'\n",
        )
        .unwrap();
        let local = "[[package]]\nname='app'\nversion='1.0.0'\n";
        let registry = format!("{local}source='registry+https://example.invalid/index'\n");
        for lock in [
            "[[package]]\nname='other'\nversion='1.0.0'\n".to_owned(),
            "[[package]]\nname='app'\nversion='2.0.0'\n".to_owned(),
            registry.clone(),
            format!("{local}{registry}"),
        ] {
            fs::write(dir.path().join("Cargo.lock"), &lock).unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert!(
                inventory.components.values().all(|c| c.licenses.is_empty()),
                "{lock}"
            );
        }
    }

    #[test]
    fn bom_manifest_yields_license_and_identity() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "\u{feff}[package]\nname='app'\nversion='1.0.0'\nlicense='MIT'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("Cargo.lock"),
            "version = 3\n[[package]]\nname='app'\nversion='1.0.0'\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "app");
        assert_eq!(inventory.asset.version.as_deref(), Some("1.0.0"));
        assert!(inventory.components.values().any(|c| {
            c.licenses
                .iter()
                .any(|l| l.expression.as_deref() == Some("MIT"))
        }));
    }
}
