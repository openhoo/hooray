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
    let declared_license = manifest
        .and_then(|b| toml::from_str::<toml::Value>(std::str::from_utf8(b).ok()?).ok())
        .and_then(|v| {
            v.get("package")?
                .get("license")?
                .as_str()
                .map(str::to_owned)
        });
    let mut ids = LockComponents::new();
    for package in packages {
        let name = required_toml(package, "name", path)?;
        let version = required_toml(package, "version", path)?;
        let licenses = declared_license
            .as_ref()
            .filter(|_| packages.len() == 1)
            .map(|v| {
                BTreeSet::from([License {
                    expression: Some(v.clone()),
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
    }
}
