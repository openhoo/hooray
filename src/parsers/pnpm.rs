use std::collections::{BTreeMap, BTreeSet};

use serde_yaml::Value as Yaml;

use super::npm::npm_scope;
use super::split_descriptor;
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};
pub(crate) fn parse_pnpm_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "pnpm-lock.yaml")?)
        .map_err(|e| malformed(path, "pnpm-lock.yaml", e))?;
    let packages = doc.get("packages").and_then(Yaml::as_mapping);
    let importers = doc.get("importers").and_then(Yaml::as_mapping);
    if packages.is_none() && importers.is_none() {
        return Err(malformed_msg(
            path,
            "pnpm-lock.yaml",
            "missing packages and importers sections",
        ));
    }
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    if let Some(packages) = packages {
        entry_bound(packages.len(), path, "pnpm-lock.yaml")?;
        for (key, entry) in packages {
            let Some(key) = key.as_str() else { continue };
            let Some((name, key_version)) = pnpm_key_parts(key) else {
                continue;
            };
            let version = entry
                .get("version")
                .and_then(Yaml::as_str)
                .unwrap_or(key_version);
            if version.is_empty() {
                continue;
            }
            let dev = entry.get("dev").and_then(Yaml::as_bool).unwrap_or(false);
            let optional = entry
                .get("optional")
                .and_then(Yaml::as_bool)
                .unwrap_or(false);
            let scope = npm_scope(dev, optional);
            let id = out.add("npm", name, version, scope, path, BTreeSet::new())?;
            ids.insert(name.to_owned(), id);
        }
        for (key, entry) in packages {
            let Some((name, _)) = key.as_str().and_then(pnpm_key_parts) else {
                continue;
            };
            let Some(from) = ids.get(name) else { continue };
            let Some(deps) = entry.get("dependencies").and_then(Yaml::as_mapping) else {
                continue;
            };
            for (dep, _) in deps {
                if let Some(to) = dep.as_str().and_then(|dep| ids.get(dep)) {
                    out.edge(from, to, Scope::Runtime, false);
                }
            }
        }
    }
    if let Some(importers) = importers {
        for importer in importers.values() {
            for (field, scope) in [
                ("dependencies", Scope::Runtime),
                ("devDependencies", Scope::Development),
                ("optionalDependencies", Scope::Optional),
            ] {
                let Some(deps) = importer.get(field).and_then(Yaml::as_mapping) else {
                    continue;
                };
                for (dep, spec) in deps {
                    let Some(dep) = dep.as_str() else { continue };
                    if ids.contains_key(dep) {
                        continue;
                    }
                    let Some(version) = pnpm_spec_version(spec) else {
                        continue;
                    };
                    if version.is_empty() {
                        continue;
                    }
                    let id = out.add("npm", dep, &version, scope, path, BTreeSet::new())?;
                    ids.insert(dep.to_owned(), id);
                }
            }
        }
    }
    Ok(())
}

fn pnpm_key_parts(key: &str) -> Option<(&str, &str)> {
    let (name, version) = split_descriptor(key)?;
    let version = version.split('(').next().unwrap_or(version);
    (!version.is_empty()).then_some((name, version))
}

fn pnpm_spec_version(spec: &Yaml) -> Option<String> {
    let Some(text) = spec.as_str() else {
        return spec
            .get("version")
            .and_then(Yaml::as_str)
            .map(str::to_owned);
    };
    if ["link:", "workspace:", "file:", "portal:"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return None;
    }
    if let Some((_, version)) = pnpm_key_parts(text) {
        return Some(version.to_owned());
    }
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;
    #[test]
    fn scans_pnpm_lock_importers_and_packages() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            concat!(
                "lockfileVersion: '9.0'\n",
                "\n",
                "importers:\n",
                "  .:\n",
                "    dependencies:\n",
                "      lodash:\n",
                "        specifier: ^4.17.21\n",
                "        version: 4.17.21\n",
                "    devDependencies:\n",
                "      typescript:\n",
                "        specifier: ^5.0.0\n",
                "        version: 5.2.2\n",
                "\n",
                "packages:\n",
                "\n",
                "  lodash@4.17.21:\n",
                "    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg}\n",
                "    dev: false\n",
                "\n",
                "  typescript@5.2.2:\n",
                "    resolution: {integrity: sha512-mIbW0Sf0MfmZIkWwZlNdcLYy4EBEOJaCKdqXmQOf9zQiEUxJ0jEroBNkdwgY2PLq9mRlMkORLp+V0OsdbNQPA}\n",
                "    dev: true\n",
                "\n",
                "  chokidar@3.5.3:\n",
                "    resolution: {integrity: sha512-ynBi1dZ7l5dXKUeXlV+1dCBJbAwxWfllPhtuK1qN5G5pXGDX1n7IvYiA3TQmRfHFRhXk2QBWmVBQlBlyYCUAA}\n",
                "    optional: true\n",
                "    hasBin: true\n",
                "    dependencies:\n",
                "      anymatch: '3.1.3'\n",
                "\n",
                "  anymatch@3.1.3:\n",
                "    resolution: {integrity: sha512-z4s7hNABNkPnHhVBMuUoCJhJSxkwkutdBmM9E2jY0GkqGnJGdyxpmVdMk9HtNi2F4}\n",
                "\n",
                "  left-pad@1.3.0:\n",
                "    resolution: {integrity: sha512-xIxjYzfAtRcAwY6CwSChWBFjJXyInpY3wLjWkgOaKQ3JDmGmoRV4vSuYqQoVOyjKw}\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let scope_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.scope)
        };
        assert_eq!(scope_of("lodash"), Some(Scope::Runtime));
        assert_eq!(scope_of("typescript"), Some(Scope::Development));
        assert_eq!(scope_of("chokidar"), Some(Scope::Optional));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "left-pad" && c.version == "1.3.0")
        );
        assert!(inventory.dependencies.iter().any(|e| {
            inventory.components.get(&e.from).map(|c| c.name.as_str()) == Some("chokidar")
                && inventory.components.get(&e.to).map(|c| c.name.as_str()) == Some("anymatch")
        }));
    }
}
