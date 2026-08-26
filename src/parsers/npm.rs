use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg};
use crate::model::{ComponentId, License, Scope};

#[derive(Deserialize)]
struct NpmLock {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    packages: BTreeMap<String, NpmPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmDependency>,
}
#[derive(Deserialize, Default)]
struct NpmPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
}
#[derive(Deserialize, Default)]
struct NpmDependency {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmDependency>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
}

pub(crate) fn parse_package_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let lock: NpmLock =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "package-lock.json", e))?;
    if !lock.packages.is_empty() {
        parse_npm_packages_v2(&lock, path, out)?;
    } else {
        parse_npm_dependencies_v1(&lock, path, out)?;
    }
    if let Some(name) = lock.name {
        out.asset.name = name;
    }
    Ok(())
}

/// npm v2 `packages`-map ingestion: registers flat components, infers names
/// from `node_modules` keys, and wires edges across the three chained
/// dependency maps.
fn parse_npm_packages_v2(
    lock: &NpmLock,
    path: &str,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    entry_bound(lock.packages.len(), path, "package-lock.json")?;
    let mut ids = BTreeMap::new();
    for (key, package) in &lock.packages {
        if key.is_empty() {
            out.asset.version = package.version.clone().or_else(|| lock.version.clone());
            continue;
        }
        let name = package
            .name
            .clone()
            .unwrap_or_else(|| match key.rsplit_once("node_modules/") {
                Some((_, tail)) => tail.to_owned(),
                None => key.to_owned(),
            });
        let version = package
            .version
            .as_deref()
            .ok_or_else(|| malformed_msg(path, "package-lock.json", "package has no version"))?;
        let scope = npm_scope(package.dev, package.optional);
        let licenses = package
            .license
            .as_ref()
            .map(|v| {
                BTreeSet::from([License {
                    expression: Some(v.clone()),
                    name: None,
                    url: None,
                }])
            })
            .unwrap_or_default();
        ids.insert(
            key.clone(),
            out.add("npm", &name, version, scope, path, licenses)?,
        );
    }
    for (key, package) in &lock.packages {
        let Some(from) = ids.get(key) else { continue };
        for (name, optional, scope) in package
            .dependencies
            .keys()
            .map(|n| (n, false, Scope::Runtime))
            .chain(
                package
                    .dev_dependencies
                    .keys()
                    .map(|n| (n, false, Scope::Development)),
            )
            .chain(
                package
                    .optional_dependencies
                    .keys()
                    .map(|n| (n, true, Scope::Optional)),
            )
        {
            if let Some(to) = resolve_npm_key(key, name, &ids).cloned() {
                out.edge(from, &to, scope, optional);
            }
        }
    }
    Ok(())
}

/// npm v1 nested `dependencies`-tree ingestion.
fn parse_npm_dependencies_v1(
    lock: &NpmLock,
    path: &str,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    for (name, dependency) in &lock.dependencies {
        collect_npm_dependency(name, dependency, None, path, out)?;
    }
    Ok(())
}
fn resolve_npm_key<'a>(
    parent: &str,
    name: &str,
    ids: &'a BTreeMap<String, ComponentId>,
) -> Option<&'a ComponentId> {
    let nested = if parent.is_empty() {
        format!("node_modules/{name}")
    } else {
        format!("{parent}/node_modules/{name}")
    };
    ids.get(&nested)
        .or_else(|| ids.get(&format!("node_modules/{name}")))
}
pub(crate) fn npm_scope(dev: bool, optional: bool) -> Scope {
    if dev {
        Scope::Development
    } else if optional {
        Scope::Optional
    } else {
        Scope::Runtime
    }
}

fn collect_npm_dependency(
    name: &str,
    dependency: &NpmDependency,
    parent: Option<ComponentId>,
    path: &str,
    out: &mut InventoryBuilder,
) -> Result<ComponentId, InputError> {
    let version = dependency
        .version
        .as_deref()
        .ok_or_else(|| malformed_msg(path, "package-lock.json", "dependency has no version"))?;
    let scope = npm_scope(dependency.dev, dependency.optional);
    entry_bound(out.components.len() + 1, path, "package-lock.json")?;
    let id = out.add("npm", name, version, scope, path, BTreeSet::new())?;
    if let Some(parent) = parent {
        out.edge(&parent, &id, scope, dependency.optional);
    }
    for (child, value) in &dependency.dependencies {
        collect_npm_dependency(child, value, Some(id.clone()), path, out)?;
    }
    Ok(id)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;
    #[test]
    fn scans_npm_v3_relationships() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package-lock.json"), r#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.2.3","license":"MIT","dependencies":{"b":"^2"}},"node_modules/b":{"name":"b","version":"2.0.0"}}}"#).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "app");
        assert_eq!(inventory.dependencies.len(), 1);
    }
    #[test]
    fn npm_v3_preserves_development_optional_and_direct_edge_scopes() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","version":"3","packages":{"":{"version":"3"},"node_modules/root":{"name":"root","version":"1","dependencies":{"runtime":"1"},"devDependencies":{"dev":"1"},"optionalDependencies":{"optional":"1"}},"node_modules/runtime":{"name":"runtime","version":"1"},"node_modules/dev":{"name":"dev","version":"1","dev":true},"node_modules/optional":{"name":"optional","version":"1","optional":true}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.version.as_deref(), Some("3"));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "dev" && c.scope == Scope::Development)
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "optional" && c.scope == Scope::Optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Development && !e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Optional && e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Runtime && !e.optional)
        );
    }
    #[test]
    fn npm_v1_dependencies_preserve_nested_dev_and_optional_contracts() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"legacy","dependencies":{"parent":{"version":"1","dependencies":{"dev":{"version":"2","dev":true},"optional":{"version":"3","optional":true}}}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "legacy");
        assert_eq!(inventory.components.len(), 3);
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Development && !e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Optional && e.optional)
        );
    }

    #[test]
    fn npm_v3_nested_dependency_resolves_via_hoisted_top_level_fallback() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.0.0","dependencies":{"b":"^2"}},"node_modules/b":{"name":"b","version":"2.0.0"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let identity_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.identity.clone())
        };
        let a = identity_of("a").unwrap();
        let b = identity_of("b").unwrap();
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.from == a && e.to == b && e.scope == Scope::Runtime && !e.optional),
            "expected hoisted fallback edge a -> b"
        );
    }

    #[test]
    fn npm_v3_rejects_package_entry_without_version() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/a":{"name":"a"}}}"#,
        )
        .unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "package-lock.json" && *message == "package has no version"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn npm_v3_rejects_lockfiles_exceeding_entry_bound() {
        let config = Config {
            max_input_bytes: 1 << 30,
            ..Config::default()
        };
        let dir = tempdir().unwrap();
        let entries: Vec<String> = (0..=100_000)
            .map(|i| format!(r#""node_modules/p{i}":{{"name":"p{i}","version":"1.0.0"}}"#))
            .collect();
        fs::write(
            dir.path().join("package-lock.json"),
            format!(r#"{{"name":"app","packages":{{{}}}}}"#, entries.join(",")),
        )
        .unwrap();
        let error = scan_path(dir.path(), &config).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "package-lock.json" && *message == "more than 100000 entries"
            ),
            "unexpected error: {error}"
        );
    }
}
