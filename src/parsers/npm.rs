use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
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
    /// npm accepts the legacy object form `{"type":"MIT","url":"…"}` copied
    /// verbatim from old package.json files; keep the raw value so both
    /// shapes deserialize.
    #[serde(default)]
    license: Option<Value>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
    /// npm's third scope class: installed as a dev or optional dependency,
    /// never part of a production install.
    #[serde(default, rename = "devOptional")]
    dev_optional: bool,
    /// Workspace symlinks (`"node_modules/<ws>": {"resolved": "packages/<ws>",
    /// "link": true}`) carry no version; they alias the link target rather
    /// than describing an installable package.
    #[serde(default)]
    link: bool,
    #[serde(default)]
    resolved: Option<String>,
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
    let lock: NpmLock = serde_json::from_str(utf8(bytes, path, "package-lock.json")?)
        .map_err(|e| malformed(path, "package-lock.json", e))?;
    let root_version = if !lock.packages.is_empty() {
        parse_npm_packages_v2(&lock, path, out)?
    } else {
        parse_npm_dependencies_v1(&lock, path, out)?;
        lock.version.clone()
    };
    // Root-anchored identity: the builder applies this claim only when no
    // shallower lockfile already claimed the field, so nested lockfiles
    // contribute components and edges but never override root identity.
    out.claim_asset_identity(path, lock.name, root_version);
    Ok(())
}

/// Parses a `package.json` manifest: claims the package name/version as
/// asset identity and records declared dependencies as components. A
/// sibling package-lock.json already resolved these constraints, so only
/// identity is claimed when one exists.
// Wired to the `package.json` manifest route in input.rs by the engine
// package (issue #154); the route table lives outside this module.
#[allow(dead_code)]
pub(crate) fn parse_package_json(
    path: &str,
    bytes: &[u8],
    lock: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value = serde_json::from_str(utf8(bytes, path, "package.json")?)
        .map_err(|e| malformed(path, "package.json", e))?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed_msg(path, "package.json", "expected a JSON object"))?;
    let name = root
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let version = root
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    out.claim_asset_identity(path, name.map(str::to_owned), version.map(str::to_owned));
    if lock.is_some() {
        return Ok(());
    }
    for (section, scope) in [
        ("dependencies", Scope::Runtime),
        ("devDependencies", Scope::Development),
        ("optionalDependencies", Scope::Optional),
        ("peerDependencies", Scope::Runtime),
    ] {
        let Some(deps) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(deps.len(), path, "package.json")?;
        for (name, constraint) in deps {
            let Some(constraint) = constraint.as_str() else {
                continue;
            };
            if constraint.is_empty() {
                continue;
            }
            out.add("npm", name, constraint, scope, path, BTreeSet::new())?;
        }
    }
    Ok(())
}

/// npm v2 `packages`-map ingestion: registers flat components, infers names
/// from `node_modules` keys, and wires edges across the four chained
/// dependency maps.
fn parse_npm_packages_v2(
    lock: &NpmLock,
    path: &str,
    out: &mut InventoryBuilder,
) -> Result<Option<String>, InputError> {
    entry_bound(lock.packages.len(), path, "package-lock.json")?;
    // Workspace link entries (`"link": true`) carry no version: they alias
    // their `resolved` target directory, so they register no component but
    // still resolve dependency edges and name workspace packages.
    let mut links = BTreeMap::new();
    for (key, package) in &lock.packages {
        if package.link
            && let Some(target) = package.resolved.as_deref().filter(|t| !t.is_empty())
        {
            links.insert(key.as_str(), target.trim_start_matches("./"));
        }
    }
    let mut ids = BTreeMap::new();
    let mut root_version = None;
    for (key, package) in &lock.packages {
        if key.is_empty() {
            root_version = package.version.clone().or_else(|| lock.version.clone());
            continue;
        }
        if package.link {
            continue;
        }
        let name = package
            .name
            .clone()
            .unwrap_or_else(|| match key.rsplit_once("node_modules/") {
                Some((_, tail)) => tail.to_owned(),
                // Workspace packages key by directory (`packages/<ws>`) and
                // omit `name`; the workspace link under node_modules records
                // the real package name. Fall back to the directory basename,
                // never the full path.
                None => links
                    .iter()
                    .find(|(_, target)| **target == key.as_str())
                    .and_then(|(link_key, _)| {
                        link_key
                            .rsplit_once("node_modules/")
                            .map(|(_, tail)| tail.to_owned())
                    })
                    .unwrap_or_else(|| key.rsplit('/').next().unwrap_or(key).to_owned()),
            });
        let version = package
            .version
            .as_deref()
            .ok_or_else(|| malformed_msg(path, "package-lock.json", "package has no version"))?;
        let scope = npm_scope(package.dev || package.dev_optional, package.optional);
        let licenses = package
            .license
            .as_ref()
            .and_then(npm_license)
            .map(|v| {
                BTreeSet::from([License {
                    expression: Some(v),
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
    // Link entries alias their target so edges into a workspace resolve.
    for (key, target) in &links {
        if let Some(id) = ids.get(*target) {
            ids.insert((*key).to_owned(), id.clone());
        }
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
            .chain(
                package
                    .peer_dependencies
                    .keys()
                    .map(|n| (n, false, Scope::Runtime)),
            )
        {
            if let Some(to) = resolve_npm_key(key, name, &ids).cloned() {
                out.edge(from, &to, scope, optional);
            }
        }
    }
    Ok(root_version)
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
    // npm hoists dependencies to the nearest node_modules that has no
    // conflict: a dependency may live at any ancestor level, so walk every
    // ancestor before the hoisted top-level fallback.
    let mut ancestor = Some(parent);
    while let Some(key) = ancestor {
        if !key.is_empty()
            && let Some(id) = ids.get(&format!("{key}/node_modules/{name}"))
        {
            return Some(id);
        }
        ancestor = npm_parent_key(key);
    }
    ids.get(&format!("node_modules/{name}"))
}

/// Drops the last `node_modules/<name>` segment pair of a package key so
/// dependency resolution walks every ancestor level.
fn npm_parent_key(key: &str) -> Option<&str> {
    if let Some(stripped) = key.strip_prefix("node_modules/")
        && !stripped.contains('/')
    {
        return Some("");
    }
    key.rsplit_once("/node_modules/").map(|(parent, _)| parent)
}

/// Reads an npm `license` field: the modern string form or the legacy
/// object form `{"type":"MIT","url":"…"}` old package.json files carried.
fn npm_license(value: &Value) -> Option<String> {
    value
        .as_str()
        .or_else(|| value.get("type").and_then(Value::as_str))
        .map(str::to_owned)
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
    fn npm_v1_lockfile_claims_root_version() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"legacy","version":"4.5.6","lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "legacy");
        assert_eq!(inventory.asset.version.as_deref(), Some("4.5.6"));
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
    fn npm_v3_mid_level_hoisted_dependency_resolves_through_ancestors() {
        let dir = tempdir().unwrap();
        // `c` is hoisted to `node_modules/a/node_modules/c` because the root
        // already carries a conflicting version; `b` nested under `a` must
        // still resolve its edge to the intermediate level.
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.0.0"},"node_modules/a/node_modules/b":{"name":"b","version":"2.0.0","dependencies":{"c":"^1"}},"node_modules/a/node_modules/c":{"name":"c","version":"1.0.0"},"node_modules/c":{"name":"c","version":"2.0.0"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str, version: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name && c.version == version)
                .unwrap_or_else(|| panic!("missing component {name}@{version}"))
                .identity
                .clone()
        };
        let b = component("b", "2.0.0");
        let c1 = component("c", "1.0.0");
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.from == b && e.to == c1),
            "expected edge b -> c@1.0.0 via intermediate node_modules"
        );
    }

    #[test]
    fn npm_workspaces_links_and_names_resolve() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","version":"1.0.0","packages":{"":{"version":"1.0.0","workspaces":["packages/*"]},"node_modules/app-lib":{"resolved":"packages/app-lib","link":true},"packages/app-lib":{"version":"2.0.0","dependencies":{"left-pad":"^1.3.0"}},"node_modules/left-pad":{"name":"left-pad","version":"1.3.0"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        // The link entry produces no phantom component; the workspace package
        // is named from its link target, not the `packages/` path.
        assert_eq!(inventory.components.len(), 2);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "app-lib" && c.version == "2.0.0")
        );
        assert!(
            !inventory
                .components
                .values()
                .any(|c| c.name.starts_with("packages/"))
        );
        let app_lib = inventory
            .components
            .values()
            .find(|c| c.name == "app-lib")
            .unwrap()
            .identity
            .clone();
        let left_pad = inventory
            .components
            .values()
            .find(|c| c.name == "left-pad")
            .unwrap()
            .identity
            .clone();
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.from == app_lib && e.to == left_pad)
        );
    }

    #[test]
    fn npm_dev_optional_and_object_license_and_peer_edges() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.0.0","license":{"type":"MIT","url":"https://example.com/MIT"},"peerDependencies":{"peer":"^1"}},"node_modules/peer":{"name":"peer","version":"1.0.0","devOptional":true}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let peer = inventory
            .components
            .values()
            .find(|c| c.name == "peer")
            .unwrap();
        assert_eq!(peer.scope, Scope::Development);
        let a = inventory
            .components
            .values()
            .find(|c| c.name == "a")
            .unwrap();
        assert!(
            a.licenses
                .iter()
                .any(|l| l.expression.as_deref() == Some("MIT"))
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.from == a.identity && e.to == peer.identity),
            "expected peerDependencies edge a -> peer"
        );
    }

    #[test]
    fn npm_bom_prefixed_lockfile_parses() {
        let dir = tempdir().unwrap();
        let mut bytes = b"\xef\xbb\xbf".to_vec();
        bytes.extend_from_slice(
            br#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.0.0"}}}"#,
        );
        fs::write(dir.path().join("package-lock.json"), bytes).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
    }

    #[test]
    fn npm_lockfile_identity_stays_anchored_to_root() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"root-app","version":"1.20.0","packages":{"":{"name":"root-app","version":"1.20.0"},"node_modules/root-dep":{"name":"root-dep","version":"1.0.0"}}}"#,
        )
        .unwrap();
        // Nested lockfiles on both sides of the root in lexical order:
        // "a/..." parses before "package-lock.json", "tests/..." after.
        for (nested, name, dep) in [
            ("a/package-lock.json", "nested-a", "dep-a"),
            ("tests/smoke/package-lock.json", "nested-b", "dep-b"),
        ] {
            let nested_path = dir.path().join(nested);
            fs::create_dir_all(nested_path.parent().unwrap()).unwrap();
            fs::write(
                nested_path,
                format!(
                    r#"{{"name":"{name}","version":"9.9.9","packages":{{"":{{"name":"{name}","version":"9.9.9"}},"node_modules/{dep}":{{"name":"{dep}","version":"2.0.0"}}}}}}"#
                ),
            )
            .unwrap();
        }
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "root-app");
        assert_eq!(inventory.asset.version.as_deref(), Some("1.20.0"));
        for dep in ["root-dep", "dep-a", "dep-b"] {
            assert!(
                inventory.components.values().any(|c| c.name == dep),
                "missing nested component {dep}"
            );
        }
    }

    #[test]
    fn npm_nested_lockfiles_prefer_shallowest_identity() {
        let dir = tempdir().unwrap();
        // No root lockfile: the shallowest nested declarer wins even though
        // the deeper "a/b/..." path parses first in lexical order.
        for (nested, name) in [
            ("a/b/package-lock.json", "deep"),
            ("a/package-lock.json", "shallow"),
        ] {
            let nested_path = dir.path().join(nested);
            fs::create_dir_all(nested_path.parent().unwrap()).unwrap();
            fs::write(
                nested_path,
                format!(
                    r#"{{"name":"{name}","version":"1.0.0","packages":{{"":{{"name":"{name}","version":"1.0.0"}}}}}}"#
                ),
            )
            .unwrap();
        }
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "shallow");
        assert_eq!(inventory.asset.version.as_deref(), Some("1.0.0"));
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
