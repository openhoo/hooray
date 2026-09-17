use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::split_descriptor;
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};
use crate::util::jsonc_to_json;

#[derive(Deserialize, Default)]
struct BunLock {
    #[serde(default)]
    workspaces: BTreeMap<String, BunWorkspace>,
    #[serde(default)]
    packages: BTreeMap<String, Vec<Value>>,
}
#[derive(Deserialize, Default)]
struct BunWorkspace {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

/// Text `bun.lock` ingestion. The file is JSONC (comments and trailing
/// commas are legal), so the bytes are sanitized to strict JSON before
/// serde sees them; the binary `bun.lockb` format is not recognized.
pub(crate) fn parse_bun_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "bun.lock")?;
    let json = jsonc_to_json(text);
    let lock: BunLock = serde_json::from_str(&json).map_err(|e| malformed(path, "bun.lock", e))?;
    entry_bound(lock.packages.len(), path, "bun.lock")?;
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    for (key, entry) in &lock.packages {
        let Some(ident) = entry.first().and_then(Value::as_str) else {
            return Err(malformed_msg(
                path,
                "bun.lock",
                format!("package {key} has no identifier"),
            ));
        };
        let Some((name, version)) = bun_ident_parts(ident) else {
            return Err(malformed_msg(
                path,
                "bun.lock",
                format!("package {key} has invalid identifier {ident:?}"),
            ));
        };
        // Local, workspace, tarball, and VCS locators carry no registry
        // version; like yarn.lock resolutions they are skipped rather than
        // pinned to a meaningless purl.
        if version.contains(':') {
            continue;
        }
        let id = out.add("npm", name, version, Scope::Runtime, path, BTreeSet::new())?;
        ids.insert(key.clone(), id);
    }
    for (key, entry) in &lock.packages {
        let Some(from) = ids.get(key) else { continue };
        let Some(meta) = entry.iter().find_map(Value::as_object) else {
            continue;
        };
        for (field, scope, optional) in [
            ("dependencies", Scope::Runtime, false),
            ("devDependencies", Scope::Development, false),
            ("optionalDependencies", Scope::Optional, true),
        ] {
            let Some(deps) = meta.get(field).and_then(Value::as_object) else {
                continue;
            };
            for dep in deps.keys() {
                if let Some(to) = resolve_bun_key(key, dep, &ids).cloned() {
                    out.edge(from, &to, scope, optional);
                }
            }
        }
    }
    if let Some(workspace) = lock.workspaces.get("") {
        // Root-anchored identity: the builder applies this claim only when no
        // shallower lockfile already claimed the field, so a nested bun.lock
        // contributes packages but never overrides root identity.
        out.claim_asset_identity(path, workspace.name.clone(), workspace.version.clone());
    }
    Ok(())
}

/// Splits a `name@locator` package identifier, unwrapping `npm:` aliases so
/// `alias@npm:real@1.2.3` reports the real package name and version.
fn bun_ident_parts(ident: &str) -> Option<(&str, &str)> {
    let (name, locator) = split_descriptor(ident)?;
    if let Some(aliased) = locator.strip_prefix("npm:") {
        return split_descriptor(aliased);
    }
    Some((name, locator))
}

/// Resolves a dependency name against the nested `a/b/c` package keys bun
/// emits for version conflicts, walking every ancestor before the hoisted
/// top-level fallback.
fn resolve_bun_key<'a>(
    parent: &str,
    name: &str,
    ids: &'a BTreeMap<String, ComponentId>,
) -> Option<&'a ComponentId> {
    let mut ancestor = Some(parent);
    while let Some(key) = ancestor {
        if let Some(id) = ids.get(&format!("{key}/{name}")) {
            return Some(id);
        }
        ancestor = bun_parent_key(key);
    }
    ids.get(name)
}

/// Drops the last package-name segment of a nested key; a `@scope/name`
/// segment pair is removed together.
fn bun_parent_key(key: &str) -> Option<&str> {
    let (parent, _) = key.rsplit_once('/')?;
    if parent
        .rsplit('/')
        .next()
        .is_some_and(|s| s.starts_with('@'))
    {
        let (parent, _) = parent.rsplit_once('/')?;
        return Some(parent);
    }
    Some(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn scans_bun_lock_packages_and_edges() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("bun.lock"),
            concat!(
                "{\n",
                "  // bun.lock is JSONC: comments and trailing commas are legal.\n",
                "  \"lockfileVersion\": 1,\n",
                "  \"workspaces\": {\n",
                "    \"\": {\n",
                "      \"name\": \"bun-app\",\n",
                "      \"dependencies\": { \"a\": \"^1.0.0\" },\n",
                "    },\n",
                "  },\n",
                "  \"packages\": {\n",
                "    \"a\": [\"a@1.2.3\", \"\", { \"dependencies\": { \"b\": \"^2.0.0\" } }, \"sha512-x\"],\n",
                "    \"b\": [\"b@2.0.0\", \"\", {}, \"sha512-y\"],\n",
                "    \"a/c\": [\"c@3.1.0\", \"\", {}, \"sha512-z\"], /* nested resolution */\n",
                "  }\n",
                "}\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "bun-app");
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        let a = component("a");
        assert_eq!(a.version, "1.2.3");
        assert_eq!(a.purl, "pkg:npm/a@1.2.3");
        assert_eq!(component("c").version, "3.1.0");
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.from == a.identity && e.to == component("b").identity)
        );
    }

    #[test]
    fn bun_lock_skips_non_registry_locators_and_resolves_npm_aliases() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("bun.lock"),
            r#"{"packages":{
                "app": ["app@file:../app", {"dependencies": {"real": "^1.0.0"}}],
                "real": ["alias@npm:real@1.0.0", "", {}, "sha512-x"],
                "git-dep": ["git-dep@git+https://example.com/repo#abc", "", {}, ""]
            }}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        let real = inventory.components.values().next().unwrap();
        assert_eq!(real.name, "real");
        assert_eq!(real.version, "1.0.0");
        assert_eq!(real.purl, "pkg:npm/real@1.0.0");
    }

    #[test]
    fn bun_lock_resolves_nested_dependencies_before_hoisted_fallback() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("bun.lock"),
            r#"{"packages":{
                "a": ["a@1.0.0", "", {"dependencies": {"b": "^2.0.0"}}, "sha512-x"],
                "a/b": ["b@2.0.0", "", {}, "sha512-y"],
                "b": ["b@1.0.0", "", {}, "sha512-z"]
            }}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str, version: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name && c.version == version)
                .unwrap_or_else(|| panic!("missing component {name}@{version}"))
        };
        assert!(inventory.dependencies.iter().any(|e| {
            e.from == component("a", "1.0.0").identity && e.to == component("b", "2.0.0").identity
        }));
    }

    #[test]
    fn malformed_bun_lock_fails_closed() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bun.lock"), "{ not json").unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, .. } if *format == "bun.lock"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn bun_lock_rejects_package_entry_without_identifier() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bun.lock"), r#"{"packages":{"a":[]}}"#).unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "bun.lock" && message.contains("no identifier")
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn minimal_bun_lock_scans_to_empty_inventory() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("bun.lock"),
            "{\n  \"lockfileVersion\": 1,\n}\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(inventory.components.is_empty());
    }

    #[test]
    fn nested_bun_lock_does_not_override_root_asset_identity() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"axios","version":"1.20.0","packages":{"":{"name":"axios","version":"1.20.0"}}}"#,
        )
        .unwrap();
        let nested = dir.path().join("tests/smoke/bun");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("bun.lock"),
            r#"{"workspaces":{"":{"name":"@axios/bun-smoke-tests"}},"packages":{}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "axios");
        assert_eq!(inventory.asset.version.as_deref(), Some("1.20.0"));
    }

    #[test]
    fn bun_lock_workspace_name_wins_without_shallower_identity() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("packages/app");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("bun.lock"),
            r#"{"workspaces":{"":{"name":"nested-app"}},"packages":{}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "nested-app");
    }
}
