use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_yaml::Value as Yaml;

use super::npm::npm_scope;
use super::{LockComponents, resolve_lock_component, split_descriptor};
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;

/// A resolved package identity: `(name, version)` with pnpm peer suffixes and
/// alias indirections already unwrapped.
type PnpmNode = (String, String);

/// A not-yet-resolved dependency edge: `(from, dep name, dep value, optional)`.
type PnpmEdge = (PnpmNode, String, String, bool);

pub(crate) fn parse_pnpm_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "pnpm-lock.yaml")?)
        .map_err(|e| malformed(path, "pnpm-lock.yaml", e))?;
    let packages = doc.get("packages").and_then(Yaml::as_mapping);
    let snapshots = doc.get("snapshots").and_then(Yaml::as_mapping);
    let importers = doc.get("importers").and_then(Yaml::as_mapping);
    if packages.is_none() && importers.is_none() {
        return Err(malformed_msg(
            path,
            "pnpm-lock.yaml",
            "missing packages and importers sections",
        ));
    }
    // Explicit `dev`/`optional` flags (v5/v6 `packages:` entries, v9
    // `snapshots:` entries) are authoritative; flagless entries derive scope
    // from importer reachability below.
    let mut entries: BTreeMap<PnpmNode, Option<Scope>> = BTreeMap::new();
    let mut pending: Vec<PnpmEdge> = Vec::new();
    let mut roots: Vec<(PnpmNode, Scope)> = Vec::new();
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
                .unwrap_or(key_version.as_str());
            if version.is_empty() || !pnpm_valid_version(version) {
                continue;
            }
            let node = (name, version.to_owned());
            let dev = entry.get("dev").and_then(Yaml::as_bool).unwrap_or(false);
            let optional = entry
                .get("optional")
                .and_then(Yaml::as_bool)
                .unwrap_or(false);
            if dev || optional {
                entries.insert(node.clone(), Some(npm_scope(dev, optional)));
            } else {
                entries.entry(node.clone()).or_insert(None);
            }
            collect_pnpm_deps(&node, entry, &mut pending);
        }
    }
    if let Some(snapshots) = snapshots {
        // pnpm v9 stores the resolved dependency graph under `snapshots:`,
        // keyed like `packages:`; v5/v6 lockfiles have no such section.
        entry_bound(snapshots.len(), path, "pnpm-lock.yaml")?;
        for (key, entry) in snapshots {
            let Some(key) = key.as_str() else { continue };
            let Some(node) = pnpm_key_parts(key) else {
                continue;
            };
            let dev = entry.get("dev").and_then(Yaml::as_bool).unwrap_or(false);
            let optional = entry
                .get("optional")
                .and_then(Yaml::as_bool)
                .unwrap_or(false);
            if dev || optional {
                entries.insert(node.clone(), Some(npm_scope(dev, optional)));
            }
            collect_pnpm_deps(&node, entry, &mut pending);
        }
    }
    let package_names: BTreeSet<String> = entries.keys().map(|(name, _)| name.clone()).collect();
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
                    let Some(node) = pnpm_resolved_parts(dep, spec) else {
                        continue;
                    };
                    if !package_names.contains(node.0.as_str()) {
                        // Importer-only dependency absent from `packages:`;
                        // its scope comes from the importer field through the
                        // reachability pass below.
                        entries.insert(node.clone(), None);
                    }
                    roots.push((node, scope));
                }
            }
        }
    }
    let reachable = pnpm_reachability(&entries, &pending, &roots);
    let mut ids = LockComponents::new();
    for (node, explicit) in &entries {
        // Explicit flags win; otherwise a package reachable only through
        // importer devDependencies is development, only through
        // optionalDependencies optional, and mixed or unreachable entries
        // stay runtime (conservative: never hide a package from policy).
        let scope = explicit
            .or_else(|| reachable.get(node).copied())
            .unwrap_or(Scope::Runtime);
        let id = out.add("npm", &node.0, &node.1, scope, path, BTreeSet::new())?;
        ids.entry(node.0.clone())
            .or_default()
            .insert(node.1.clone(), id);
    }
    for (from, dep, value, optional) in &pending {
        let Some(from) = ids.get(&from.0).and_then(|versions| versions.get(&from.1)) else {
            continue;
        };
        let Some(to) = pnpm_dep_target(dep, value, |name, version| {
            ids.get(name)
                .and_then(|versions| resolve_lock_component(versions, version))
        }) else {
            continue;
        };
        let scope = if *optional {
            Scope::Optional
        } else {
            Scope::Runtime
        };
        out.edge(from, &to, scope, *optional);
    }
    Ok(())
}

/// Queues a package or snapshot entry's `dependencies`/`optionalDependencies`
/// for resolution once every component is registered.
fn collect_pnpm_deps(from: &PnpmNode, entry: &Yaml, pending: &mut Vec<PnpmEdge>) {
    for (field, optional) in [
        ("dependencies", false),
        ("optionalDependencies", true),
        ("peerDependencies", false),
    ] {
        let Some(deps) = entry.get(field).and_then(Yaml::as_mapping) else {
            continue;
        };
        for (dep, value) in deps {
            let (Some(dep), Some(value)) = (dep.as_str(), value.as_str()) else {
                continue;
            };
            pending.push((from.clone(), dep.to_owned(), value.to_owned(), optional));
        }
    }
}

/// Resolves a dependency map value to its target: the parsed
/// `name@version`/bare-version identity when present, otherwise the
/// dependency name's first known version. Local and protocol specifiers
/// (`link:`, `workspace:`, …) are local references and yield no target.
fn pnpm_dep_target<T>(
    dep: &str,
    value: &str,
    lookup: impl Fn(&str, Option<&str>) -> Option<T>,
) -> Option<T> {
    if pnpm_local_specifier(value) {
        return None;
    }
    pnpm_resolved_str(dep, value)
        .and_then(|(name, version)| lookup(&name, Some(&version)))
        .or_else(|| lookup(dep, None))
}

/// Computes which importer dependency fields can reach each package. A
/// package's class set is the union of the root classes that reach it; a
/// `dependencies` edge keeps the parent's classes while an
/// `optionalDependencies` edge contributes `Optional`, so transitives of
/// optional roots stay optional. Solely-dev-reachable packages classify as
/// development, solely-optional as optional, and anything mixed as runtime.
fn pnpm_reachability(
    entries: &BTreeMap<PnpmNode, Option<Scope>>,
    pending: &[PnpmEdge],
    roots: &[(PnpmNode, Scope)],
) -> BTreeMap<PnpmNode, Scope> {
    let mut by_name: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (name, version) in entries.keys() {
        by_name
            .entry(name.as_str())
            .or_default()
            .insert(version.as_str());
    }
    let mut adjacent: BTreeMap<PnpmNode, Vec<(PnpmNode, bool)>> = BTreeMap::new();
    for (from, dep, value, optional) in pending {
        if !entries.contains_key(from) {
            continue;
        }
        let to = pnpm_dep_target(dep, value, |name, version| {
            let versions = by_name.get(name)?;
            let version = version
                .and_then(|version| versions.get(version).copied())
                .or_else(|| versions.iter().next().copied())?;
            Some((name.to_owned(), version.to_owned()))
        });
        if let Some(to) = to {
            adjacent
                .entry(from.clone())
                .or_default()
                .push((to, *optional));
        }
    }
    let mut classes: BTreeMap<PnpmNode, BTreeSet<Scope>> = BTreeMap::new();
    let mut queue: VecDeque<PnpmNode> = VecDeque::new();
    for (node, scope) in roots {
        let Some(node) = by_name
            .get(node.0.as_str())
            .and_then(|versions| {
                versions
                    .get(node.1.as_str())
                    .copied()
                    .or_else(|| versions.iter().next().copied())
            })
            .map(|version| (node.0.clone(), version.to_owned()))
        else {
            continue;
        };
        if classes.entry(node.clone()).or_default().insert(*scope) {
            queue.push_back(node);
        }
    }
    while let Some(node) = queue.pop_front() {
        let parent = classes[&node].clone();
        let Some(edges) = adjacent.get(&node) else {
            continue;
        };
        for (to, optional) in edges {
            let next: Vec<Scope> = if *optional {
                vec![Scope::Optional]
            } else {
                parent.iter().copied().collect()
            };
            let mut newly = false;
            for class in next {
                newly |= classes.entry(to.clone()).or_default().insert(class);
            }
            if newly {
                queue.push_back(to.clone());
            }
        }
    }
    classes
        .into_iter()
        .map(|(node, set)| {
            let scope = if set.len() == 1 {
                *set.iter().next().unwrap_or(&Scope::Runtime)
            } else {
                Scope::Runtime
            };
            (node, scope)
        })
        .collect()
}

/// Splits a `name@version` lockfile key, stripping the `(peer@version)`
/// suffixes pnpm appends to peer-resolved variants and resolving tarball-URL
/// keys (`alias@https://…/name/-/name-version.tgz`) to the real package.
fn pnpm_key_parts(key: &str) -> Option<PnpmNode> {
    let key = key.split('(').next().unwrap_or(key);
    if let Some((name, version)) = pnpm_tarball_parts(key) {
        return Some((name.to_owned(), version.to_owned()));
    }
    let (name, version) = split_descriptor(key)
        .map(|(name, version)| (name.to_owned(), version.to_owned()))
        .or_else(|| pnpm_slash_key_parts(key))?;
    if let Some(aliased) = version.strip_prefix("npm:") {
        let (name, version) = split_descriptor(aliased)?;
        return pnpm_valid_version(version).then(|| (name.to_owned(), version.to_owned()));
    }
    if version.is_empty() || !pnpm_valid_version(&version) {
        return None;
    }
    Some((name, version))
}

/// pnpm v5 `packages:`/`snapshots:` keys use the `/name/version` slash form
/// (`/lodash/4.17.15`, `/@scope/name/1.0.0`); the last segment is the version.
/// Only leading-slash keys parse this way — bare `host/path` keys are git
/// references, not registry packages.
fn pnpm_slash_key_parts(key: &str) -> Option<PnpmNode> {
    let (name, version) = key.strip_prefix('/')?.rsplit_once('/')?;
    if name.is_empty() {
        return None;
    }
    pnpm_valid_version(version).then(|| (name.to_owned(), version.to_owned()))
}

/// Resolves an importer dependency entry to its real `(name, version)`.
/// `npm:` aliases unwrap to the aliased package, local/protocol specifiers
/// (`link:`, `workspace:`, `file:`, `portal:`, `tarball:`) never produce
/// components, and registry tarball URLs resolve to the packaged identity.
fn pnpm_resolved_parts(dep: &str, spec: &Yaml) -> Option<PnpmNode> {
    let text = match spec.as_str() {
        Some(text) => text,
        None => spec.get("version").and_then(Yaml::as_str)?,
    };
    pnpm_resolved_str(dep, text)
}

fn pnpm_resolved_str(dep: &str, text: &str) -> Option<PnpmNode> {
    let text = text.split('(').next().unwrap_or(text);
    if pnpm_local_specifier(text) {
        return None;
    }
    if let Some(aliased) = text.strip_prefix("npm:") {
        return pnpm_resolved_str(dep, aliased);
    }
    if let Some((name, version)) = pnpm_tarball_parts(text) {
        return Some((name.to_owned(), version.to_owned()));
    }
    if let Some(node) = pnpm_key_parts(text) {
        return Some(node);
    }
    // pnpm <5 dependency values use the legacy `/name/version` form.
    if let Some(rest) = text.strip_prefix('/')
        && let Some((name, version)) = rest.rsplit_once('/')
    {
        return pnpm_valid_version(version).then(|| (name.to_owned(), version.to_owned()));
    }
    if text.is_empty() || text.contains(':') || text.contains('@') || text.contains('/') {
        return None;
    }
    Some((dep.to_owned(), text.to_owned()))
}

/// Local and non-registry specifiers never identify a registry component.
fn pnpm_local_specifier(text: &str) -> bool {
    ["link:", "workspace:", "file:", "portal:", "tarball:"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

/// Extracts `name@version` from a registry tarball URL of the form
/// `scheme://host/<name>/-/<name>-<version>.tgz`; other URLs return `None`.
fn pnpm_tarball_parts(text: &str) -> Option<(&str, &str)> {
    let path = text.split("://").nth(1)?;
    let (name_part, file) = path.rsplit_once("/-/")?;
    let stem = file
        .strip_suffix(".tgz")
        .or_else(|| file.strip_suffix(".tar.gz"))
        .or_else(|| file.strip_suffix(".tar"))?;
    let (before, last) = name_part.rsplit_once('/')?;
    let name = match before.rsplit('/').next() {
        Some(scope) if scope.starts_with('@') => &name_part[before.len() - scope.len()..],
        _ => last,
    };
    let version = stem.strip_prefix(last)?.strip_prefix('-')?;
    pnpm_valid_version(version).then_some((name, version))
}

/// Resolved versions are plain semver-ish strings; anything carrying `@`,
/// a protocol `:`, or a path `/` is specifier text, not a version.
fn pnpm_valid_version(version: &str) -> bool {
    !version.contains('@') && !version.contains(':') && !version.contains('/')
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

    #[test]
    fn scans_pnpm_v9_snapshots_edges_and_reachability_scopes() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            concat!(
                "lockfileVersion: '9.0'\n",
                "\n",
                "importers:\n",
                "  .:\n",
                "    dependencies:\n",
                "      left-pad:\n",
                "        specifier: 1.3.0\n",
                "        version: 1.3.0\n",
                "      myalias:\n",
                "        specifier: npm:right-pad@1.0.1\n",
                "        version: right-pad@1.0.1\n",
                "      localpkg:\n",
                "        specifier: workspace:*\n",
                "        version: link:../localpkg\n",
                "      tarred:\n",
                "        specifier: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz\n",
                "        version: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz\n",
                "    devDependencies:\n",
                "      vitest:\n",
                "        specifier: ^4.0.0\n",
                "        version: 4.1.5\n",
                "    optionalDependencies:\n",
                "      fsevents:\n",
                "        specifier: ^2.3.3\n",
                "        version: 2.3.3\n",
                "\n",
                "packages:\n",
                "\n",
                "  left-pad@1.3.0:\n",
                "    resolution: {integrity: sha512-x}\n",
                "\n",
                "  right-pad@1.0.1:\n",
                "    resolution: {integrity: sha512-y}\n",
                "\n",
                "  vitest@4.1.5:\n",
                "    resolution: {integrity: sha512-z}\n",
                "\n",
                "  tinybench@2.9.0:\n",
                "    resolution: {integrity: sha512-t}\n",
                "\n",
                "  fsevents@2.3.3:\n",
                "    resolution: {integrity: sha512-f}\n",
                "\n",
                "  fsevents-dep@1.0.0:\n",
                "    resolution: {integrity: sha512-fd}\n",
                "\n",
                "  shared@1.0.0:\n",
                "    resolution: {integrity: sha512-s}\n",
                "\n",
                "  tarred@https://registry.npmjs.org/zod/-/zod-4.4.3.tgz:\n",
                "    resolution: {integrity: sha512-tb, tarball: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz}\n",
                "    version: 4.4.3\n",
                "\n",
                "snapshots:\n",
                "\n",
                "  left-pad@1.3.0:\n",
                "    dependencies:\n",
                "      right-pad: 1.0.1\n",
                "      shared: 1.0.0\n",
                "\n",
                "  right-pad@1.0.1: {}\n",
                "\n",
                "  vitest@4.1.5:\n",
                "    dependencies:\n",
                "      tinybench: 2.9.0\n",
                "      shared: 1.0.0\n",
                "\n",
                "  tinybench@2.9.0: {}\n",
                "\n",
                "  fsevents@2.3.3:\n",
                "    dependencies:\n",
                "      fsevents-dep: 1.0.0\n",
                "\n",
                "  fsevents-dep@1.0.0: {}\n",
                "\n",
                "  shared@1.0.0: {}\n",
                "\n",
                "  tarred@https://registry.npmjs.org/zod/-/zod-4.4.3.tgz: {}\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        // v9 snapshot dependency edges resolve to real components.
        assert!(inventory.dependencies.iter().any(|e| {
            e.from == component("left-pad").identity && e.to == component("right-pad").identity
        }));
        assert!(inventory.dependencies.iter().any(|e| {
            e.from == component("vitest").identity && e.to == component("tinybench").identity
        }));
        // Reachability scopes: dev-only packages are development, optional-only
        // optional, and packages reachable through both stay runtime.
        assert_eq!(component("vitest").scope, Scope::Development);
        assert_eq!(component("tinybench").scope, Scope::Development);
        assert_eq!(component("fsevents").scope, Scope::Optional);
        assert_eq!(component("fsevents-dep").scope, Scope::Optional);
        assert_eq!(component("left-pad").scope, Scope::Runtime);
        assert_eq!(component("shared").scope, Scope::Runtime);
        // npm: aliases unwrap to the real package; link:/workspace: specifiers
        // never produce components; tarball URLs resolve to the real identity.
        assert_eq!(component("right-pad").version, "1.0.1");
        assert_eq!(component("zod").version, "4.4.3");
        assert_eq!(component("zod").purl, "pkg:npm/zod@4.4.3");
        for c in inventory.components.values() {
            assert!(
                !c.version.contains('@')
                    && !c.version.contains(':')
                    && !c.version.contains('/')
                    && !c.version.contains('('),
                "phantom component {}@{}",
                c.name,
                c.version
            );
            assert!(
                !["myalias", "localpkg", "tarred"].contains(&c.name.as_str()),
                "phantom component {}",
                c.name
            );
        }
    }

    #[test]
    fn pnpm_v5_slash_keys_inventory_transitives() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            concat!(
                "lockfileVersion: 5.4\n",
                "\n",
                "importers:\n",
                "  .:\n",
                "    dependencies:\n",
                "      left-pad: 1.3.0\n",
                "\n",
                "packages:\n",
                "\n",
                "  /left-pad/1.3.0:\n",
                "    resolution: {integrity: sha512-x}\n",
                "    dependencies:\n",
                "      kind-of: 6.0.3\n",
                "\n",
                "  /kind-of/6.0.3:\n",
                "    resolution: {integrity: sha512-y}\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        assert_eq!(component("left-pad").version, "1.3.0");
        assert_eq!(component("kind-of").version, "6.0.3");
        assert!(inventory.dependencies.iter().any(|e| {
            e.from == component("left-pad").identity && e.to == component("kind-of").identity
        }));
    }

    #[test]
    fn pnpm_peer_dependencies_produce_edges() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            concat!(
                "lockfileVersion: '9.0'\n",
                "\n",
                "importers:\n",
                "  .:\n",
                "    dependencies:\n",
                "      plugin:\n",
                "        specifier: ^1.0.0\n",
                "        version: 1.0.0\n",
                "\n",
                "packages:\n",
                "\n",
                "  plugin@1.0.0:\n",
                "    resolution: {integrity: sha512-x}\n",
                "\n",
                "  host@2.0.0:\n",
                "    resolution: {integrity: sha512-y}\n",
                "\n",
                "snapshots:\n",
                "\n",
                "  plugin@1.0.0:\n",
                "    peerDependencies:\n",
                "      host: 2.0.0\n",
                "\n",
                "  host@2.0.0: {}\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        assert!(inventory.dependencies.iter().any(|e| {
            e.from == component("plugin").identity && e.to == component("host").identity
        }));
    }
}
