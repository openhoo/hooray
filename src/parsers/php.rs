use std::collections::BTreeSet;

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg};
use crate::model::Scope;
pub(crate) fn parse_composer_json(
    path: &str,
    bytes: &[u8],
    lock: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "composer.json", e))?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed_msg(path, "composer.json", "expected a JSON object"))?;
    if let Some(version) = root
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        out.claim_asset_identity(path, None, Some(version.to_owned()));
    }
    // A sibling composer.lock already resolved these constraints; the
    // lockfile's pinned versions supersede the declared ranges.
    if lock.is_some() {
        return Ok(());
    }
    for (section, scope) in [
        ("require", Scope::Runtime),
        ("require-dev", Scope::Development),
    ] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(packages.len(), path, "composer.json")?;
        for (name, constraint) in packages {
            // Platform packages (php, ext-*, lib-*, composer) carry no vendor/name pair.
            if !name.contains('/') {
                continue;
            }
            let Some(constraint) = constraint.as_str() else {
                continue;
            };
            if constraint.is_empty() {
                continue;
            }
            out.add("composer", name, constraint, scope, path, BTreeSet::new())?;
        }
    }
    Ok(())
}

/// Parses a `composer.lock`: the resolved-dependency artifact `composer
/// install`/`update` writes. `packages[]` holds runtime dependencies and
/// `packages-dev[]` development ones; every entry pins an exact `version`,
/// so locked components always carry `pkg:composer/<vendor>/<name>@<version>`.
pub(crate) fn parse_composer_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "composer.lock", e))?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed_msg(path, "composer.lock", "expected a JSON object"))?;
    for (section, scope) in [
        ("packages", Scope::Runtime),
        ("packages-dev", Scope::Development),
    ] {
        let packages = match root.get(section) {
            Some(value) => value.as_array().ok_or_else(|| {
                malformed_msg(path, "composer.lock", format!("{section} is not a list"))
            })?,
            // `packages` is mandatory in every composer.lock; `packages-dev`
            // may be absent.
            None if section == "packages" => {
                return Err(malformed_msg(
                    path,
                    "composer.lock",
                    "missing packages list",
                ));
            }
            None => continue,
        };
        for package in packages {
            let Some(name) = package.get("name").and_then(Value::as_str) else {
                return Err(malformed_msg(
                    path,
                    "composer.lock",
                    "package entry has no name",
                ));
            };
            let Some(version) = package.get("version").and_then(Value::as_str) else {
                return Err(malformed_msg(
                    path,
                    "composer.lock",
                    "package entry has no version",
                ));
            };
            if name.is_empty() || version.is_empty() {
                return Err(malformed_msg(
                    path,
                    "composer.lock",
                    "package entry has an empty name or version",
                ));
            }
            let licenses = package
                .get("license")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|expression| crate::model::License {
                    expression: Some(expression.to_owned()),
                    name: None,
                    url: None,
                })
                .collect();
            out.add("composer", name, version, scope, path, licenses)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use crate::model::Scope;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn composer_lock_resolves_pinned_versions_and_dev_scope() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages":[{"name":"symfony/console","version":"6.3.4"},{"name":"monolog/monolog","version":"3.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.3.5"}],"aliases":[],"content-hash":"abc"}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap()
        };
        assert_eq!(component("symfony/console").version, "6.3.4");
        assert_eq!(component("symfony/console").scope, Scope::Runtime);
        assert_eq!(
            component("symfony/console").purl,
            "pkg:composer/symfony/console@6.3.4"
        );
        assert_eq!(component("phpunit/phpunit").version, "10.3.5");
        assert_eq!(component("phpunit/phpunit").scope, Scope::Development);
        assert_eq!(inventory.components.len(), 3);
    }

    #[test]
    fn composer_lock_preserves_declared_licenses_and_honest_unknowns() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages":[
                {"name":"acme/runtime","version":"1.0.0","license":["MIT","Apache-2.0","MIT"]},
                {"name":"acme/absent","version":"1.0.0"}
            ],"packages-dev":[
                {"name":"acme/dev","version":"1.0.0","license":["BSD-3-Clause"]},
                {"name":"acme/empty","version":"1.0.0","license":[]}
            ]}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let analysis = crate::license::analyze_with_files(&inventory, Vec::new()).unwrap();
        for (name, expected) in [
            ("acme/runtime", vec!["Apache-2.0", "MIT"]),
            ("acme/dev", vec!["BSD-3-Clause"]),
            ("acme/absent", vec![]),
            ("acme/empty", vec![]),
        ] {
            let component = inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap();
            assert_eq!(
                component
                    .licenses
                    .iter()
                    .filter_map(|l| l.expression.as_deref())
                    .collect::<Vec<_>>(),
                expected,
                "declared licenses for {name}"
            );
            let rules = analysis
                .findings
                .iter()
                .filter(|f| f.component_id.as_ref() == Some(&component.identity))
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                rules,
                if expected.is_empty() {
                    vec!["license:unknown"]
                } else {
                    vec!["license:detected"; expected.len()]
                },
                "license findings for {name}"
            );
        }
    }

    #[test]
    fn composer_lock_supersedes_composer_json_constraints() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            r#"{"name":"acme/app","version":"1.2.3","require":{"symfony/console":"^6.3","monolog/monolog":"^3.0"},"require-dev":{"phpunit/phpunit":"^10.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages":[{"name":"symfony/console","version":"6.3.4"},{"name":"monolog/monolog","version":"3.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.3.5"}]}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        // Locked versions win; no constraint-as-version components remain.
        assert_eq!(inventory.components.len(), 3);
        assert!(inventory.components.values().all(|c| c.purl.contains('@')));
        assert_eq!(inventory.asset.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn composer_lock_without_packages_or_dev_is_valid() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages":[],"packages-dev":[],"content-hash":"abc"}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 0);
    }

    #[test]
    fn composer_lock_entry_without_name_or_version_fails_closed() {
        for contents in [
            r#"{"packages":[{"version":"1.0.0"}]}"#,
            r#"{"packages":[{"name":"a/b"}]}"#,
            r#"{"packages":[{"name":"","version":"1.0.0"}]}"#,
            r#"{"packages-dev":[{"version":"1.0.0"}]}"#,
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("composer.lock"), contents).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(
                matches!(&error, InputError::Malformed { format, .. } if *format == "composer.lock"),
                "unexpected error for {contents:?}: {error}"
            );
        }
    }

    #[test]
    fn composer_lock_non_object_fails_closed() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("composer.lock"), "[1,2]").unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(&error, InputError::Malformed { format, .. } if *format == "composer.lock"),
            "unexpected error: {error}"
        );
    }
}
