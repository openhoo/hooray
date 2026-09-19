use std::collections::BTreeSet;

use serde_yaml::Value as Yaml;

use super::yaml_str;
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_chart_yaml(
    path: &str,
    bytes: &[u8],
    lock: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "Chart.yaml")?)
        .map_err(|e| malformed(path, "Chart.yaml", e))?;
    let name = doc
        .get("name")
        .and_then(Yaml::as_str)
        .filter(|v| !v.is_empty());
    let version = doc
        .get("version")
        .and_then(yaml_str)
        .filter(|v| !v.is_empty());
    if name.is_some() || version.is_some() {
        out.claim_asset_identity(path, name.map(str::to_owned), version);
    }
    let Some(dependencies) = doc.get("dependencies").and_then(Yaml::as_sequence) else {
        return Ok(());
    };
    entry_bound(dependencies.len(), path, "Chart.yaml")?;
    for dependency in dependencies {
        // `file://` repositories and `@local`/`alias:local` references name
        // local subcharts, not registry components.
        if helm_local_repository(dependency) {
            continue;
        }
        let Some(name) = dependency.get("name").and_then(Yaml::as_str) else {
            return Err(malformed_msg(
                path,
                "Chart.yaml",
                "dependency entry has no name",
            ));
        };
        let Some(version) = dependency.get("version").and_then(yaml_str) else {
            return Err(malformed_msg(
                path,
                "Chart.yaml",
                "dependency entry has no version",
            ));
        };
        if name.is_empty() || version.is_empty() {
            return Err(malformed_msg(
                path,
                "Chart.yaml",
                "dependency entry has an empty name or version",
            ));
        }
        // A sibling Chart.lock already resolved these constraints; the
        // lockfile's pinned versions supersede the declared ranges.
        if lock.is_none() {
            out.add(
                "helm",
                name,
                &version,
                Scope::Runtime,
                path,
                BTreeSet::new(),
            )?;
        }
    }
    Ok(())
}

/// Reports whether a Chart dependency references a local subchart rather
/// than a chart repository: `file://` URLs or the `@local`/`alias:local`
/// repository aliases.
fn helm_local_repository(dependency: &Yaml) -> bool {
    dependency
        .get("repository")
        .and_then(Yaml::as_str)
        .is_some_and(|repository| {
            repository.starts_with("file://")
                || repository == "@local"
                || repository == "alias:local"
        })
}

/// Parses a Helm `Chart.lock`: the resolved-dependency artifact `helm
/// dependency build`/`update` writes. Entries carry exact resolved versions,
/// unlike `Chart.yaml` constraints, so they always produce versioned
/// `pkg:helm/<name>@<version>` components.
pub(crate) fn parse_chart_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "Chart.lock")?)
        .map_err(|e| malformed(path, "Chart.lock", e))?;
    let dependencies = doc
        .get("dependencies")
        .and_then(Yaml::as_sequence)
        .ok_or_else(|| malformed_msg(path, "Chart.lock", "missing dependencies list"))?;
    entry_bound(dependencies.len(), path, "Chart.lock")?;
    for dependency in dependencies {
        if helm_local_repository(dependency) {
            continue;
        }
        let Some(name) = dependency.get("name").and_then(Yaml::as_str) else {
            return Err(malformed_msg(
                path,
                "Chart.lock",
                "dependency entry has no name",
            ));
        };
        let Some(version) = dependency.get("version").and_then(yaml_str) else {
            return Err(malformed_msg(
                path,
                "Chart.lock",
                "dependency entry has no version",
            ));
        };
        if name.is_empty() || version.is_empty() {
            return Err(malformed_msg(
                path,
                "Chart.lock",
                "dependency entry has an empty name or version",
            ));
        }
        out.add(
            "helm",
            name,
            &version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn chart_dependencies_without_name_fail_closed() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.yaml"),
            "version: 1.0.0\ndependencies:\n  - version: \"1.2.3\"\n",
        )
        .unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "Chart.yaml" && *message == "dependency entry has no name"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn chart_dependencies_without_version_fail_closed() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.yaml"),
            "version: 1.0.0\ndependencies:\n  - name: postgresql\n",
        )
        .unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "Chart.yaml" && *message == "dependency entry has no version"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn chart_lock_resolves_pinned_versions() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.lock"),
            concat!(
                "dependencies:\n",
                "  - name: alpine\n",
                "    version: \"0.1.0\"\n",
                "    repository: https://example.com/charts\n",
                "  - name: mariner\n",
                "    version: \"4.3.2\"\n",
                "    repository: https://example.com/charts\n",
                "digest: sha256:abc\n",
                "generated: \"2020-02-03T10:38:51Z\"\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let version_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.version.clone())
        };
        assert_eq!(version_of("alpine").as_deref(), Some("0.1.0"));
        assert_eq!(version_of("mariner").as_deref(), Some("4.3.2"));
        assert_eq!(inventory.components.len(), 2);
        assert!(
            inventory
                .components
                .values()
                .all(|c| c.purl.starts_with("pkg:helm/") && c.purl.contains('@'))
        );
    }

    #[test]
    fn chart_lock_supersedes_chart_yaml_constraints() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.yaml"),
            concat!(
                "apiVersion: v2\n",
                "name: myapp\n",
                "version: 1.4.2\n",
                "dependencies:\n",
                "  - name: alpine\n",
                "    version: \">=0.1.0\"\n",
                "    repository: https://example.com/charts\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join("Chart.lock"),
            concat!(
                "dependencies:\n",
                "  - name: alpine\n",
                "    version: \"0.1.0\"\n",
                "    repository: https://example.com/charts\n",
                "digest: sha256:abc\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        // The resolved lockfile version wins; the declared constraint is not
        // inventoried alongside it.
        assert_eq!(inventory.components.len(), 1);
        let alpine = inventory
            .components
            .values()
            .find(|c| c.name == "alpine")
            .unwrap();
        assert_eq!(alpine.version, "0.1.0");
        assert_eq!(alpine.purl, "pkg:helm/alpine@0.1.0");
        // Chart.yaml still contributes asset identity.
        assert_eq!(inventory.asset.version.as_deref(), Some("1.4.2"));
    }

    #[test]
    fn chart_lock_without_dependencies_fails_closed() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("Chart.lock"), "digest: sha256:abc\n").unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "Chart.lock" && *message == "missing dependencies list"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn chart_lock_entry_without_name_or_version_fails_closed() {
        for contents in [
            "dependencies:\n  - version: \"1.2.3\"\n",
            "dependencies:\n  - name: postgresql\n",
            "dependencies:\n  - name: \"\"\n    version: \"1.2.3\"\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("Chart.lock"), contents).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(
                matches!(&error, InputError::Malformed { format, .. } if *format == "Chart.lock"),
                "unexpected error for {contents:?}: {error}"
            );
        }
    }

    #[test]
    fn chart_lock_empty_dependencies_is_valid() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.lock"),
            "dependencies: []\ndigest: sha256:abc\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 0);
    }

    #[test]
    fn chart_yaml_claims_name_and_skips_local_deps() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Chart.yaml"),
            concat!(
                "apiVersion: v2\n",
                "name: my-chart\n",
                "version: 1.0\n",
                "dependencies:\n",
                "  - name: sub\n",
                "    version: 2.0\n",
                "    repository: file://../sub\n",
                "  - name: redis\n",
                "    version: 17.0\n",
                "    repository: https://charts.bitnami.com/bitnami\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "my-chart");
        assert_eq!(inventory.asset.version.as_deref(), Some("1.0"));
        assert_eq!(inventory.components.len(), 1);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "redis" && c.purl == "pkg:helm/redis@17.0")
        );
    }
}
