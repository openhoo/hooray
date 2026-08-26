use std::collections::BTreeSet;

use serde_yaml::Value as Yaml;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_chart_yaml(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "Chart.yaml")?)
        .map_err(|e| malformed(path, "Chart.yaml", e))?;
    if let Some(version) = doc
        .get("version")
        .and_then(Yaml::as_str)
        .filter(|v| !v.is_empty())
    {
        out.asset.version = Some(version.to_owned());
    }
    let Some(dependencies) = doc.get("dependencies").and_then(Yaml::as_sequence) else {
        return Ok(());
    };
    entry_bound(dependencies.len(), path, "Chart.yaml")?;
    for dependency in dependencies {
        let Some(name) = dependency.get("name").and_then(Yaml::as_str) else {
            return Err(malformed_msg(
                path,
                "Chart.yaml",
                "dependency entry has no name",
            ));
        };
        let Some(version) = dependency.get("version").and_then(Yaml::as_str) else {
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
        out.add("helm", name, version, Scope::Runtime, path, BTreeSet::new())?;
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
}
