use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};
pub(crate) fn parse_requirements(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut logical = String::new();
    for raw in utf8(bytes, path, "requirements.txt")?.lines() {
        let trimmed = raw.trim();
        logical.push_str(trimmed.strip_suffix('\\').unwrap_or(trimmed));
        if trimmed.ends_with('\\') {
            logical.push(' ');
            continue;
        }
        let line = logical.split('#').next().unwrap_or_default().trim();
        if !line.is_empty() && !line.starts_with('-') {
            let (name, pinned) = line.split_once("==").ok_or_else(|| {
                malformed_msg(
                    path,
                    "requirements.txt",
                    "requirements must be pinned with ==",
                )
            })?;
            let version = pinned
                .split(';')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or_default();
            if name.trim().is_empty() || version.is_empty() {
                return Err(malformed_msg(
                    path,
                    "requirements.txt",
                    "empty package name or version",
                ));
            }
            entry_bound(out.components.len() + 1, path, "requirements.txt")?;
            out.add(
                "pypi",
                &normalize_pypi_name(name),
                version,
                Scope::Runtime,
                path,
                BTreeSet::new(),
            )?;
        }
        logical.clear();
    }
    if !logical.trim().is_empty() {
        return Err(malformed_msg(
            path,
            "requirements.txt",
            "unterminated line continuation",
        ));
    }
    Ok(())
}
pub(crate) fn parse_poetry_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "poetry.lock")?;
    let value: toml::Value = toml::from_str(text).map_err(|e| malformed(path, "poetry.lock", e))?;
    let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
        return Err(malformed_msg(
            path,
            "poetry.lock",
            "missing [[package]] entries",
        ));
    };
    entry_bound(packages.len(), path, "poetry.lock")?;
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| malformed_msg(path, "poetry.lock", "package missing name"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                malformed_msg(
                    path,
                    "poetry.lock",
                    format!("package {name} missing version"),
                )
            })?;
        let category = package
            .get("category")
            .and_then(toml::Value::as_str)
            .unwrap_or("main");
        let optional = package
            .get("optional")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let scope = if category == "dev" {
            Scope::Development
        } else if optional {
            Scope::Optional
        } else {
            Scope::Runtime
        };
        let id = out.add(
            "pypi",
            &normalize_pypi_name(name),
            version,
            scope,
            path,
            BTreeSet::new(),
        )?;
        ids.insert(name.to_ascii_lowercase(), id);
    }
    for package in packages {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(from) = ids.get(&name.to_ascii_lowercase()) else {
            continue;
        };
        let Some(deps) = package.get("dependencies").and_then(toml::Value::as_table) else {
            continue;
        };
        for dep in deps.keys() {
            if dep == "python" {
                continue;
            }
            if let Some(to) = ids.get(&dep.to_ascii_lowercase()) {
                out.edge(from, to, Scope::Runtime, false);
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_pipfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "Pipfile.lock", e))?;
    let Some(root) = value.as_object() else {
        return Err(malformed_msg(
            path,
            "Pipfile.lock",
            "expected a JSON object",
        ));
    };
    for (section, scope) in [("default", Scope::Runtime), ("develop", Scope::Development)] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(packages.len(), path, "Pipfile.lock")?;
        for (name, entry) in packages {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let version = version.strip_prefix("==").unwrap_or(version);
            if version.is_empty() {
                continue;
            }
            out.add(
                "pypi",
                &normalize_pypi_name(name),
                version,
                scope,
                path,
                BTreeSet::new(),
            )?;
        }
    }
    Ok(())
}
/// PEP 503 PyPI name normalization plus extras stripping (`Requests[security]`),
/// so one package cannot split into several component identities or purls.
fn normalize_pypi_name(name: &str) -> String {
    let base = name.split('[').next().unwrap_or(name).trim();
    let mut normalized = String::with_capacity(base.len());
    let mut separator = false;
    for ch in base.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
            }
            separator = true;
        } else {
            separator = false;
            normalized.extend(ch.to_lowercase());
        }
    }
    normalized
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::input::{config, scan_path};
    use tempfile::tempdir;
    #[test]
    fn scans_poetry_and_pipfile_python_locks() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("poetry.lock"),
            concat!(
                "[metadata]\n",
                "lock-version = \"2.0\"\n",
                "\n",
                "[[package]]\n",
                "name = \"requests\"\n",
                "version = \"2.31.0\"\n",
                "optional = false\n",
                "category = \"main\"\n",
                "dependencies = { charset-normalizer = { version = \"^3.0\" } }\n",
                "\n",
                "[[package]]\n",
                "name = \"charset-normalizer\"\n",
                "version = \"3.3.2\"\n",
                "category = \"main\"\n",
                "\n",
                "[[package]]\n",
                "name = \"pytest\"\n",
                "version = \"7.4.2\"\n",
                "category = \"dev\"\n",
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
        assert_eq!(scope_of("requests"), Some(Scope::Runtime));
        assert_eq!(scope_of("pytest"), Some(Scope::Development));
        assert_eq!(inventory.components.len(), 3);
        assert!(inventory.dependencies.iter().any(|e| {
            inventory.components.get(&e.from).map(|c| c.name.as_str()) == Some("requests")
                && inventory.components.get(&e.to).map(|c| c.name.as_str())
                    == Some("charset-normalizer")
        }));

        let pipfile = tempdir().unwrap();
        fs::write(
            pipfile.path().join("Pipfile.lock"),
            r#"{"_meta":{"requires":{}},"default":{"requests":{"version":"==2.31.0","hashes":["sha256:abc"]}},"develop":{"pytest":{"version":"==7.4.2"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(pipfile.path(), &config()).unwrap();
        let scope_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.scope)
        };
        assert_eq!(scope_of("requests"), Some(Scope::Runtime));
        assert_eq!(scope_of("pytest"), Some(Scope::Development));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "requests" && c.version == "2.31.0")
        );
    }
}
