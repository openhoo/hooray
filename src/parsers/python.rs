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
            add_requirement(path, line, out)?;
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

/// Records one PEP 508 requirement line. `==`/`===` pins keep their concrete
/// version; every other specifier (`>=`, `~=`, `!=`, extras, `@` direct
/// references, bare names) is stored verbatim — or as `*` when absent — so
/// `concrete_version_specifier` maps it to a versionless purl instead of
/// fabricating a floor version. Environment markers (`;`) and trailing
/// `--hash`/`--index-url` options are stripped. Bare URLs and VCS lines
/// carry no package name and are skipped; a missing name otherwise fails
/// closed.
fn add_requirement(path: &str, line: &str, out: &mut InventoryBuilder) -> Result<(), InputError> {
    let requirement = line.split(';').next().unwrap_or(line).trim();
    if requirement.is_empty() {
        return Ok(());
    }
    let name_end = requirement
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(requirement.len());
    let name = &requirement[..name_end];
    let mut rest = &requirement[name_end..];
    if name.is_empty() {
        // `https://…`, `./path` and bare URLs are valid requirement lines
        // that name no package.
        if requirement.contains("://") || requirement.starts_with('.') {
            return Ok(());
        }
        return Err(malformed_msg(
            path,
            "requirements.txt",
            format!("requirement missing package name: {line:?}"),
        ));
    }
    // Bare URLs (`https://…`) and VCS URLs (`git+https://…`, `hg+…`,
    // `svn+…`, `bzr+…`) name no package.
    if rest.starts_with("://") || (rest.starts_with('+') && rest.contains("://")) {
        return Ok(());
    }
    // Extras (`requests[security]`) belong to the name, not the specifier.
    if let Some(extras) = rest.strip_prefix('[') {
        match extras.find(']') {
            Some(close) => rest = &extras[close + 1..],
            None => {
                return Err(malformed_msg(
                    path,
                    "requirements.txt",
                    format!("unterminated extras in {line:?}"),
                ));
            }
        }
    }
    // Options such as `--hash=…` may follow the specifier; keep only the
    // specifier tokens.
    let specifier = rest
        .split_whitespace()
        .take_while(|token| !token.starts_with('-'))
        .collect::<Vec<_>>()
        .join(" ");
    let version = if let Some(pinned) = specifier
        .strip_prefix("===")
        .or_else(|| specifier.strip_prefix("=="))
    {
        pinned.trim().to_owned()
    } else if specifier.is_empty() {
        "*".to_owned()
    } else {
        specifier
    };
    if version.is_empty() {
        return Err(malformed_msg(
            path,
            "requirements.txt",
            format!("requirement {name:?} has an empty version"),
        ));
    }
    entry_bound(out.components.len() + 1, path, "requirements.txt")?;
    out.add(
        "pypi",
        &normalize_pypi_name(name),
        &version,
        Scope::Runtime,
        path,
        BTreeSet::new(),
    )?;
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
        // Poetry 2.x locks record `groups` (e.g. ["main", "dev"]) instead of
        // the 1.x `category` key. Group membership decides scope: `main`
        // membership means runtime, otherwise the package is development-only;
        // `optional = true` marks extras/optional-group installs in both
        // formats. Legacy `category`/`optional` remain the fallback for 1.x.
        let groups = package.get("groups").and_then(toml::Value::as_array);
        let category = package
            .get("category")
            .and_then(toml::Value::as_str)
            .unwrap_or("main");
        let optional = package
            .get("optional")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let scope = if let Some(groups) = groups {
            let in_main = groups.iter().any(|group| group.as_str() == Some("main"));
            if optional {
                Scope::Optional
            } else if in_main {
                Scope::Runtime
            } else {
                Scope::Development
            }
        } else if category == "dev" {
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

    #[test]
    fn poetry_lock_groups_drive_scope() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("poetry.lock"),
            concat!(
                "[[package]]\n",
                "name = \"requests\"\n",
                "version = \"2.31.0\"\n",
                "groups = [\"main\"]\n",
                "\n",
                "[[package]]\n",
                "name = \"pytest\"\n",
                "version = \"7.4.2\"\n",
                "groups = [\"dev\"]\n",
                "\n",
                "[[package]]\n",
                "name = \"coverage\"\n",
                "version = \"7.5.0\"\n",
                "groups = [\"main\", \"dev\"]\n",
                "\n",
                "[[package]]\n",
                "name = \"extra-only\"\n",
                "version = \"1.0\"\n",
                "optional = true\n",
                "groups = [\"main\"]\n",
                "\n",
                "[metadata]\n",
                "lock-version = \"2.1\"\n",
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
        // main membership wins even when a dev group is also present.
        assert_eq!(scope_of("coverage"), Some(Scope::Runtime));
        assert_eq!(scope_of("extra-only"), Some(Scope::Optional));
        assert_eq!(inventory.components.len(), 4);
    }

    #[test]
    fn requirements_txt_accepts_unpinned_and_constrained_lines() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            concat!(
                "requests==2.31.0\n",
                "imagesize>=1.4.1\n",
                "myst-parser[linkify]>=4.0.0\n",
                "Sphinx\n",
                "jinja2>=3.1.4; python_version >= \"3.9\"\n",
                "tomli ; python_version < \"3.11\"\n",
                "-e .\n",
                "-r other.txt\n",
                "--index-url https://example.com/simple\n",
                "git+https://github.com/org/repo.git@abc\n",
                "https://example.com/pkg-1.0.tar.gz\n",
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
        let purl_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.purl.clone())
        };
        assert_eq!(version_of("requests").as_deref(), Some("2.31.0"));
        assert_eq!(
            purl_of("requests").as_deref(),
            Some("pkg:pypi/requests@2.31.0")
        );
        // Constraints are recorded verbatim and produce versionless purls.
        assert_eq!(version_of("imagesize").as_deref(), Some(">=1.4.1"));
        assert_eq!(purl_of("imagesize").as_deref(), Some("pkg:pypi/imagesize"));
        assert_eq!(version_of("myst-parser").as_deref(), Some(">=4.0.0"));
        assert_eq!(version_of("jinja2").as_deref(), Some(">=3.1.4"));
        // Bare names become versionless components instead of aborting.
        assert_eq!(version_of("sphinx").as_deref(), Some("*"));
        assert_eq!(purl_of("sphinx").as_deref(), Some("pkg:pypi/sphinx"));
        assert_eq!(version_of("tomli").as_deref(), Some("*"));
        // Options, editable/path includes, and bare URLs produce nothing.
        assert_eq!(inventory.components.len(), 6);
    }
}
