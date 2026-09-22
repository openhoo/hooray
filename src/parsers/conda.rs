use std::collections::BTreeSet;

use serde_yaml::Value as Yaml;

use super::{python::parse_requirements, yaml_doc};
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_conda_environment(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = yaml_doc(
        utf8(bytes, path, "environment.yml")?,
        path,
        "environment.yml",
    )?;
    let Some(dependencies) = doc.get("dependencies").and_then(Yaml::as_sequence) else {
        return Err(malformed_msg(
            path,
            "environment.yml",
            "missing dependencies list",
        ));
    };
    entry_bound(dependencies.len(), path, "environment.yml")?;
    let mut pip = Vec::new();
    for entry in dependencies {
        if let Some(spec) = entry.as_str() {
            add_conda_spec(path, spec, out)?;
        } else if let Some(lines) = entry.get("pip").and_then(Yaml::as_sequence) {
            for line in lines {
                if let Some(cleaned) = line.as_str().and_then(clean_pip_requirement) {
                    pip.push(cleaned);
                }
            }
        }
    }
    if !pip.is_empty() {
        let requirements = pip.join("\n");
        parse_requirements(path, requirements.as_bytes(), out)?;
    }
    Ok(())
}

fn add_conda_spec(path: &str, spec: &str, out: &mut InventoryBuilder) -> Result<(), InputError> {
    let spec = spec.split('#').next().unwrap_or(spec).trim();
    let spec = spec.rsplit("::").next().unwrap_or(spec);
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
        .unwrap_or(spec.len());
    let name = &spec[..name_end];
    if name.is_empty() {
        return Ok(());
    }
    // Conda matchspecs pin with `=`/`==`; everything else (`>=2,<3`, `1.24.*`,
    // bare names) is a constraint, not a resolved version. Recording the raw
    // constraint text — or `*` when the spec carries none — lets
    // `concrete_version_specifier` emit a versionless `pkg:conda/<name>` purl
    // instead of fabricating a floor version (composer.json precedent).
    let constraint = spec[name_end..].trim();
    let version = match constraint
        .strip_prefix("==")
        .or_else(|| constraint.strip_prefix('='))
    {
        // `pkg==1.24.2=py310h…` pins version plus build string; the second
        // `=` separates the build, so keep only the version part.
        Some(pinned) => pinned.trim().split('=').next().unwrap_or(pinned).to_owned(),
        None if constraint.is_empty() => "*".to_owned(),
        None => constraint.to_owned(),
    };
    if version.is_empty() {
        return Ok(());
    }
    entry_bound(out.components.len() + 1, path, "environment.yml")?;
    out.add(
        "conda",
        name,
        &version,
        Scope::Runtime,
        path,
        BTreeSet::new(),
    )?;
    Ok(())
}

pub(crate) fn clean_pip_requirement(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("--")
        || trimmed.starts_with("-r")
        || trimmed.starts_with("-e")
    {
        return None;
    }
    let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
    // parse_requirements accepts unpinned and constrained lines, so every
    // non-option pip line is forwarded verbatim.
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn conda_version_build_pins_keep_the_version() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("environment.yml"),
            "dependencies:\n  - numpy==1.24.2=py310h12345\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let numpy = inventory
            .components
            .values()
            .find(|c| c.name == "numpy")
            .unwrap();
        assert_eq!(numpy.version, "1.24.2");
        assert_eq!(numpy.purl, "pkg:conda/numpy@1.24.2");
    }
}
