use std::collections::BTreeSet;

use serde_yaml::Value as Yaml;

use super::python::parse_requirements;
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_conda_environment(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "environment.yml")?)
        .map_err(|e| malformed(path, "environment.yml", e))?;
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
    let version = spec[name_end..]
        .trim_start_matches(|c: char| "=<>!~ ".contains(c))
        .split([',', ';', ' ', '\t'])
        .next()
        .unwrap_or_default();
    // Versionless specs such as `- pip` are valid environment.yml content
    // hooray cannot pin to a version, so they remain a deliberate lenient
    // skip; only specs yielding both a name and a version reach `out.add`
    // below.
    if version.is_empty() {
        return Ok(());
    }
    entry_bound(out.components.len() + 1, path, "environment.yml")?;
    out.add(
        "conda",
        name,
        version,
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
    trimmed.contains("==").then(|| trimmed.to_owned())
}
