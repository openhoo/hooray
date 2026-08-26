use std::collections::BTreeSet;

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, malformed, malformed_msg};
use crate::model::Scope;

use super::{LockComponents, resolve_lock_component};
pub(crate) fn parse_nuget_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "packages.lock.json", e))?;
    let frameworks = value
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed_msg(path, "packages.lock.json", "missing dependencies object"))?;
    let mut ids = LockComponents::new();
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    malformed_msg(
                        path,
                        "packages.lock.json",
                        "package missing resolved version",
                    )
                })?;
            let scope = match package.get("type").and_then(Value::as_str) {
                Some("Direct") => Scope::Runtime,
                Some("Transitive") => Scope::Runtime,
                _ => Scope::Unknown,
            };
            let id = out.add(
                "nuget",
                &name.to_ascii_lowercase(),
                version,
                scope,
                path,
                BTreeSet::new(),
            )?;
            ids.entry(name.to_ascii_lowercase())
                .or_default()
                .insert(version.to_owned(), id);
        }
    }
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name_lower = name.to_ascii_lowercase();
            let Some(from) = ids
                .get(&name_lower)
                .and_then(|versions| versions.get(version))
            else {
                continue;
            };
            for (dependency, constraint) in package
                .get("dependencies")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let requested = constraint.as_str().unwrap_or_default();
                let target = ids
                    .get(&dependency.to_ascii_lowercase())
                    .and_then(|versions| resolve_lock_component(versions, Some(requested)));
                if let Some(to) = target {
                    out.edge(from, &to, Scope::Runtime, false);
                }
            }
        }
    }
    Ok(())
}
