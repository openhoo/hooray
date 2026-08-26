use std::collections::BTreeSet;

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg};
use crate::model::Scope;
pub(crate) fn parse_composer_json(
    path: &str,
    bytes: &[u8],
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
        out.asset.version = Some(version.to_owned());
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
