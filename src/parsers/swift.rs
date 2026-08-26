use std::collections::BTreeSet;

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg};
use crate::model::Scope;
pub(crate) fn parse_package_resolved(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "Package.resolved", e))?;
    let pins = value
        .get("pins")
        .and_then(Value::as_array)
        .or_else(|| {
            value
                .get("object")
                .and_then(|object| object.get("pins"))
                .and_then(Value::as_array)
        })
        .ok_or_else(|| malformed_msg(path, "Package.resolved", "missing pins array"))?;
    entry_bound(pins.len(), path, "Package.resolved")?;
    for pin in pins {
        let name = pin
            .get("identity")
            .or_else(|| pin.get("package"))
            .and_then(Value::as_str);
        let version = pin
            .get("state")
            .and_then(|state| state.get("version"))
            .and_then(Value::as_str);
        let (Some(name), Some(version)) = (name, version) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.add(
            "swift",
            name,
            version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}
