use std::collections::BTreeSet;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_go_mod(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut in_require = false;
    for raw in utf8(bytes, path, "go.mod")?.lines() {
        let line = raw.split("//").next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line == "require (" {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }
        let requirement = if in_require {
            Some(line)
        } else {
            line.strip_prefix("require ").map(str::trim)
        };
        let Some(requirement) = requirement else {
            continue;
        };
        let mut parts = requirement.split_whitespace();
        let (Some(name), Some(version), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(malformed_msg(path, "go.mod", "invalid require directive"));
        };
        entry_bound(out.components.len() + 1, path, "go.mod")?;
        out.add(
            "golang",
            name,
            version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    if in_require {
        return Err(malformed_msg(path, "go.mod", "unterminated require block"));
    }
    Ok(())
}
