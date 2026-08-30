use std::collections::BTreeSet;

use reqwest::Url;
use serde_json::Value;

use crate::input::{
    InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, package_url,
};
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
        let repository = pin
            .get("location")
            .or_else(|| pin.get("repositoryURL"))
            .and_then(Value::as_str)
            .and_then(swift_purl_name);
        match repository {
            Some(purl_name) => out.add_with_purl(
                name,
                version,
                package_url("swift", &purl_name, version),
                Scope::Runtime,
                path,
                BTreeSet::new(),
            )?,
            // The Swift purl type requires a source-host/user namespace. Keep
            // source-less pins in inventory without emitting an invalid Swift
            // purl that makes OSV reject the complete query batch.
            None => out.add(
                "generic",
                name,
                version,
                Scope::Runtime,
                path,
                BTreeSet::new(),
            )?,
        };
    }
    Ok(())
}

fn swift_purl_name(location: &str) -> Option<String> {
    let location = location.trim();
    let normalized;
    let location = if location.contains("://") {
        location
    } else {
        let (authority, path) = location.split_once(':')?;
        if !authority.contains('@') || path.is_empty() {
            return None;
        }
        normalized = format!("ssh://{authority}/{path}");
        &normalized
    };
    let url = Url::parse(location).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "git" | "ssh") {
        return None;
    }
    let host = url.host_str()?;
    let mut segments = url
        .path_segments()?
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return None;
    }
    let name = segments.pop()?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    Some(format!("{host}/{}/{name}", segments.join("/")))
}

#[cfg(test)]
mod tests {
    use super::swift_purl_name;

    #[test]
    fn derives_required_namespace_from_remote_repository() {
        assert_eq!(
            swift_purl_name("https://github.com/apple/swift-collections.git").as_deref(),
            Some("github.com/apple/swift-collections")
        );
        assert_eq!(
            swift_purl_name("git@github.com:Alamofire/Alamofire.git").as_deref(),
            Some("github.com/Alamofire/Alamofire")
        );
        assert_eq!(swift_purl_name("../LocalPackage"), None);
    }
}
