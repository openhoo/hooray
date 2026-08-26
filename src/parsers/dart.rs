use std::collections::BTreeSet;

use serde_yaml::Value as Yaml;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;
pub(crate) fn parse_pubspec_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "pubspec.lock")?)
        .map_err(|e| malformed(path, "pubspec.lock", e))?;
    let Some(packages) = doc.get("packages").and_then(Yaml::as_mapping) else {
        return Err(malformed_msg(
            path,
            "pubspec.lock",
            "missing packages section",
        ));
    };
    entry_bound(packages.len(), path, "pubspec.lock")?;
    for (key, entry) in packages {
        // Source is inspected first so non-hosted entries stay lenient even
        // with odd keys. Valid pubspec.lock variants record sources hooray
        // cannot version — `git` (url/resolved-ref/path), `sdk` (flutter or
        // dart SDK packages), and relative `path` overrides — so those
        // entries are deliberately skipped instead of failing the scan.
        let Some(source) = entry.get("source").and_then(Yaml::as_str) else {
            continue;
        };
        if source != "hosted" {
            continue;
        }
        let Some(name) = key.as_str() else {
            return Err(malformed_msg(
                path,
                "pubspec.lock",
                "hosted package key is not a string",
            ));
        };
        let Some(version) = entry.get("version").and_then(Yaml::as_str) else {
            return Err(malformed_msg(
                path,
                "pubspec.lock",
                "hosted package has no version",
            ));
        };
        let dependency = entry
            .get("dependency")
            .and_then(Yaml::as_str)
            .unwrap_or_default();
        let scope = if dependency.ends_with("dev") {
            Scope::Development
        } else {
            Scope::Runtime
        };
        out.add("pub", name, version, scope, path, BTreeSet::new())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn hosted_pubspec_entries_without_version_fail_closed() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pubspec.lock"),
            "packages:\n  meta:\n    source: hosted\n    description: hosted package\n",
        )
        .unwrap();
        let error = scan_path(dir.path(), &config()).unwrap_err();
        assert!(
            matches!(
                &error,
                InputError::Malformed { format, message, .. }
                    if *format == "pubspec.lock" && *message == "hosted package has no version"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn git_pubspec_sources_remain_lenient_skips() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pubspec.lock"),
            "packages:\n  tool:\n    source: git\n    description:\n      url: \"https://github.com/example/tool.git\"\n      resolved-ref: \"abcdef123456\"\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(inventory.components.is_empty());
    }
}
