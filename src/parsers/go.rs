use std::collections::BTreeSet;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;

/// A `go`/`toolchain` directive version: `1.21`, `1.24.11`, or a pre-release
/// like `1.26rc1`. Anything else is a malformed directive, not a version the
/// OSV Go ecosystem could match.
fn is_go_version(version: &str) -> bool {
    let (base, rc) = match version.split_once("rc") {
        Some((base, rc)) if !rc.is_empty() => (base, Some(rc)),
        _ => (version, None),
    };
    let mut numbers = base.split('.');
    let valid_base = matches!(numbers.next(), Some(major) if !major.is_empty() && major.bytes().all(|b| b.is_ascii_digit()))
        && matches!(numbers.next(), Some(minor) if !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
        && numbers
            .next()
            .is_none_or(|patch| !patch.is_empty() && patch.bytes().all(|b| b.is_ascii_digit()))
        && numbers.next().is_none();
    valid_base && rc.is_none_or(|rc| rc.bytes().all(|b| b.is_ascii_digit()))
}

pub(crate) fn parse_go_mod(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut in_require = false;
    // The `go` directive declares the language version; an explicit
    // `toolchain` directive overrides it as the effective toolchain. Either
    // yields one `pkg:golang/stdlib@<version>` component so OSV stdlib
    // advisories (GO-*) match the toolchain the module builds with.
    let mut go_version: Option<&str> = None;
    let mut toolchain_version: Option<&str> = None;
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
        if !in_require {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("go") => {
                    let (Some(version), None) = (words.next(), words.next()) else {
                        return Err(malformed_msg(path, "go.mod", "invalid go directive"));
                    };
                    if !is_go_version(version) {
                        return Err(malformed_msg(path, "go.mod", "invalid go directive"));
                    }
                    go_version = Some(version);
                    continue;
                }
                Some("toolchain") => {
                    let (Some(name), None) = (words.next(), words.next()) else {
                        return Err(malformed_msg(path, "go.mod", "invalid toolchain directive"));
                    };
                    // `toolchain default`/`none` declare no concrete
                    // toolchain and produce no component.
                    if name != "default" && name != "none" {
                        let Some(version) = name.strip_prefix("go") else {
                            return Err(malformed_msg(
                                path,
                                "go.mod",
                                "invalid toolchain directive",
                            ));
                        };
                        if !is_go_version(version) {
                            return Err(malformed_msg(
                                path,
                                "go.mod",
                                "invalid toolchain directive",
                            ));
                        }
                        toolchain_version = Some(version);
                    }
                    continue;
                }
                _ => {}
            }
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
    if let Some(version) = toolchain_version.or(go_version) {
        entry_bound(out.components.len() + 1, path, "go.mod")?;
        out.add(
            "golang",
            "stdlib",
            version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn go_directive_yields_stdlib_component() {
        let dir = tempdir().unwrap();
        // Mirrors gitleaks/gitleaks go.mod (commit b58d3f1): `go 1.24.11`.
        fs::write(
            dir.path().join("go.mod"),
            concat!(
                "module github.com/gitleaks/gitleaks/v8\n",
                "\n",
                "go 1.24.11\n",
                "\n",
                "require (\n",
                "\tgolang.org/x/crypto v0.35.0\n",
                ")\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let stdlib = inventory
            .components
            .values()
            .find(|c| c.name == "stdlib")
            .expect("stdlib component");
        assert_eq!(stdlib.purl, "pkg:golang/stdlib@1.24.11");
        assert_eq!(stdlib.version, "1.24.11");
        assert_eq!(inventory.components.len(), 2);
    }

    #[test]
    fn toolchain_directive_overrides_go_version() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.16\n\ntoolchain go1.21.0\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let stdlib = inventory
            .components
            .values()
            .find(|c| c.name == "stdlib")
            .expect("stdlib component");
        assert_eq!(stdlib.version, "1.21.0");
        assert_eq!(inventory.components.len(), 1);
    }

    #[test]
    fn missing_go_directive_and_default_toolchain_emit_no_stdlib() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ntoolchain default\n\nrequire example.com/dep v1.0.0\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(!inventory.components.values().any(|c| c.name == "stdlib"));
    }

    #[test]
    fn malformed_go_and_toolchain_directives_fail_closed() {
        for contents in [
            "module example.com/app\ngo\n",
            "module example.com/app\ngo latest\n",
            "module example.com/app\ngo 1.21 extra\n",
            "module example.com/app\ngo 1.21\ntoolchain bogus\n",
            "module example.com/app\ngo 1.21\ntoolchain gofoo\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("go.mod"), contents).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { format, .. }) if format == "go.mod"
                ),
                "expected malformed for: {contents}"
            );
        }
    }
}
