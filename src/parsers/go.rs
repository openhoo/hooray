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

/// The text after a go.mod directive keyword when `line` starts that
/// directive (`require x`, `require(`, `replace a => b`); `None` when the
/// keyword is absent or merely a prefix of a longer word.
fn go_directive_rest<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(directive)?;
    if rest.is_empty() {
        return Some("");
    }
    if rest.starts_with('(') {
        return Some(rest);
    }
    rest.strip_prefix(|c: char| c.is_whitespace())
        .map(str::trim_start)
}

pub(crate) fn parse_go_mod(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    /// Which directive block a `(`-opened section collects.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Block {
        Require,
        Replace,
        Exclude,
    }
    let mut in_block: Option<Block> = None;
    // The `go` directive declares the language version; an explicit
    // `toolchain` directive overrides it as the effective toolchain. Either
    // yields one `pkg:golang/stdlib@<version>` component so OSV stdlib
    // advisories (GO-*) match the toolchain the module builds with.
    let mut go_version: Option<&str> = None;
    let mut toolchain_version: Option<&str> = None;
    let mut module_path: Option<&str> = None;
    let mut requires = Vec::new();
    // `replace old [v] => new [v]` rules and `exclude name v` pins apply to
    // the recorded require versions; both may appear after the requires
    // they govern, so requirements are collected first and resolved after.
    let mut replaces = Vec::new();
    let mut excludes = Vec::new();
    for raw in utf8(bytes, path, "go.mod")?.lines() {
        let line = raw.split("//").next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if in_block.is_some() && line == ")" {
            in_block = None;
            continue;
        }
        if in_block.is_none() {
            // `require (` and `require(` both open a block; the same holds
            // for `replace (`/`exclude (` blocks.
            for (directive, block) in [
                ("require", Block::Require),
                ("replace", Block::Replace),
                ("exclude", Block::Exclude),
            ] {
                if let Some(rest) = go_directive_rest(line, directive) {
                    if rest == "(" {
                        in_block = Some(block);
                    } else {
                        match block {
                            Block::Require => requires.push(rest),
                            Block::Replace => replaces.push(rest),
                            Block::Exclude => excludes.push(rest),
                        }
                    }
                    break;
                }
            }
            if in_block.is_some() {
                continue;
            }
            if ["require", "replace", "exclude"]
                .iter()
                .any(|directive| go_directive_rest(line, directive).is_some())
            {
                continue;
            }
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
                Some("module") => {
                    let (Some(name), None) = (words.next(), words.next()) else {
                        return Err(malformed_msg(path, "go.mod", "invalid module directive"));
                    };
                    module_path = Some(name);
                    continue;
                }
                _ => {}
            }
            continue;
        }
        match in_block {
            Some(Block::Require) => requires.push(line),
            Some(Block::Replace) => replaces.push(line),
            Some(Block::Exclude) => excludes.push(line),
            None => {}
        }
    }
    if in_block.is_some() {
        return Err(malformed_msg(path, "go.mod", "unterminated require block"));
    }
    // Root-anchored identity: the module path names the asset like the
    // manifest-name claims of the npm/maven/bun parsers.
    if let Some(module) = module_path {
        out.claim_asset_identity(path, Some(module.to_owned()), None);
    }
    for requirement in requires {
        let mut parts = requirement.split_whitespace();
        let (Some(name), Some(version), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(malformed_msg(path, "go.mod", "invalid require directive"));
        };
        // `exclude name v` drops the pinned version from the build list.
        if excludes.iter().any(|excluded| {
            let mut parts = excluded.split_whitespace();
            parts.next() == Some(name) && parts.next() == Some(version) && parts.next().is_none()
        }) {
            continue;
        }
        // `replace old [v] => new v` substitutes the recorded module; local
        // path replacements (`./x`, `/x`, `../x`) are not registry
        // components and produce no inventory entry.
        let mut name = name;
        let mut version = version;
        for rule in &replaces {
            let Some((left, right)) = rule.split_once("=>") else {
                return Err(malformed_msg(path, "go.mod", "invalid replace directive"));
            };
            let mut left = left.split_whitespace();
            let (Some(old_name), old_version, None) = (left.next(), left.next(), left.next())
            else {
                return Err(malformed_msg(path, "go.mod", "invalid replace directive"));
            };
            if old_name != name || old_version.is_some_and(|v| v != version) {
                continue;
            }
            let mut right = right.split_whitespace();
            let (Some(new_name), new_version, None) = (right.next(), right.next(), right.next())
            else {
                return Err(malformed_msg(path, "go.mod", "invalid replace directive"));
            };
            if new_name.starts_with("./")
                || new_name.starts_with('/')
                || new_name.starts_with("../")
            {
                name = "";
                break;
            }
            name = new_name;
            if let Some(new_version) = new_version {
                version = new_version;
            }
            break;
        }
        if name.is_empty() {
            continue;
        }
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

    #[test]
    fn go_mod_require_block_without_space_and_module_identity() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\ngo 1.21\nrequire(\n\tdep.one v1.0.0\n)\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "example.com/app");
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "dep.one" && c.version == "v1.0.0")
        );
    }

    #[test]
    fn go_mod_replace_and_exclude_apply_to_inventory() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            concat!(
                "module example.com/app\n",
                "go 1.21\n",
                "require (\n",
                "\told.mod v1.0.0\n",
                "\tskip.mod v2.0.0\n",
                "\tlocal.mod v3.0.0\n",
                ")\n",
                "replace old.mod v1.0.0 => new.mod v1.5.0\n",
                "replace local.mod => ../local\n",
                "exclude skip.mod v2.0.0\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let names: Vec<_> = inventory
            .components
            .values()
            .map(|c| (c.name.as_str(), c.version.as_str()))
            .collect();
        assert!(names.contains(&("new.mod", "v1.5.0")));
        assert!(!names.iter().any(|(n, _)| *n == "old.mod"));
        assert!(!names.iter().any(|(n, _)| *n == "skip.mod"));
        assert!(!names.iter().any(|(n, _)| *n == "local.mod"));
    }
}
