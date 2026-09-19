use std::collections::{BTreeMap, BTreeSet};

use serde_yaml::Value as Yaml;

use super::{split_descriptor, yaml_str};
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};
struct YarnEntry {
    descriptors: Vec<String>,
    name: String,
    version: String,
    deps: Vec<(String, bool)>,
}

pub(crate) fn parse_yarn_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "yarn.lock")?;
    if text.starts_with("__metadata:") || text.contains("\n__metadata:") {
        parse_yarn_berry(path, text, out)
    } else {
        parse_yarn_classic(path, text, out)
    }
}

/// Classic yarn.lock entry state: header metadata, then dependency sections.
#[derive(Clone, Copy, PartialEq, Eq)]
enum YarnSection {
    Header,
    Dependencies,
    OptionalDependencies,
}
fn parse_yarn_classic(
    path: &str,
    text: &str,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut entries = Vec::new();
    let mut current: Option<YarnEntry> = None;
    let mut mode = YarnSection::Header;
    for raw in text.lines() {
        let trimmed = raw.trim_end().trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            let header = trimmed.strip_suffix(':').ok_or_else(|| {
                malformed_msg(
                    path,
                    "yarn.lock",
                    format!("invalid entry header {trimmed:?}"),
                )
            })?;
            if let Some(entry) = current.take() {
                insert_yarn_entry(&mut entries, path, entry)?;
            }
            let descriptors = yarn_descriptors(path, header, false)?;
            let name = yarn_name(path, &descriptors[0])?.to_owned();
            current = Some(YarnEntry {
                descriptors,
                name,
                version: String::new(),
                deps: Vec::new(),
            });
            mode = YarnSection::Header;
            continue;
        }
        let Some(entry) = current.as_mut() else {
            return Err(malformed_msg(
                path,
                "yarn.lock",
                format!("unexpected indented line {trimmed:?}"),
            ));
        };
        let next_section = if trimmed == "dependencies:" {
            Some(YarnSection::Dependencies)
        } else if trimmed == "optionalDependencies:" {
            Some(YarnSection::OptionalDependencies)
        } else {
            None
        };
        if let Some(section) = next_section {
            mode = section;
        } else {
            match mode {
                YarnSection::Header => {
                    if let Some(value) = trimmed.strip_prefix("version ") {
                        entry.version = value.trim().trim_matches('"').to_owned();
                    }
                }
                active => {
                    let Some((dep, requested)) = trimmed.split_once(char::is_whitespace) else {
                        return Err(malformed_msg(
                            path,
                            "yarn.lock",
                            "dependency has no selector",
                        ));
                    };
                    let dep = dep.trim_matches('"');
                    let requested = requested.trim().trim_matches('"');
                    if dep.is_empty() || requested.is_empty() {
                        return Err(malformed_msg(
                            path,
                            "yarn.lock",
                            "dependency has no selector",
                        ));
                    }
                    entry.deps.push((
                        format!("{dep}@{requested}"),
                        active == YarnSection::OptionalDependencies,
                    ));
                }
            }
        }
    }
    if let Some(entry) = current.take() {
        insert_yarn_entry(&mut entries, path, entry)?;
    }
    add_yarn_entries(path, entries, out)
}

fn parse_yarn_berry(path: &str, text: &str, out: &mut InventoryBuilder) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(text).map_err(|e| malformed(path, "yarn.lock", e))?;
    let Some(root) = doc.as_mapping() else {
        return Err(malformed_msg(
            path,
            "yarn.lock",
            "expected a mapping of lockfile entries",
        ));
    };
    let mut entries = Vec::new();
    for (key, value) in root {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        let Some(version) = value.get("version").and_then(yaml_str) else {
            // README promises malformed lockfiles fail rather than skip
            // entries; this is the same condition the classic parser
            // hard-errors on, so Berry must not silently drop the entry.
            return Err(malformed_msg(
                path,
                "yarn.lock",
                format!("entry {key} has no version"),
            ));
        };
        let descriptor = value
            .get("resolution")
            .and_then(Yaml::as_str)
            .unwrap_or(key);
        let Some((_, locator)) = split_descriptor(descriptor) else {
            return Err(malformed_msg(
                path,
                "yarn.lock",
                format!("entry {key} has invalid resolution {descriptor:?}"),
            ));
        };
        if locator.starts_with("workspace:")
            || locator.starts_with("link:")
            || locator.starts_with("portal:")
            || locator.starts_with("file:")
        {
            continue;
        }
        let name = yarn_name(path, descriptor)?.to_owned();
        let descriptors = yarn_descriptors(path, key, true)?;
        let mut deps: Vec<(String, bool)> = Vec::new();
        for (field, optional) in [
            ("dependencies", false),
            ("optionalDependencies", true),
            ("peerDependencies", false),
        ] {
            if let Some(map) = value.get(field).and_then(Yaml::as_mapping) {
                for (dep, requested) in map {
                    let (Some(dep), Some(requested)) = (dep.as_str(), requested.as_str()) else {
                        return Err(malformed_msg(
                            path,
                            "yarn.lock",
                            "invalid dependency selector",
                        ));
                    };
                    deps.push((
                        yarn_berry_descriptor(&format!("{dep}@{requested}")),
                        optional,
                    ));
                }
            }
        }
        insert_yarn_entry(
            &mut entries,
            path,
            YarnEntry {
                descriptors,
                name,
                version,
                deps,
            },
        )?;
    }
    add_yarn_entries(path, entries, out)
}

/// Resolve npm aliases using the same scoped descriptor split as the other npm parsers.
fn yarn_name<'a>(path: &str, descriptor: &'a str) -> Result<&'a str, InputError> {
    let (name, locator) = split_descriptor(descriptor)
        .filter(|(name, locator)| !name.is_empty() && !locator.is_empty())
        .ok_or_else(|| {
            malformed_msg(
                path,
                "yarn.lock",
                format!("invalid descriptor {descriptor:?}"),
            )
        })?;
    Ok(locator
        .strip_prefix("npm:")
        .and_then(split_descriptor)
        .map_or(name, |(target, _)| target))
}

fn yarn_berry_descriptor(descriptor: &str) -> String {
    if let Some((name, locator)) = split_descriptor(descriptor)
        && let Some(locator) = locator.strip_prefix("npm:")
    {
        return format!("{name}@{locator}");
    }
    descriptor.to_owned()
}

fn yarn_descriptors(path: &str, header: &str, berry: bool) -> Result<Vec<String>, InputError> {
    let mut quoted = false;
    let mut escaped = false;
    let mut descriptors = Vec::new();
    for descriptor in header.split(|ch| {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        }
        ch == ',' && !quoted
    }) {
        let descriptor = descriptor.trim();
        let descriptor = if descriptor.starts_with('"') {
            serde_json::from_str::<String>(descriptor)
                .map_err(|e| malformed(path, "yarn.lock", e))?
        } else {
            descriptor.to_owned()
        };
        yarn_name(path, &descriptor)?;
        descriptors.push(if berry {
            yarn_berry_descriptor(&descriptor)
        } else {
            descriptor
        });
    }
    Ok(descriptors)
}

fn insert_yarn_entry(
    entries: &mut Vec<YarnEntry>,
    path: &str,
    mut entry: YarnEntry,
) -> Result<(), InputError> {
    entry_bound(entries.len() + 1, path, "yarn.lock")?;
    if entry.version.is_empty() {
        return Err(malformed_msg(
            path,
            "yarn.lock",
            format!("entry {} has no version", entry.name),
        ));
    }
    entry.deps.sort();
    entry.deps.dedup();
    entries.push(entry);
    Ok(())
}

fn add_yarn_entries(
    path: &str,
    entries: Vec<YarnEntry>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    // The builder deduplicates resolved identities, not package names. Keep every
    // descriptor and dependency list even when several entries share an identity.
    let mut ids: BTreeMap<&str, ComponentId> = BTreeMap::new();
    let mut resolved = Vec::with_capacity(entries.len());
    for entry in &entries {
        let id = out.add(
            "npm",
            &entry.name,
            &entry.version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
        for descriptor in &entry.descriptors {
            if let Some(previous) = ids.insert(descriptor, id.clone())
                && previous != id
            {
                return Err(malformed_msg(
                    path,
                    "yarn.lock",
                    format!("conflicting descriptor {descriptor:?}"),
                ));
            }
        }
        resolved.push(id);
    }
    for (entry, from) in entries.iter().zip(&resolved) {
        for (dep, optional) in &entry.deps {
            if let Some(to) = ids.get(dep.as_str()) {
                out.edge(from, to, Scope::Runtime, *optional);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;
    #[test]
    fn yarn_multiversion_descriptors_select_exact_resolved_identities() {
        let classic = r#"acorn@^8.7.1, acorn@~8.8.0:
  version "8.8.1"
acorn@^8.8.2:
  version "8.10.0"
acorn@8.10.0:
  version "8.10.0"
old@1:
  version "1.0.0"
  dependencies:
    acorn "^8.7.1"
grouped@1:
  version "1.0.0"
  dependencies:
    acorn "~8.8.0"
new@1:
  version "1.0.0"
  optionalDependencies:
    acorn "^8.8.2"
exact@1:
  version "1.0.0"
  dependencies:
    acorn "8.10.0"
unmatched@1:
  version "1.0.0"
  dependencies:
    acorn "^9.0.0"
"#;
        let berry = r#"__metadata:
  version: 8
"acorn@npm:^8.7.1, acorn@npm:~8.8.0":
  version: 8.8.1
  resolution: "acorn@npm:8.8.1"
"acorn@npm:^8.8.2":
  version: 8.10.0
  resolution: "acorn@npm:8.10.0"
"acorn@npm:8.10.0":
  version: 8.10.0
  resolution: "acorn@npm:8.10.0"
"old@npm:1":
  version: 1.0.0
  dependencies:
    acorn: "^8.7.1"
"grouped@npm:1":
  version: 1.0.0
  dependencies:
    acorn: "npm:~8.8.0"
"new@npm:1":
  version: 1.0.0
  optionalDependencies:
    acorn: "^8.8.2"
"exact@npm:1":
  version: 1.0.0
  dependencies:
    acorn: "8.10.0"
"unmatched@npm:1":
  version: 1.0.0
  dependencies:
    acorn: "^9.0.0"
"#;
        for text in [classic, berry] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("yarn.lock"), text).unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            let identities: BTreeSet<_> = inventory
                .components
                .values()
                .map(|c| (c.name.as_str(), c.version.as_str()))
                .collect();
            assert_eq!(
                identities,
                BTreeSet::from([
                    ("acorn", "8.8.1"),
                    ("acorn", "8.10.0"),
                    ("old", "1.0.0"),
                    ("grouped", "1.0.0"),
                    ("new", "1.0.0"),
                    ("exact", "1.0.0"),
                    ("unmatched", "1.0.0"),
                ])
            );
            assert_eq!(inventory.components.len(), identities.len());
            let edges: BTreeSet<_> = inventory
                .dependencies
                .iter()
                .map(|edge| {
                    let from = &inventory.components[&edge.from];
                    let to = &inventory.components[&edge.to];
                    (
                        from.name.as_str(),
                        to.name.as_str(),
                        to.version.as_str(),
                        edge.optional,
                    )
                })
                .collect();
            assert_eq!(
                edges,
                BTreeSet::from([
                    ("old", "acorn", "8.8.1", false),
                    ("grouped", "acorn", "8.8.1", false),
                    ("new", "acorn", "8.10.0", true),
                    ("exact", "acorn", "8.10.0", false),
                ])
            );
        }
    }

    #[test]
    fn yarn_scoped_aliases_and_quoted_grouped_descriptors_keep_edges() {
        for text in [
            r#""alias@npm:@scope/pkg@^1", "alias@npm:@scope/pkg@~1.2":
  version "1.2.0"
"@scope/pkg@^2":
  version "2.1.0"
consumer@1:
  version "1.0.0"
  dependencies:
    alias "npm:@scope/pkg@~1.2"
  optionalDependencies:
    "@scope/pkg" "^2"
"#,
            r#"__metadata:
  version: 8
"alias@npm:@scope/pkg@^1, alias@npm:@scope/pkg@~1.2":
  version: 1.2.0
  resolution: "@scope/pkg@npm:1.2.0"
"@scope/pkg@npm:^2":
  version: 2.1.0
  resolution: "@scope/pkg@npm:2.1.0"
"consumer@npm:1":
  version: 1.0.0
  dependencies:
    alias: "npm:@scope/pkg@~1.2"
  optionalDependencies:
    "@scope/pkg": "^2"
"#,
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("yarn.lock"), text).unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert_eq!(inventory.components.len(), 3);
            assert!(!inventory.components.values().any(|c| c.name == "alias"));
            let edges: BTreeSet<_> = inventory
                .dependencies
                .iter()
                .map(|edge| {
                    let from = &inventory.components[&edge.from];
                    let to = &inventory.components[&edge.to];
                    (
                        from.name.as_str(),
                        to.name.as_str(),
                        to.version.as_str(),
                        edge.optional,
                    )
                })
                .collect();
            assert_eq!(
                edges,
                BTreeSet::from([
                    ("consumer", "@scope/pkg", "1.2.0", false),
                    ("consumer", "@scope/pkg", "2.1.0", true),
                ])
            );
        }
    }

    #[test]
    fn yarn_classic_malformed_entries_and_conflicting_descriptors_fail_closed() {
        for text in [
            "a@1:\n  resolved \"url\"\n",
            "a@1, broken:\n  version \"1.0.0\"\n",
            "a@1:\n  version \"1.0.0\"\n  dependencies:\n    b\n",
            "a@1:\n  version \"1.0.0\"\na@1:\n  version \"2.0.0\"\n",
            "__metadata:\n  version: 8\n\"a@npm:1, a@npm:2\":\n  version: 1.0.0\n\"a@npm:2\":\n  version: 2.0.0\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("yarn.lock"), text).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed {
                        format: "yarn.lock",
                        ..
                    })
                ),
                "expected malformed yarn.lock for {text:?}"
            );
        }
    }

    #[test]
    fn scans_yarn_lock_classic_and_berry_formats() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("yarn.lock"),
            concat!(
                "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT.\n",
                "\n",
                "left-pad@^1.3.0:\n",
                "  version \"1.3.0\"\n",
                "  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\"\n",
                "  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8yNrjeoQk1w==\n",
                "  dependencies:\n",
                "    kind-of \"^6.0.3\"\n",
                "\n",
                "kind-of@^6.0.3:\n",
                "  version \"6.0.3\"\n",
                "\n",
                "\"@babel/core@^7.0.0\":\n",
                "  version \"7.23.0\"\n",
                "  dependencies:\n",
                "    \"@babel/code-generator\" \"^7.22.0\"\n",
                "  optionalDependencies:\n",
                "    fsevents \"^2.3.2\"\n",
                "\n",
                "\"@babel/code-generator@^7.22.0\":\n",
                "  version \"7.22.5\"\n",
                "\n",
                "fsevents@^2.3.2:\n",
                "  version \"2.3.2\"\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "@babel/core" && c.version == "7.23.0")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "left-pad" && c.version == "1.3.0")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "kind-of" && c.version == "6.0.3")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "@babel/code-generator" && c.version == "7.22.5")
        );
        assert_eq!(inventory.components.len(), 5);
        let edges: BTreeSet<_> = inventory
            .dependencies
            .iter()
            .map(|edge| {
                let from = &inventory.components[&edge.from];
                let to = &inventory.components[&edge.to];
                (
                    from.name.as_str(),
                    to.name.as_str(),
                    to.version.as_str(),
                    edge.optional,
                )
            })
            .collect();
        assert_eq!(
            edges,
            BTreeSet::from([
                ("left-pad", "kind-of", "6.0.3", false),
                ("@babel/core", "@babel/code-generator", "7.22.5", false),
                ("@babel/core", "fsevents", "2.3.2", true),
            ])
        );

        let berry = tempdir().unwrap();
        fs::write(
            berry.path().join("yarn.lock"),
            concat!(
                "# This file is generated by running \"yarn install\" inside your project.\n",
                "__metadata:\n",
                "  version: 8\n",
                "  cacheKey: 10c0\n",
                "\n",
                "\"left-pad@npm:1.3.0\":\n",
                "  version: 1.3.0\n",
                "  resolution: \"left-pad@npm:1.3.0\"\n",
                "  dependencies:\n",
                "    kind-of: ^6.0.3\n",
                "  languageName: node\n",
                "  linkType: hard\n",
                "\n",
                "\"kind-of@npm:^6.0.3\":\n",
                "  version: 6.0.3\n",
                "  resolution: \"kind-of@npm:6.0.3\"\n",
                "  languageName: node\n",
                "  linkType: hard\n",
                "\n",
                "\"my-app@workspace:.\":\n",
                "  version: 0.0.0-use.local\n",
                "  resolution: \"my-app@workspace:.\"\n",
                "  dependencies:\n",
                "    left-pad: ^1.3.0\n",
                "  languageName: unknown\n",
                "  linkType: soft\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(berry.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 2);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "left-pad" && c.version == "1.3.0")
        );
        assert!(!inventory.components.values().any(|c| c.name == "my-app"));
        assert_eq!(inventory.dependencies.len(), 1);
    }
    #[test]
    fn yarn_berry_malformed_entries_fail_closed() {
        let missing_version =
            "__metadata:\n  version: 8\n\"a@npm:1.0\":\n  resolution: \"a@npm:1.0\"\n";
        let bad_resolution = "__metadata:\n  version: 8\n\"broken\":\n  version: 1.0\n";
        for text in [missing_version, bad_resolution] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("yarn.lock"), text).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(
                matches!(
                    error,
                    InputError::Malformed { format, .. } if format == "yarn.lock"
                ),
                "expected malformed yarn.lock for {text:?}"
            );
        }
    }
}
