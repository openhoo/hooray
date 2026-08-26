use std::collections::{BTreeMap, BTreeSet};

use serde_yaml::Value as Yaml;

use super::split_descriptor;
use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::{ComponentId, Scope};
type YarnEntries = BTreeMap<String, (String, Vec<(String, bool)>)>;
type YarnCurrent = (String, String, Vec<(String, bool)>);

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
    let mut entries: YarnEntries = BTreeMap::new();
    let mut current: Option<YarnCurrent> = None;
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
            if let Some((name, version, deps)) = current.take() {
                insert_yarn_entry(&mut entries, path, name, version, deps)?;
            }
            let descriptor = header
                .split(',')
                .next()
                .unwrap_or(header)
                .trim()
                .trim_matches('"');
            let Some((name, _)) = split_descriptor(descriptor) else {
                return Err(malformed_msg(
                    path,
                    "yarn.lock",
                    format!("invalid descriptor {descriptor:?}"),
                ));
            };
            current = Some((name.to_owned(), String::new(), Vec::new()));
            mode = YarnSection::Header;
            continue;
        }
        let Some((_, version, deps)) = current.as_mut() else {
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
                        *version = value.trim().trim_matches('"').to_owned();
                    }
                }
                active => {
                    if let Some(dep) = trimmed.split_whitespace().next() {
                        deps.push((dep.to_owned(), active == YarnSection::OptionalDependencies));
                    }
                }
            }
        }
    }
    if let Some((name, version, deps)) = current.take() {
        insert_yarn_entry(&mut entries, path, name, version, deps)?;
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
    let mut entries: YarnEntries = BTreeMap::new();
    for (key, value) in root {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        let Some(version) = value.get("version").and_then(Yaml::as_str) else {
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
        let Some((name, locator)) = split_descriptor(descriptor) else {
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
        let mut deps: Vec<(String, bool)> = Vec::new();
        for (field, optional) in [("dependencies", false), ("optionalDependencies", true)] {
            if let Some(map) = value.get(field).and_then(Yaml::as_mapping) {
                for (dep, _) in map {
                    if let Some(dep) = dep.as_str() {
                        deps.push((dep.to_owned(), optional));
                    }
                }
            }
        }
        deps.sort();
        deps.dedup();
        entry_bound(entries.len() + 1, path, "yarn.lock")?;
        entries
            .entry(name.to_owned())
            .or_insert((version.to_owned(), deps));
    }
    add_yarn_entries(path, entries, out)
}

fn insert_yarn_entry(
    entries: &mut YarnEntries,
    path: &str,
    name: String,
    version: String,
    mut deps: Vec<(String, bool)>,
) -> Result<(), InputError> {
    entry_bound(entries.len() + 1, path, "yarn.lock")?;
    if version.is_empty() {
        return Err(malformed_msg(
            path,
            "yarn.lock",
            format!("entry {name} has no version"),
        ));
    }
    deps.sort();
    deps.dedup();
    entries.entry(name).or_insert((version, deps));
    Ok(())
}

fn add_yarn_entries(
    path: &str,
    entries: YarnEntries,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    for (name, (version, _)) in &entries {
        let id = out.add("npm", name, version, Scope::Runtime, path, BTreeSet::new())?;
        ids.insert(name.clone(), id);
    }
    for (name, (_, deps)) in &entries {
        let Some(from) = ids.get(name) else { continue };
        for (dep, optional) in deps {
            if let Some(to) = ids.get(dep) {
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
            !inventory
                .components
                .values()
                .any(|c| c.name == "@babel/code-generator")
        );
        assert_eq!(inventory.components.len(), 4);
        assert_eq!(inventory.dependencies.len(), 2);
        assert!(inventory.dependencies.iter().any(|e| e.optional));

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
