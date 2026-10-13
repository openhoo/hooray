//! Second-pass controls for workspace admission and cross-record identities.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use hooray::config::Config;
use hooray::input::scan_path;
use hooray::model::Scope;

fn zipped_directory(root: &Path) -> Vec<u8> {
    fn append(root: &Path, directory: &Path, writer: &mut zip::ZipWriter<Cursor<Vec<u8>>>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                append(root, &path, writer);
            } else {
                writer
                    .start_file(
                        path.strip_prefix(root).unwrap().to_str().unwrap(),
                        zip::write::SimpleFileOptions::default(),
                    )
                    .unwrap();
                writer.write_all(&fs::read(path).unwrap()).unwrap();
            }
        }
    }
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    append(root, root, &mut writer);
    writer.finish().unwrap().into_inner()
}

#[test]
fn ancestor_node_locks_cover_only_their_actual_workspace_members() {
    let cases = [
        (
            "package-lock.json",
            r#"{"name":"root","packages":{"":{},"apps/member":{"name":"member","version":"1.0.0","dependencies":{"member-dep":"^2"}},"node_modules/member":{"link":true,"resolved":"apps/member"},"node_modules/root-dep":{"version":"1.0.0"},"node_modules/member-dep":{"version":"2.0.0"}}}"#,
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      root-dep: {specifier: ^1, version: 1.0.0}\n  apps/member:\n    dependencies:\n      member-dep: {specifier: ^2, version: 2.0.0}\npackages:\n  root-dep@1.0.0: {}\n  member-dep@2.0.0: {}\n",
        ),
        (
            "bun.lock",
            r#"{"workspaces":{"":{"name":"root"},"apps/member":{"name":"member"}},"packages":{"root-dep":["root-dep@1.0.0","",{},""],"member-dep":["member-dep@2.0.0","",{},""]}}"#,
        ),
        (
            "yarn.lock",
            "root-dep@^1:\n  version \"1.0.0\"\nmember-dep@^2:\n  version \"2.0.0\"\n",
        ),
    ];
    for (lock_name, lock) in cases {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("package.json"), r#"{"name":"root","private":true,"workspaces":["apps/*"],"dependencies":{"root-dep":"^1"}}"#).unwrap();
        for (directory, dependency) in [
            ("apps/member", "member-dep"),
            ("tools/independent", "independent-dep"),
        ] {
            let directory = temp.path().join(directory);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("package.json"),
                format!(r#"{{"dependencies":{{"{dependency}":"^2"}}}}"#),
            )
            .unwrap();
        }
        fs::write(temp.path().join(lock_name), lock).unwrap();
        let inventory = scan_path(temp.path(), &Config::default()).unwrap();
        assert_eq!(inventory.asset.name, "root", "{lock_name}");
        assert!(
            inventory
                .components
                .values()
                .any(|component| component.name == "independent-dep"
                    && component.version == "^2"
                    && component.purl == "pkg:npm/independent-dep"),
            "{lock_name}: unrelated nested declaration disappeared"
        );
        assert!(
            inventory
                .components
                .values()
                .any(|component| component.name == "member-dep" && component.version == "2.0.0"),
            "{lock_name}: workspace's resolved dependency disappeared"
        );
        assert!(
            !inventory
                .components
                .values()
                .any(|component| component.name == "member-dep" && component.version == "^2"),
            "{lock_name}: duplicate workspace constraint"
        );
        let archive = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        fs::write(archive.path(), zipped_directory(temp.path())).unwrap();
        let zipped = scan_path(archive.path(), &Config::default()).unwrap();
        assert_eq!(
            zipped.components, inventory.components,
            "{lock_name}: ZIP workspace admission"
        );
        assert_eq!(
            zipped.dependencies, inventory.dependencies,
            "{lock_name}: ZIP graph"
        );
        fs::write(
            temp.path().join("tools/independent/package-lock.json"),
            r#"{"packages":{"":{},"node_modules/independent-dep":{"version":"2.5.0"}}}"#,
        )
        .unwrap();
        let resolved = scan_path(temp.path(), &Config::default()).unwrap();
        assert!(
            resolved.components.values().any(
                |component| component.name == "independent-dep" && component.version == "2.5.0"
            ),
            "{lock_name}: sibling precedence"
        );
        assert!(
            !resolved
                .components
                .values()
                .any(|component| component.name == "independent-dep" && component.version == "^2"),
            "{lock_name}: sibling declaration duplicated"
        );
    }
}

#[test]
fn npm_aliases_identify_the_registry_package_in_manifests_and_v1_locks() {
    for (file, contents) in [
        (
            "package.json",
            r#"{"dependencies":{"alias":"npm:real@1.2.3"},"devDependencies":{"scoped-alias":"npm:@org/real@^2"},"optionalDependencies":{"ordinary":"3.0.0"}}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{"alias":{"version":"npm:real@1.2.3"},"scoped-alias":{"version":"npm:@org/real@2.4.0","dev":true},"ordinary":{"version":"3.0.0","optional":true}}}"#,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(file), contents).unwrap();
        let inventory = scan_path(temp.path(), &Config::default()).unwrap();
        assert_eq!(inventory.components.len(), 3);
        let unscoped = inventory
            .components
            .values()
            .find(|component| component.name == "real")
            .expect("aliased package name");
        assert_eq!(unscoped.purl, "pkg:npm/real@1.2.3");
        let scoped = inventory
            .components
            .values()
            .find(|component| component.name == "@org/real")
            .expect("scoped aliased package name");
        assert_eq!(scoped.scope, Scope::Development);
        assert_eq!(
            scoped.purl,
            if file == "package.json" {
                "pkg:npm/%40org/real"
            } else {
                "pkg:npm/%40org/real@2.4.0"
            }
        );
        assert!(
            !inventory
                .components
                .values()
                .any(|component| component.name == "alias" || component.name == "scoped-alias")
        );
    }
}

#[test]
fn poetry_ambiguous_and_unsatisfied_constraints_do_not_guess_one_locked_version() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("poetry.lock"),
        r#"
[[package]]
name = "app"
version = "1.0.0"
dependencies = {shared = ">=1", impossible = ">=9", missing = "3.0.0"}
[[package]]
name = "shared"
version = "1.0.0"
[[package]]
name = "shared"
version = "2.0.0"
[[package]]
name = "impossible"
version = "1.0.0"
[[package]]
name = "missing"
version = "4.0.0"
"#,
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(inventory.components.len(), 5);
    let edges = inventory
        .dependencies
        .iter()
        .map(|edge| {
            let from = &inventory.components[&edge.from];
            let to = &inventory.components[&edge.to];
            (from.name.as_str(), to.name.as_str(), to.version.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        edges,
        BTreeSet::from([("app", "shared", "1.0.0"), ("app", "shared", "2.0.0")])
    );
}

#[test]
fn yarn_workspace_patterns_keep_excluded_and_deeper_projects_independent() {
    for workspaces in [
        serde_json::json!(["apps/*", "!apps/excluded"]),
        serde_json::json!({"packages": ["apps/*", "!apps/excluded"]}),
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            serde_json::to_vec(&serde_json::json!({"name": "root", "workspaces": workspaces}))
                .unwrap(),
        )
        .unwrap();
        fs::write(
            temp.path().join("yarn.lock"),
            "member-dep@^1:\n  version \"1.0.0\"\n",
        )
        .unwrap();
        for (path, name) in [
            ("apps/member", "member-dep"),
            ("apps/excluded", "excluded-dep"),
            ("apps/member/deeper", "deeper-dep"),
        ] {
            let directory = temp.path().join(path);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("package.json"),
                format!(r#"{{"dependencies":{{"{name}":"^1"}}}}"#),
            )
            .unwrap();
        }
        let inventory = scan_path(temp.path(), &Config::default()).unwrap();
        assert_eq!(inventory.components.len(), 3);
        for name in ["excluded-dep", "deeper-dep"] {
            assert!(
                inventory
                    .components
                    .values()
                    .any(|component| component.name == name && component.version == "^1"),
                "{name}"
            );
        }
        assert!(
            !inventory
                .components
                .values()
                .any(|component| component.name == "member-dep" && component.version == "^1")
        );
    }
}

#[test]
fn poetry_compatible_release_exclusion_and_exact_pins_select_valid_variants() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("poetry.lock"),
        r#"
[[package]]
name = "app"
version = "1.0.0"
dependencies = {compatible = "~=2.4", narrow = "~=2.4.0", excluded = ">=1,!=1.*", exact = "==1.0.0"}
[[package]]
name = "compatible"
version = "2.4.0"
[[package]]
name = "compatible"
version = "2.8.0"
[[package]]
name = "compatible"
version = "3.0.0"
[[package]]
name = "narrow"
version = "2.4.3"
[[package]]
name = "narrow"
version = "2.8.0"
[[package]]
name = "excluded"
version = "1.4.0"
[[package]]
name = "excluded"
version = "2.0.0"
[[package]]
name = "exact"
version = "1.0.0"
[[package]]
name = "exact"
version = "2.0.0"
"#,
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    let targets = inventory
        .dependencies
        .iter()
        .map(|edge| {
            let component = &inventory.components[&edge.to];
            (component.name.as_str(), component.version.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        targets,
        BTreeSet::from([
            ("compatible", "2.4.0"),
            ("compatible", "2.8.0"),
            ("narrow", "2.4.3"),
            ("excluded", "2.0.0"),
            ("exact", "1.0.0")
        ])
    );
}

#[test]
fn poetry_malformed_constraints_do_not_infer_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("poetry.lock"),
        r#"
[[package]]
name = "app"
version = "1.0.0"
dependencies = {empty = ",,", invalid = "!=not-a-version", unsupported = "!=https://example.test/archive", comparison = ">=not-a-version", exact = "not-a-version", bad_or = "*||not-a-version", bad_suffix = "!=1.0-", trailing = "*,", valid = "!=1.0.0"}
[[package]]
name = "empty"
version = "1.0.0"
[[package]]
name = "invalid"
version = "1.0.0"
[[package]]
name = "unsupported"
version = "1.0.0"
[[package]]
name = "comparison"
version = "1.0.0"
[[package]]
name = "exact"
version = "not-a-version"
[[package]]
name = "bad_or"
version = "1.0.0"
[[package]]
name = "bad_suffix"
version = "1.0.0"
[[package]]
name = "trailing"
version = "1.0.0"
[[package]]
name = "valid"
version = "1.0.0"
[[package]]
name = "valid"
version = "2.0.0"
"#,
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    let targets = inventory
        .dependencies
        .iter()
        .map(|edge| {
            let component = &inventory.components[&edge.to];
            (component.name.as_str(), component.version.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(targets, BTreeSet::from([("valid", "2.0.0")]));
}
