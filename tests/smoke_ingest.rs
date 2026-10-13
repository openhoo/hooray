//! Public ingestion smoke controls across ecosystem inputs and archive codecs.

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use hooray::config::Config;
use hooray::input::{InputError, ScanInput, scan_path};
use hooray::model::Scope;

fn files_below(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &path, files);
            } else {
                assert!(kind.is_file(), "fixture is not a regular file: {path:?}");
                files.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn stage(files: &BTreeMap<String, Vec<u8>>, root: &Path) {
    std::fs::create_dir(root).unwrap();
    for (name, bytes) in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

fn tar(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut writer = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    writer.into_inner().unwrap()
}

fn zip(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        writer
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn containers(files: &BTreeMap<String, Vec<u8>>) -> [(&'static str, Vec<u8>); 4] {
    let tar = tar(files);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar).unwrap();
    let zstd = zstd::stream::encode_all(tar.as_slice(), 1).unwrap();
    [
        ("project.zip", zip(files)),
        ("project.tar", tar),
        ("project.tar.gz", gzip.finish().unwrap()),
        ("project.tar.zst", zstd),
    ]
}

#[test]
fn committed_ecosystem_corpus_matches_across_directory_and_archive_codecs() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parity/corpus");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus.join("manifest.json")).unwrap()).unwrap();
    let config = Config::default();
    let mut project_cases = 0;
    let mut archive_cases = 0;
    for case in manifest["cases"].as_array().unwrap() {
        if case["kind"] != "project-directory" {
            continue;
        }
        let id = case["case_id"].as_str().unwrap();
        let files = files_below(&corpus.join(id));
        // Complete fixture roots and their original names/bytes keep this
        // independent of developer-home ignore files and preserve attribution.
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join(id);
        stage(&files, &project);
        let expected = scan_path(&project, &config).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert!(
            expected.components.len() >= case["min_components"].as_u64().unwrap() as usize,
            "{id}"
        );
        for ecosystem in case["expected_ecosystems"].as_array().unwrap() {
            let prefix = format!("pkg:{}/", ecosystem.as_str().unwrap());
            assert!(
                expected
                    .components
                    .values()
                    .any(|c| c.purl.starts_with(&prefix)),
                "{id}: {prefix}"
            );
        }
        for (name, bytes) in containers(&files) {
            let archive = temp.path().join(name);
            std::fs::write(&archive, bytes).unwrap();
            let actual =
                scan_path(&archive, &config).unwrap_or_else(|e| panic!("{id}/{name}: {e}"));
            assert_eq!(
                actual.components, expected.components,
                "{id}/{name}: components"
            );
            assert_eq!(
                actual.dependencies, expected.dependencies,
                "{id}/{name}: graph"
            );
            archive_cases += 1;
        }
        project_cases += 1;
    }
    assert!(project_cases >= 19, "only {project_cases} project controls");
    assert_eq!(archive_cases, project_cases * 4);
    println!(
        "ecosystem smoke: {project_cases} directory controls, {archive_cases} archive controls"
    );
}

#[test]
fn standalone_package_json_accepts_utf8_bom() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("package.json"),
        "\u{feff}{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"dep\":\"2.0.0\"}}",
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(inventory.asset.name, "app");
    assert_eq!(inventory.components.len(), 1);
    assert_eq!(
        inventory.components.values().next().unwrap().purl,
        "pkg:npm/dep@2.0.0"
    );
}

#[test]
fn standalone_package_json_keeps_peer_dependencies_and_lock_precedence() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"name":"app","peerDependencies":{"peer":"^2"},"devDependencies":{"build":"1.0.0"}}"#,
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    let peer = inventory
        .components
        .values()
        .find(|c| c.name == "peer")
        .expect("peer dependency");
    assert_eq!(peer.purl, "pkg:npm/peer");
    assert_eq!(peer.version, "^2");
    assert_eq!(peer.scope, Scope::Runtime);
    assert_eq!(inventory.components.len(), 2);
    std::fs::write(
        temp.path().join("package-lock.json"),
        r#"{"name":"app","packages":{"":{},"node_modules/peer":{"version":"2.3.4"}}}"#,
    )
    .unwrap();
    let locked = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(locked.components.len(), 1);
    assert_eq!(
        locked.components.values().next().unwrap().purl,
        "pkg:npm/peer@2.3.4"
    );
}

#[test]
fn zip_inputs_use_the_archive_budget_with_expanded_size_controls() {
    let temp = tempfile::tempdir().unwrap();
    let files = BTreeMap::from([(
        "requirements.txt".to_owned(),
        b"requests==2.31.0\n".to_vec(),
    )]);
    let archive = temp.path().join("project.zip");
    let bytes = zip(&files);
    assert!(bytes.len() > 64);
    std::fs::write(&archive, &bytes).unwrap();
    let config = Config {
        max_input_bytes: 64,
        max_archive_bytes: 4096,
        ..Config::default()
    };
    let inventory = scan_path(&archive, &config).unwrap();
    assert_eq!(inventory.components.len(), 1);
    let bounded = Config {
        max_archive_bytes: bytes.len() as u64 - 1,
        ..config.clone()
    };
    assert!(matches!(
        scan_path(&archive, &bounded),
        Err(InputError::InputTooLarge { .. })
    ));
    let too_large = BTreeMap::from([("large.txt".to_owned(), vec![b'x'; 8192])]);
    std::fs::write(&archive, zip(&too_large)).unwrap();
    assert!(matches!(
        scan_path(&archive, &config),
        Err(InputError::ArchiveTooLarge { .. })
    ));
}

#[test]
fn docker_save_requires_config_and_normalizes_manifest_paths() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.tar");
    let layer = tar(&BTreeMap::from([(
        "app/requirements.txt".to_owned(),
        b"requests==2.31.0\n".to_vec(),
    )]));
    let mut files = BTreeMap::from([
        (
            "manifest.json".to_owned(),
            br#"[{"Config":"config.json","Layers":["layer.tar"]}]"#.to_vec(),
        ),
        ("layer.tar".to_owned(), layer),
    ]);
    std::fs::write(&image, tar(&files)).unwrap();
    let config = Config::default();
    assert!(
        matches!(scan_path(&image, &config), Err(InputError::MissingBlob(name)) if name == "config.json")
    );
    let input = ScanInput::detect(&image, &config).unwrap();
    assert!(
        matches!(input.virtual_files(&config), Err(InputError::MissingBlob(name)) if name == "config.json")
    );
    files.insert(
        "config.json".to_owned(),
        br#"{"os":"linux","architecture":"amd64"}"#.to_vec(),
    );
    for (manifest, expected_error) in [
        (
            br#"[{"Config":"./config.json","Layers":["./layer.tar"]}]"#.as_slice(),
            false,
        ),
        (
            br#"[{"Config":"../config.json","Layers":["layer.tar"]}]"#.as_slice(),
            true,
        ),
        (
            br#"[{"Config":"config.json","Layers":["../layer.tar"]}]"#.as_slice(),
            true,
        ),
    ] {
        files.insert("manifest.json".to_owned(), manifest.to_vec());
        std::fs::write(&image, tar(&files)).unwrap();
        if expected_error {
            assert!(matches!(
                scan_path(&image, &config),
                Err(InputError::PathTraversal(_))
            ));
        } else {
            let inventory = scan_path(&image, &config).unwrap();
            assert_eq!(inventory.components.len(), 1);
            assert_eq!(inventory.asset.metadata["os"], "linux");
            assert!(
                ScanInput::detect(&image, &config)
                    .unwrap()
                    .virtual_files(&config)
                    .unwrap()
                    .unwrap()
                    .contains_key("app/requirements.txt")
            );
        }
    }
}

#[test]
fn sbom_inputs_reject_incomplete_purl_identities() {
    let temp = tempfile::tempdir().unwrap();
    let mut accepted = Vec::new();
    for (purl, version, reject) in [
        ("pkg:foo", Some("1"), true),
        ("pkg:cargo/a@", None, true),
        ("pkg:cargo/@1", None, true),
        ("pkg:cargo/a", Some("1"), false),
        ("pkg:npm/@scope/a@1", None, false),
        ("pkg:cargo/a@1%2Brev", Some("1+rev"), false),
    ] {
        for format in ["cdx", "spdx"] {
            let document = if format == "cdx" {
                serde_json::json!({
                    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                    "components": [{"type": "library", "name": "a", "purl": purl, "version": version}],
                })
            } else {
                serde_json::json!({
                    "spdxVersion": "SPDX-2.3", "name": "smoke",
                    "packages": [{"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": version,
                        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]}],
                })
            };
            let path = temp.path().join(format!("invalid.{format}.json"));
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            let result = scan_path(&path, &Config::default());
            if reject {
                if let Ok(inventory) = result {
                    accepted.push(format!(
                        "{format}: {purl}, {} components",
                        inventory.components.len()
                    ));
                }
            } else {
                let inventory = result.unwrap_or_else(|error| panic!("{format}: {purl}: {error}"));
                assert_eq!(inventory.components.len(), 1);
                assert_eq!(
                    inventory.components.values().next().unwrap().version,
                    version.unwrap_or("1")
                );
            }
        }
    }
    assert!(accepted.is_empty(), "invalid purls accepted: {accepted:?}");
}

#[test]
fn nested_composer_and_helm_projects_keep_their_own_unlocked_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("composer.lock"),
        r#"{"packages":[{"name":"root/php","version":"1.0.0"}]}"#,
    )
    .unwrap();
    std::fs::write(
        temp.path().join("Chart.lock"),
        "dependencies:\n  - name: root-chart\n    version: 1.0.0\n",
    )
    .unwrap();
    let nested = temp.path().join("tools");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(
        nested.join("composer.json"),
        r#"{"require":{"nested/php":"^2"}}"#,
    )
    .unwrap();
    std::fs::write(
        nested.join("Chart.yaml"),
        "name: nested\nversion: 1.0.0\ndependencies:\n  - name: nested-chart\n    version: ^2\n",
    )
    .unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(inventory.components.len(), 4);
    for name in ["nested/php", "nested-chart"] {
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == name && c.version == "^2"),
            "{name}"
        );
    }
    std::fs::write(
        nested.join("composer.lock"),
        r#"{"packages":[{"name":"nested/php","version":"2.3.4"}]}"#,
    )
    .unwrap();
    std::fs::write(
        nested.join("Chart.lock"),
        "dependencies:\n  - name: nested-chart\n    version: 2.3.4\n",
    )
    .unwrap();
    let locked = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(locked.components.len(), 4);
    for name in ["nested/php", "nested-chart"] {
        assert!(
            locked
                .components
                .values()
                .any(|c| c.name == name && c.version == "2.3.4"),
            "{name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn direct_archive_inputs_reject_fifos_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;
    use std::time::Duration;

    use hooray::input::ArchiveFormat;

    let temp = tempfile::tempdir().unwrap();
    for (name, format) in [
        ("fifo.zip", ArchiveFormat::Zip),
        ("fifo.tar", ArchiveFormat::Tar),
    ] {
        let path = temp.path().join(name);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = ScanInput::Archive { path, format }.inventory(&Config::default());
            let _ = sender.send(result);
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("FIFO open waited for a writer");
        assert!(
            matches!(result, Err(InputError::UnsupportedPath(_))),
            "{result:?}"
        );
    }
}

#[test]
fn poetry_multiversion_graph_uses_each_packages_locked_identity() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("poetry.lock"), r#"
[[package]]
name = "app"
version = "1.0.0"
dependencies = {shared_lib = "<2"}
[[package]]
name = "app"
version = "2.0.0"
dependencies = {shared_lib = {version = ">=2"}}
[[package]]
name = "bridge"
version = "1.0.0"
dependencies = {shared_lib = [{version = "<2", markers = "python_version < '3.11'"}, {version = ">=2", markers = "python_version >= '3.11'"}]}
[[package]]
name = "shared-lib"
version = "1.4.0"
[[package]]
name = "shared-lib"
version = "2.4.0"
[[package]]
name = "app"
version = "1.0.0"
source = {type = "git", url = "https://example.com/private.git"}
dependencies = {shared_lib = ">=2"}
"#).unwrap();
    let inventory = scan_path(temp.path(), &Config::default()).unwrap();
    assert_eq!(inventory.components.len(), 5);
    let edges = inventory
        .dependencies
        .iter()
        .map(|edge| {
            let from = &inventory.components[&edge.from];
            let to = &inventory.components[&edge.to];
            (
                from.name.as_str(),
                from.version.as_str(),
                to.name.as_str(),
                to.version.as_str(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        edges,
        std::collections::BTreeSet::from([
            ("app", "1.0.0", "shared-lib", "1.4.0"),
            ("app", "2.0.0", "shared-lib", "2.4.0"),
            ("bridge", "1.0.0", "shared-lib", "1.4.0"),
            ("bridge", "1.0.0", "shared-lib", "2.4.0"),
        ])
    );
}
