use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use super::archive::{read_tar_file, read_tar_with_expanded};
use crate::config::Config;
use crate::input::{
    InputError, base_name, malformed, malformed_msg, read_limited, reject_symlink_ancestors,
    reject_symlink_ancestors_below, scan_virtual_files, sha256,
};
use crate::model::{Asset, AssetKind, Inventory};

pub(crate) fn scan_oci_layout(root: &Path, config: &Config) -> Result<Inventory, InputError> {
    reject_symlink_ancestors(root)?;
    let index = read_limited(&root.join("index.json"), config.max_input_bytes)?;
    let index: OciIndex =
        serde_json::from_slice(&index).map_err(|e| malformed("index.json", "OCI index", e))?;
    let descriptor = index.manifests.first().ok_or(InputError::MissingManifest)?;
    let manifest_bytes = read_oci_blob(root, &descriptor.digest, config)?;
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| malformed("manifest", "OCI manifest", e))?;
    let config_bytes = read_oci_blob(root, &manifest.config.digest, config)?;
    let mut filesystem = BTreeMap::new();
    let mut expanded = 0;
    for layer in &manifest.layers {
        let bytes = read_oci_blob(root, &layer.digest, config)?;
        apply_layer(
            &bytes,
            layer.media_type.as_deref(),
            config,
            &mut expanded,
            &mut filesystem,
        )?;
    }
    let mut inventory = scan_virtual_files(root, AssetKind::ContainerImage, filesystem)?;
    inventory
        .asset
        .metadata
        .insert("manifest_digest".into(), json!(descriptor.digest));
    add_oci_config_metadata(&mut inventory.asset, &config_bytes);
    Ok(inventory)
}

pub(crate) fn scan_oci_tar(path: &Path, config: &Config) -> Result<Inventory, InputError> {
    let outer = read_tar_file(path, config)?;
    let (mut inventory, manifest_digest, config_bytes) =
        if let Some(index_bytes) = outer.get("index.json") {
            let index: OciIndex = serde_json::from_slice(index_bytes)
                .map_err(|e| malformed("index.json", "OCI index", e))?;
            let descriptor = index.manifests.first().ok_or(InputError::MissingManifest)?;
            let manifest_bytes = outer
                .get(&blob_path(&descriptor.digest)?)
                .ok_or_else(|| InputError::MissingBlob(descriptor.digest.clone()))?;
            verify_digest(&descriptor.digest, manifest_bytes)?;
            let manifest: OciManifest = serde_json::from_slice(manifest_bytes)
                .map_err(|e| malformed("manifest", "OCI manifest", e))?;
            let config_bytes = outer
                .get(&blob_path(&manifest.config.digest)?)
                .map(|bytes| {
                    verify_digest(&manifest.config.digest, bytes)?;
                    Ok::<Vec<u8>, InputError>(bytes.clone())
                })
                .transpose()?
                .unwrap_or_default();
            let mut filesystem = BTreeMap::new();
            let mut expanded = 0;
            for layer in &manifest.layers {
                let bytes = outer
                    .get(&blob_path(&layer.digest)?)
                    .ok_or_else(|| InputError::MissingBlob(layer.digest.clone()))?;
                verify_digest(&layer.digest, bytes)?;
                apply_layer(
                    bytes,
                    layer.media_type.as_deref(),
                    config,
                    &mut expanded,
                    &mut filesystem,
                )?;
            }
            (
                scan_virtual_files(path, AssetKind::ContainerImage, filesystem)?,
                descriptor.digest.clone(),
                config_bytes,
            )
        } else {
            let manifest_bytes = outer
                .get("manifest.json")
                .ok_or(InputError::MissingManifest)?;
            let docker: Vec<DockerManifest> = serde_json::from_slice(manifest_bytes)
                .map_err(|e| malformed("manifest.json", "Docker image manifest", e))?;
            let manifest = docker.first().ok_or(InputError::MissingManifest)?;
            let mut filesystem = BTreeMap::new();
            let mut expanded = 0;
            for layer in &manifest.layers {
                let bytes = outer
                    .get(layer)
                    .ok_or_else(|| InputError::MissingBlob(layer.clone()))?;
                apply_layer(bytes, None, config, &mut expanded, &mut filesystem)?;
            }
            let config_bytes = outer.get(&manifest.config).cloned().unwrap_or_default();
            (
                scan_virtual_files(path, AssetKind::ContainerImage, filesystem)?,
                sha256(manifest_bytes),
                config_bytes,
            )
        };
    inventory
        .asset
        .metadata
        .insert("manifest_digest".into(), json!(manifest_digest));
    add_oci_config_metadata(&mut inventory.asset, &config_bytes);
    Ok(inventory)
}

#[derive(Deserialize)]
struct OciIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}
#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
}
#[derive(Deserialize)]
struct OciManifest {
    config: OciDescriptor,
    #[serde(default)]
    layers: Vec<OciDescriptor>,
}
#[derive(Deserialize)]
struct DockerManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

fn apply_layer(
    bytes: &[u8],
    media_type: Option<&str>,
    config: &Config,
    expanded: &mut u64,
    filesystem: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), InputError> {
    let layer = read_tar_with_expanded(layer_reader(bytes, media_type)?, config, expanded)?;
    for (path, bytes) in layer {
        let name = base_name(&path);
        if name == ".wh..wh..opq" {
            let parent = path.rsplit_once('/').map(|v| v.0).unwrap_or_default();
            let prefix = if parent.is_empty() {
                String::new()
            } else {
                format!("{parent}/")
            };
            filesystem.retain(|key, _| !key.starts_with(&prefix));
        } else if let Some(target) = name.strip_prefix(".wh.") {
            let parent = path.rsplit_once('/').map(|v| v.0).unwrap_or_default();
            let removed = if parent.is_empty() {
                target.to_owned()
            } else {
                format!("{parent}/{target}")
            };
            filesystem.retain(|key, _| key != &removed && !key.starts_with(&format!("{removed}/")));
        } else {
            filesystem.insert(path, bytes);
        }
    }
    Ok(())
}

/// Wraps a layer blob in the decompressor its bytes and media type declare.
/// Magic bytes decide the codec (gzip `1f 8b`, zstd `28 b5 2f fd`); the
/// media type only guards fail-closed handling: a declared codec the blob
/// does not match is malformed, and a non-tar media type without a
/// recognized codec is unsupported. Anything else is read as a plain tar.
fn layer_reader<'a>(
    bytes: &'a [u8],
    media_type: Option<&str>,
) -> Result<Box<dyn Read + 'a>, InputError> {
    const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    let declared = media_type.and_then(layer_codec);
    let detected = if bytes.starts_with(&GZIP_MAGIC) {
        Some("gzip")
    } else if bytes.starts_with(&ZSTD_MAGIC) {
        Some("zstd")
    } else {
        None
    };
    if let Some(declared) = declared {
        let detail = match detected {
            Some(detected) if detected != declared => format!(
                "media type {} declares {declared} compression but the blob is {detected}",
                media_type.unwrap_or_default()
            ),
            None => format!(
                "media type {} declares {declared} compression but the blob is not compressed",
                media_type.unwrap_or_default()
            ),
            _ => return decompress(detected, bytes),
        };
        return Err(malformed_msg("layer", "OCI layer", detail));
    }
    match detected {
        Some(_) => decompress(detected, bytes),
        None => {
            if let Some(media_type) = media_type
                && !is_plain_layer_media_type(media_type)
            {
                return Err(InputError::UnsupportedLayerMediaType(media_type.to_owned()));
            }
            Ok(Box::new(bytes))
        }
    }
}

fn decompress<'a>(codec: Option<&str>, bytes: &'a [u8]) -> Result<Box<dyn Read + 'a>, InputError> {
    match codec {
        Some("gzip") => Ok(Box::new(flate2::read::MultiGzDecoder::new(bytes))),
        Some("zstd") => zstd::stream::read::Decoder::new(bytes)
            .map(|decoder| Box::new(decoder) as Box<dyn Read>)
            .map_err(|source| InputError::Io {
                path: PathBuf::from("<oci-layer>"),
                source,
            }),
        Some(_) => unreachable!("detected codecs are limited to gzip and zstd"),
        None => Ok(Box::new(bytes)),
    }
}

/// Extracts the compression codec a layer media type declares: the `+codec`
/// suffix of OCI types (`…layer.v1.tar+gzip`) or the docker-style `.codec`
/// extension (`…rootfs.diff.tar.gzip`). Returns `None` for plain tar types
/// and for media types carrying no recognized codec.
fn layer_codec(media_type: &str) -> Option<&str> {
    let codec = media_type
        .rsplit_once('+')
        .map(|(_, codec)| codec)
        .or_else(|| media_type.rsplit_once('.').map(|(_, codec)| codec))?;
    matches!(codec, "gzip" | "zstd").then_some(codec)
}

/// Media types that name an uncompressed tar layer. Anything else without a
/// recognized codec suffix is rejected instead of being fed to the tar parser.
fn is_plain_layer_media_type(media_type: &str) -> bool {
    media_type.ends_with(".tar") || media_type == "application/tar"
}

fn read_oci_blob(root: &Path, digest: &str, config: &Config) -> Result<Vec<u8>, InputError> {
    let path = root.join(blob_path(digest)?);
    reject_symlink_ancestors_below(root, &path)?;
    let bytes = read_limited(&path, config.max_archive_bytes)?;
    verify_digest(digest, &bytes)?;
    Ok(bytes)
}

fn verify_digest(digest: &str, bytes: &[u8]) -> Result<(), InputError> {
    if sha256(bytes) == digest.to_ascii_lowercase() {
        Ok(())
    } else {
        Err(InputError::DigestMismatch(digest.to_owned()))
    }
}

fn blob_path(digest: &str) -> Result<String, InputError> {
    let (algorithm, value) = digest
        .split_once(':')
        .ok_or_else(|| InputError::MissingBlob(digest.to_owned()))?;
    if algorithm != "sha256" || value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(InputError::MissingBlob(digest.to_owned()));
    }
    Ok(format!("blobs/{algorithm}/{value}"))
}

fn add_oci_config_metadata(asset: &mut Asset, bytes: &[u8]) {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if let Some(labels) = value.pointer("/config/Labels").and_then(Value::as_object) {
            asset
                .metadata
                .insert("labels".into(), Value::Object(labels.clone()));
        }
        if let Some(os) = value.get("os") {
            asset.metadata.insert("os".into(), os.clone());
        }
        if let Some(architecture) = value.get("architecture") {
            asset
                .metadata
                .insert("architecture".into(), architecture.clone());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;

    use crate::input::{config, scan_path, tar_bytes, write_tar};
    use tempfile::tempdir;
    #[test]
    fn applies_oci_whiteouts_without_execution() {
        let mut first = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut first);
            let data = b"old==1\n";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            builder
                .append_data(&mut h, "app/requirements.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut second = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut second);
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_cksum();
            builder
                .append_data(&mut h, "app/.wh.requirements.txt", io::empty())
                .unwrap();
            let data = b"new==2\n";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            builder
                .append_data(&mut h, "requirements.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut filesystem = BTreeMap::new();
        let mut expanded = 0;
        apply_layer(&first, None, &config(), &mut expanded, &mut filesystem).unwrap();
        apply_layer(&second, None, &config(), &mut expanded, &mut filesystem).unwrap();
        assert!(!filesystem.contains_key("app/requirements.txt"));
        assert_eq!(filesystem["requirements.txt"], b"new==2\n");
    }
    #[test]
    fn oci_tar_compressed_layers_scan_identically_to_plain() {
        use std::collections::BTreeSet;
        use std::io::Write;
        let dir = tempdir().unwrap();
        let layer = tar_bytes(&[("requirements.txt", b"requests==2.31.0\n")]);
        let config_json = br#"{"os":"linux"}"#;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&layer).unwrap();
        let gzip_layer = encoder.finish().unwrap();
        let zstd_layer = zstd::stream::encode_all(&layer[..], 3).unwrap();

        let mut component_sets = Vec::new();
        for (name, media_type, blob) in [
            (
                "plain.tar",
                "application/vnd.oci.image.layer.v1.tar",
                layer.clone(),
            ),
            (
                "gzip.tar",
                "application/vnd.oci.image.layer.v1.tar+gzip",
                gzip_layer.clone(),
            ),
            (
                "zstd.tar",
                "application/vnd.oci.image.layer.v1.tar+zstd",
                zstd_layer,
            ),
        ] {
            let config_digest = sha256(config_json);
            let layer_digest = sha256(&blob);
            let manifest = format!(
                r#"{{"config":{{"digest":"{config_digest}"}},"layers":[{{"mediaType":"{media_type}","digest":"{layer_digest}"}}]}}"#
            );
            let manifest_digest = sha256(manifest.as_bytes());
            let index = format!(r#"{{"manifests":[{{"digest":"{manifest_digest}"}}]}}"#);
            let path = dir.path().join(name);
            write_tar(
                &path,
                &[
                    ("oci-layout", b"{}"),
                    ("index.json", index.as_bytes()),
                    (&blob_name(&manifest_digest), manifest.as_bytes()),
                    (&blob_name(&config_digest), config_json),
                    (&blob_name(&layer_digest), &blob),
                ],
            );
            let inventory = scan_path(&path, &config()).unwrap();
            component_sets.push(
                inventory
                    .components
                    .values()
                    .map(|component| (component.name.clone(), component.version.clone()))
                    .collect::<BTreeSet<_>>(),
            );
        }
        let expected = BTreeSet::from([("requests".to_owned(), "2.31.0".to_owned())]);
        assert_eq!(component_sets, vec![expected.clone(); 3]);

        // Docker-save archives carry no layer media type; gzip layers are
        // still detected by magic bytes.
        let docker_manifest = br#"[{"Config":"config.json","Layers":["layer.tar"]}]"#;
        let docker_path = dir.path().join("image-docker-gzip.tar");
        write_tar(
            &docker_path,
            &[
                ("manifest.json", docker_manifest),
                ("config.json", config_json),
                ("layer.tar", &gzip_layer),
            ],
        );
        let inventory = scan_path(&docker_path, &config()).unwrap();
        assert_eq!(
            inventory
                .components
                .values()
                .map(|component| (component.name.clone(), component.version.clone()))
                .collect::<BTreeSet<_>>(),
            expected
        );
    }
    #[test]
    fn oci_tar_rejects_mismatched_and_unknown_layer_media_types() {
        let dir = tempdir().unwrap();
        let layer = tar_bytes(&[("requirements.txt", b"a==1\n")]);
        let config_json = br#"{"os":"linux"}"#;
        let config_digest = sha256(config_json);
        let layer_digest = sha256(&layer);
        let write_image = |name: &str, media_type: &str| {
            let manifest = format!(
                r#"{{"config":{{"digest":"{config_digest}"}},"layers":[{{"mediaType":"{media_type}","digest":"{layer_digest}"}}]}}"#
            );
            let manifest_digest = sha256(manifest.as_bytes());
            let index = format!(r#"{{"manifests":[{{"digest":"{manifest_digest}"}}]}}"#);
            let path = dir.path().join(name);
            write_tar(
                &path,
                &[
                    ("oci-layout", b"{}"),
                    ("index.json", index.as_bytes()),
                    (&blob_name(&manifest_digest), manifest.as_bytes()),
                    (&blob_name(&config_digest), config_json),
                    (&blob_name(&layer_digest), &layer),
                ],
            );
            path
        };

        // A declared codec the blob does not carry is malformed.
        let path = write_image(
            "declared-gzip.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
        );
        let error = scan_path(&path, &config()).unwrap_err();
        assert!(
            matches!(
                error,
                InputError::Malformed {
                    format: "OCI layer",
                    ..
                }
            ),
            "unexpected error: {error:?}"
        );

        // A media type without a recognized codec fails closed by name.
        let path = write_image(
            "unknown-codec.tar",
            "application/vnd.oci.image.layer.v1.tar+lz4",
        );
        assert!(matches!(
            scan_path(&path, &config()),
            Err(InputError::UnsupportedLayerMediaType(media_type))
                if media_type == "application/vnd.oci.image.layer.v1.tar+lz4"
        ));
    }
    #[test]
    fn oci_layout_reads_index_manifest_layers_and_config_metadata() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let config_json =
            br#"{"os":"linux","architecture":"amd64","config":{"Labels":{"org.example":"yes"}}}"#;
        let layer = tar_bytes(&[("requirements.txt", b"inside==1\n")]);
        let config_digest = sha256(config_json);
        let layer_digest = sha256(&layer);
        let manifest = format!(
            r#"{{"config":{{"digest":"{config_digest}"}},"layers":[{{"digest":"{layer_digest}"}}]}}"#
        );
        let manifest_digest = sha256(manifest.as_bytes());
        for (name, bytes) in [
            (blob_name(&manifest_digest), manifest.into_bytes()),
            (blob_name(&config_digest), config_json.to_vec()),
            (blob_name(&layer_digest), layer),
        ] {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::write(
            dir.path().join("index.json"),
            format!(r#"{{"manifests":[{{"digest":"{manifest_digest}"}}]}}"#),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.kind, AssetKind::ContainerImage);
        assert_eq!(inventory.asset.metadata["manifest_digest"], manifest_digest);
        assert_eq!(inventory.asset.metadata["os"], "linux");
        assert_eq!(inventory.asset.metadata["architecture"], "amd64");
        assert_eq!(inventory.asset.metadata["labels"]["org.example"], "yes");
        assert!(inventory.components.values().any(|c| c.name == "inside"));
    }
    #[test]
    fn oci_layout_rejects_empty_index_invalid_digest_missing_blob_and_digest_mismatch() {
        for index in [
            r#"{"manifests":[]}"#.to_owned(),
            r#"{"manifests":[{"digest":"sha512:bad"}]}"#.to_owned(),
            format!(r#"{{"manifests":[{{"digest":"{}"}}]}}"#, digest(9)),
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("oci-layout"), "{}").unwrap();
            fs::write(dir.path().join("index.json"), index).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(matches!(
                error,
                InputError::MissingManifest | InputError::MissingBlob(_) | InputError::Io { .. }
            ));
        }

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("oci-layout"), "{}").unwrap();
        let claimed = digest(7);
        let blob = dir.path().join(blob_name(&claimed));
        fs::create_dir_all(blob.parent().unwrap()).unwrap();
        fs::write(blob, b"different content").unwrap();
        fs::write(
            dir.path().join("index.json"),
            format!(r#"{{"manifests":[{{"digest":"{claimed}"}}]}}"#),
        )
        .unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config()),
            Err(InputError::DigestMismatch(value)) if value == claimed
        ));
    }
    #[test]
    fn oci_tar_index_and_docker_manifest_variants_are_scanned() {
        let dir = tempdir().unwrap();
        let layer = tar_bytes(&[(
            "go.mod",
            b"module example.com/app\nrequire example.com/mod v1.2.3\n",
        )]);
        let config_json = br#"{"os":"linux"}"#;

        let config_digest = sha256(config_json);
        let layer_digest = sha256(&layer);
        let manifest = format!(
            r#"{{"config":{{"digest":"{config_digest}"}},"layers":[{{"digest":"{layer_digest}"}}]}}"#
        );
        let manifest_digest = sha256(manifest.as_bytes());
        let index = format!(r#"{{"manifests":[{{"digest":"{manifest_digest}"}}]}}"#);
        let oci_path = dir.path().join("image-index.tar");
        write_tar(
            &oci_path,
            &[
                ("oci-layout", b"{}"),
                ("index.json", index.as_bytes()),
                (&blob_name(&manifest_digest), manifest.as_bytes()),
                (&blob_name(&config_digest), config_json),
                (&blob_name(&layer_digest), &layer),
            ],
        );
        assert_eq!(scan_path(&oci_path, &config()).unwrap().components.len(), 1);

        let docker_manifest = br#"[{"Config":"config.json","Layers":["layer.tar"]}]"#;
        let docker_path = dir.path().join("image-docker.tar");
        write_tar(
            &docker_path,
            &[
                ("manifest.json", docker_manifest),
                ("config.json", config_json),
                ("layer.tar", &layer),
            ],
        );
        let inventory = scan_path(&docker_path, &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert_eq!(inventory.asset.metadata["os"], "linux");
        assert_eq!(
            inventory.asset.metadata["manifest_digest"],
            sha256(docker_manifest)
        );
    }
    #[test]
    fn oci_tar_reports_malformed_manifests_missing_layers_and_bad_digests() {
        let dir = tempdir().unwrap();
        type TarEntries<'a> = Vec<(&'a str, &'a [u8])>;
        let cases: Vec<(&str, TarEntries<'_>)> = vec![
            ("empty.tar", vec![("manifest.json", b"[]")]),
            (
                "missing-layer.tar",
                vec![(
                    "manifest.json",
                    br#"[{"Config":"config.json","Layers":["missing.tar"]}]"#,
                )],
            ),
            (
                "bad-digest.tar",
                vec![
                    ("oci-layout", b"{}"),
                    ("index.json", br#"{"manifests":[{"digest":"bad"}]}"#),
                ],
            ),
        ];
        for (name, entries) in cases {
            let path = dir.path().join(name);
            write_tar(&path, &entries);
            assert!(matches!(
                scan_path(&path, &config()),
                Err(InputError::Malformed { .. }
                    | InputError::MissingManifest
                    | InputError::MissingBlob(_)
                    | InputError::DigestMismatch(_))
            ));
        }

        // An object-shaped (or unparseable) manifest.json is a web app
        // manifest or garbage, not a docker-save archive: detection falls
        // back to archive scanning, which rejects the tar as unsupported
        // instead of the image parser's Malformed.
        let path = dir.path().join("web-manifest.tar");
        write_tar(&path, &[("manifest.json", br#"{"name":"app"}"#)]);
        assert!(matches!(
            scan_path(&path, &config()),
            Err(InputError::UnsupportedFormat(_))
        ));

        let claimed = digest(8);
        let index = format!(r#"{{"manifests":[{{"digest":"{claimed}"}}]}}"#);
        let path = dir.path().join("digest-mismatch.tar");
        write_tar(
            &path,
            &[
                ("oci-layout", b"{}"),
                ("index.json", index.as_bytes()),
                (&blob_name(&claimed), b"not the claimed manifest"),
            ],
        );
        assert!(matches!(
            scan_path(&path, &config()),
            Err(InputError::DigestMismatch(value)) if value == claimed
        ));
    }
    #[test]
    fn opaque_whiteout_removes_only_the_target_directory_contents() {
        let first = tar_bytes(&[
            ("app/requirements.txt", b"removed==1\n"),
            ("other/requirements.txt", b"kept==1\n"),
        ]);
        let second = tar_bytes(&[
            ("app/.wh..wh..opq", b""),
            (
                "app/package-lock.json",
                br#"{"dependencies":{"new":{"version":"2"}}}"#,
            ),
        ]);
        let mut filesystem = BTreeMap::new();
        let mut expanded = 0;
        apply_layer(&first, None, &config(), &mut expanded, &mut filesystem).unwrap();
        apply_layer(&second, None, &config(), &mut expanded, &mut filesystem).unwrap();
        assert!(!filesystem.contains_key("app/requirements.txt"));
        assert!(filesystem.contains_key("other/requirements.txt"));
        assert!(filesystem.contains_key("app/package-lock.json"));
        assert!(!filesystem.contains_key("app/.wh..wh..opq"));
    }
    #[test]
    fn image_archive_limit_is_cumulative_across_layers_and_whiteouts() {
        let first = tar_bytes(&[("old", b"1234")]);
        let second = tar_bytes(&[(".wh.old", b""), ("requirements.txt", b"a==1\n")]);
        let mut limited = config();
        limited.max_archive_bytes = 5;
        let mut filesystem = BTreeMap::new();
        let mut expanded = 0;
        apply_layer(&first, None, &limited, &mut expanded, &mut filesystem).unwrap();
        assert!(matches!(
            apply_layer(&second, None, &limited, &mut expanded, &mut filesystem),
            Err(InputError::ArchiveTooLarge {
                actual: 9,
                maximum: 5
            })
        ));
    }
    fn digest(value: u8) -> String {
        format!("sha256:{}", format!("{value:02x}").repeat(32))
    }
    fn blob_name(digest: &str) -> String {
        format!("blobs/sha256/{}", digest.strip_prefix("sha256:").unwrap())
    }
}
