use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Component as PathComponent, Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::Config,
    model::{
        Asset, AssetId, AssetKind, Component, ComponentId, DependencyEdge, Inventory, License,
        Scope, Source, SourceKind, stable_component_id,
    },
    sbom::{self, SbomError},
};

#[path = "parsers/mod.rs"]
mod parsers;

use self::parsers::{
    archive::{read_entry_bounded, read_tar_file, read_zip_file},
    cargo::parse_cargo_lock,
    conda::parse_conda_environment,
    dart::parse_pubspec_lock,
    go::parse_go_mod,
    helm::parse_chart_yaml,
    image::{scan_oci_layout, scan_oci_tar},
    npm::parse_package_lock,
    nuget::parse_nuget_lock,
    php::parse_composer_json,
    pnpm::parse_pnpm_lock,
    python::{parse_pipfile_lock, parse_poetry_lock, parse_requirements},
    ruby::{parse_gemfile_lock, parse_podfile_lock},
    swift::parse_package_resolved,
    yarn::parse_yarn_lock,
};

#[cfg(test)]
pub(crate) use tests::{config, tar_bytes, write_tar};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanInput {
    ProjectDirectory(PathBuf),
    Archive {
        path: PathBuf,
        format: ArchiveFormat,
    },
    OciImageLayout(PathBuf),
    OciImageTar(PathBuf),
    CycloneDx(PathBuf),
}

#[derive(Debug, Error)]
pub enum InputError {
    #[error("input path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("input path is not a regular file or directory: {0}")]
    UnsupportedPath(PathBuf),
    #[error("unsupported input format: {0}")]
    UnsupportedFormat(PathBuf),
    #[error("input path contains or resolves through a symbolic link: {0}")]
    Symlink(PathBuf),
    #[error("path escapes its input root: {0}")]
    PathTraversal(String),
    #[error("input contains a non-UTF-8 path")]
    NonUtf8Path,
    #[error("input size {actual} exceeds maximum {maximum} bytes")]
    InputTooLarge { actual: u64, maximum: u64 },
    #[error("archive expanded size {actual} exceeds maximum {maximum} bytes")]
    ArchiveTooLarge { actual: u64, maximum: u64 },
    #[error("archive has more than {maximum} entries")]
    TooManyArchiveEntries { maximum: usize },
    #[error("archive contains a symbolic or hard link: {0}")]
    ArchiveLink(String),
    #[error("malformed {format} document at {path}: {message}")]
    Malformed {
        path: String,
        format: &'static str,
        message: String,
    },
    #[error("OCI image references missing blob {0}")]
    MissingBlob(String),
    #[error("OCI blob content does not match digest {0}")]
    DigestMismatch(String),
    #[error("OCI image has no manifest")]
    MissingManifest,
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("ZIP error")]
    Zip(#[from] zip::result::ZipError),
    #[error("SBOM error")]
    Sbom(#[from] SbomError),
    #[error("invalid generated inventory")]
    InvalidInventory(#[from] crate::model::ModelInvariantError),
    #[error("invalid stable identifier")]
    InvalidIdentifier,
}

pub fn scan_path(path: impl AsRef<Path>, config: &Config) -> Result<Inventory, InputError> {
    ScanInput::detect(path, config)?.inventory(config)
}

impl ScanInput {
    pub fn detect(path: impl AsRef<Path>, config: &Config) -> Result<Self, InputError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|source| match source.kind() {
            io::ErrorKind::NotFound => InputError::NotFound(path.to_owned()),
            _ => InputError::Io {
                path: path.to_owned(),
                source,
            },
        })?;
        if metadata.file_type().is_symlink() {
            return Err(InputError::Symlink(path.to_owned()));
        }
        let canonical = fs::canonicalize(path).map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?;
        if metadata.is_dir() {
            if canonical.join("oci-layout").is_file() && canonical.join("index.json").is_file() {
                return Ok(Self::OciImageLayout(canonical));
            }
            if has_project_manifest(&canonical)? {
                return Ok(Self::ProjectDirectory(canonical));
            }
            return Err(InputError::UnsupportedFormat(canonical));
        }
        if !metadata.is_file() {
            return Err(InputError::UnsupportedPath(canonical));
        }
        check_file_size(&canonical, config.max_input_bytes)?;
        let lower = canonical
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if lower.ends_with(".cdx.json")
            || lower.ends_with(".cyclonedx.json")
            || looks_like_cyclonedx(&canonical)?
        {
            return Ok(Self::CycloneDx(canonical));
        }
        if lower.ends_with(".spdx.json")
            || crate::sbom::looks_like_spdx(&read_prefix(&canonical, 4096)?)
        {
            return Ok(Self::CycloneDx(canonical));
        }
        if lower.ends_with(".zip") {
            return Ok(Self::Archive {
                path: canonical,
                format: ArchiveFormat::Zip,
            });
        }
        if lower.ends_with(".tar") {
            if tar_is_image(open_regular_nofollow(&canonical)?, config)? {
                return Ok(Self::OciImageTar(canonical));
            }
            return Ok(Self::Archive {
                path: canonical,
                format: ArchiveFormat::Tar,
            });
        }
        Err(InputError::UnsupportedFormat(canonical))
    }

    pub fn inventory(&self, config: &Config) -> Result<Inventory, InputError> {
        match self {
            Self::ProjectDirectory(root) => scan_directory(root, config),
            Self::Archive {
                path,
                format: ArchiveFormat::Zip,
            } => {
                let files = read_zip_file(path, config)?;
                scan_virtual_files(path, AssetKind::Filesystem, files)
            }
            Self::Archive {
                path,
                format: ArchiveFormat::Tar,
            } => {
                let files = read_tar_file(path, config)?;
                scan_virtual_files(path, AssetKind::Filesystem, files)
            }
            Self::OciImageLayout(root) => scan_oci_layout(root, config),
            Self::OciImageTar(path) => scan_oci_tar(path, config),
            Self::CycloneDx(path) => {
                let bytes = read_limited(path, config.max_input_bytes)?;
                Ok(sbom::parse_cyclonedx(&bytes)?)
            }
        }
    }
}

fn scan_directory(root: &Path, config: &Config) -> Result<Inventory, InputError> {
    reject_symlink_ancestors(root)?;
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| InputError::Io {
            path: error.path().unwrap_or(root).to_owned(),
            source: io::Error::other(error),
        })?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| InputError::PathTraversal(entry.path().display().to_string()))?;
        if entry.file_type().is_symlink() {
            return Err(InputError::Symlink(entry.path().to_owned()));
        }
        if !entry.file_type().is_file() || !is_inventory_file(relative) {
            continue;
        }
        let bytes = read_limited(entry.path(), config.max_input_bytes)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or(InputError::InputTooLarge {
                actual: u64::MAX,
                maximum: config.max_input_bytes,
            })?;
        if total > config.max_input_bytes {
            return Err(InputError::InputTooLarge {
                actual: total,
                maximum: config.max_input_bytes,
            });
        }
        files.insert(normalize_relative(relative)?, bytes);
    }
    scan_virtual_files(root, AssetKind::Repository, files)
}

type LockfileParser = fn(&str, &[u8], &mut InventoryBuilder) -> Result<(), InputError>;

/// Single registry of recognized ecosystem lockfiles. Virtual-file dispatch,
/// directory inventory detection, and project-manifest detection all derive
/// from this table so the filename set cannot drift between them.
/// `Cargo.lock` carries `None` because it additionally consumes the sibling
/// `Cargo.toml` manifest for license inheritance.
const LOCKFILES: &[(&str, Option<LockfileParser>)] = &[
    ("Cargo.lock", None),
    ("package-lock.json", Some(parse_package_lock)),
    ("requirements.txt", Some(parse_requirements)),
    ("go.mod", Some(parse_go_mod)),
    ("packages.lock.json", Some(parse_nuget_lock)),
    ("yarn.lock", Some(parse_yarn_lock)),
    ("pnpm-lock.yaml", Some(parse_pnpm_lock)),
    ("poetry.lock", Some(parse_poetry_lock)),
    ("Pipfile.lock", Some(parse_pipfile_lock)),
    ("Gemfile.lock", Some(parse_gemfile_lock)),
    ("Package.resolved", Some(parse_package_resolved)),
    ("pubspec.lock", Some(parse_pubspec_lock)),
    ("Podfile.lock", Some(parse_podfile_lock)),
    ("composer.json", Some(parse_composer_json)),
    ("environment.yml", Some(parse_conda_environment)),
    ("Chart.yaml", Some(parse_chart_yaml)),
];

/// Repository files collected as inventory inputs that have no dedicated
/// parser of their own.
const MANIFEST_SIDECARS: &[&str] = &["Cargo.toml", "go.sum"];

fn lockfile_parser(name: &str) -> Option<Option<LockfileParser>> {
    LOCKFILES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, parser)| *parser)
}

fn scan_virtual_files(
    locator: &Path,
    kind: AssetKind,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<Inventory, InputError> {
    let asset_id = stable_asset(locator, &files)?;
    let mut builder = InventoryBuilder::new(asset_id, locator, kind);
    let mut recognized = false;
    for (path, bytes) in &files {
        if let Some(parser) = lockfile_parser(base_name(path)) {
            match parser {
                Some(parse) => parse(path, bytes, &mut builder)?,
                None => parse_cargo_lock(
                    path,
                    bytes,
                    files.get(&sibling(path, "Cargo.toml")),
                    &mut builder,
                )?,
            }
            recognized = true;
        }
    }
    if !recognized {
        return Err(InputError::UnsupportedFormat(locator.to_owned()));
    }
    builder.finish()
}

struct InventoryBuilder {
    asset: Asset,
    components: BTreeMap<ComponentId, Component>,
    dependencies: BTreeSet<DependencyEdge>,
}

impl InventoryBuilder {
    fn new(id: AssetId, locator: &Path, kind: AssetKind) -> Self {
        Self {
            asset: Asset {
                id,
                name: locator
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("input")
                    .to_owned(),
                kind,
                version: None,
                metadata: BTreeMap::from([(
                    "locator".into(),
                    json!(locator.display().to_string()),
                )]),
            },
            components: BTreeMap::new(),
            dependencies: BTreeSet::new(),
        }
    }

    fn add(
        &mut self,
        ecosystem: &str,
        name: &str,
        version: &str,
        scope: Scope,
        path: &str,
        licenses: BTreeSet<License>,
    ) -> Result<ComponentId, InputError> {
        let purl = package_url(ecosystem, name, version);
        let identity = stable_component_id(&purl).map_err(|_| InputError::InvalidIdentifier)?;
        let source = Source {
            kind: SourceKind::Lockfile,
            locator: path.to_owned(),
            digest: None,
        };
        let locations = BTreeSet::new();
        self.components
            .entry(identity.clone())
            .and_modify(|component| {
                component.provenance.insert(source.clone());
                component.licenses.extend(licenses.clone());
                if component.scope == Scope::Unknown {
                    component.scope = scope;
                }
            })
            .or_insert(Component {
                identity: identity.clone(),
                name: name.to_owned(),
                version: version.to_owned(),
                purl,
                scope,
                provenance: BTreeSet::from([source]),
                licenses,
                locations,
            });
        Ok(identity)
    }

    fn edge(&mut self, from: &ComponentId, to: &ComponentId, scope: Scope, optional: bool) {
        if from != to {
            self.dependencies.insert(DependencyEdge {
                from: from.clone(),
                to: to.clone(),
                scope,
                optional,
            });
        }
    }

    fn finish(self) -> Result<Inventory, InputError> {
        let inventory = Inventory {
            asset: self.asset,
            components: self.components,
            locations: BTreeSet::new(),
            dependencies: self.dependencies,
        };
        inventory.validate()?;
        Ok(inventory)
    }
}

const MAX_LOCKFILE_ENTRIES: usize = 100_000;

fn entry_bound(count: usize, path: &str, format: &'static str) -> Result<(), InputError> {
    if count > MAX_LOCKFILE_ENTRIES {
        Err(malformed_msg(
            path,
            format,
            format!("more than {MAX_LOCKFILE_ENTRIES} entries"),
        ))
    } else {
        Ok(())
    }
}

/// Streams entry names of a plain `.tar` once to decide whether it is an
/// OCI/docker-save image archive, without buffering entry contents. Enforces
/// the same entry-count, link, and path rules as `read_tar_with_expanded`;
/// only `manifest.json` is materialized because its array shape decides
/// docker-save classification (see `is_oci_markers`).
fn tar_is_image<R: Read>(reader: R, config: &Config) -> Result<bool, InputError> {
    let mut archive = tar::Archive::new(reader);
    let mut count = 0_usize;
    let mut expanded = 0_u64;
    let mut has_layout = false;
    let mut has_index = false;
    let mut manifest = None;
    let entries = archive.entries().map_err(|source| InputError::Io {
        path: PathBuf::from("<tar>"),
        source,
    })?;
    for entry in entries {
        count += 1;
        if count > config.max_archive_entries {
            return Err(InputError::TooManyArchiveEntries {
                maximum: config.max_archive_entries,
            });
        }
        let mut entry = entry.map_err(|source| InputError::Io {
            path: PathBuf::from("<tar>"),
            source,
        })?;
        let path = normalize_relative(&entry.path().map_err(|source| InputError::Io {
            path: PathBuf::from("<tar>"),
            source,
        })?)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(InputError::ArchiveLink(path));
        }
        if !entry_type.is_file() {
            continue;
        }
        match path.as_str() {
            "oci-layout" => has_layout = true,
            "index.json" => has_index = true,
            "manifest.json" => {
                let expected = entry.size();
                manifest = Some(read_entry_bounded(
                    &mut entry,
                    expected,
                    &path,
                    "TAR",
                    config,
                    &mut expanded,
                )?);
            }
            _ => {}
        }
    }
    Ok(is_oci_markers(has_layout, has_index, manifest.as_deref()))
}

fn has_project_manifest(root: &Path) -> Result<bool, InputError> {
    for (name, _) in LOCKFILES {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_inventory_file(path: &Path) -> bool {
    path.file_name().and_then(|v| v.to_str()).is_some_and(|v| {
        MANIFEST_SIDECARS.contains(&v) || LOCKFILES.iter().any(|(name, _)| *name == v)
    })
}
/// Decides image classification from archive markers. Only an array-shaped
/// `manifest.json` marks a docker-save archive; object-shaped manifests are
/// web app manifests (PWA), and routing project tarballs that carry one into
/// the image parser rejected valid archives with Malformed instead of
/// scanning their lockfiles.
fn is_oci_markers(has_layout: bool, has_index: bool, manifest_json: Option<&[u8]>) -> bool {
    (has_layout && has_index)
        || manifest_json.is_some_and(|bytes| {
            serde_json::from_slice::<Value>(bytes)
                .map(|value| value.is_array())
                .unwrap_or(false)
        })
}
fn looks_like_cyclonedx(path: &Path) -> Result<bool, InputError> {
    let bytes = read_prefix(path, 4096)?;
    Ok(std::str::from_utf8(&bytes)
        .is_ok_and(|v| v.contains("\"bomFormat\"") && v.contains("CycloneDX")))
}
fn read_prefix(path: &Path, maximum: u64) -> Result<Vec<u8>, InputError> {
    let mut file = open_regular_nofollow(path)?;
    let mut bytes = Vec::with_capacity(maximum.min(usize::MAX as u64) as usize);
    file.by_ref()
        .take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?;
    Ok(bytes)
}
fn check_file_size(path: &Path, maximum: u64) -> Result<(), InputError> {
    let actual = fs::metadata(path)
        .map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?
        .len();
    if actual > maximum {
        Err(InputError::InputTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}
fn open_regular_nofollow(path: &Path) -> Result<File, InputError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW: i32 = 0x20_000;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW: i32 = 0x100;
        options.custom_flags(O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| {
        if is_symlink_open_error(&source) {
            InputError::Symlink(path.to_owned())
        } else {
            InputError::Io {
                path: path.to_owned(),
                source,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| InputError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(InputError::UnsupportedPath(path.to_owned()));
    }
    Ok(file)
}

/// `ELOOP` per target: Linux/Android use 40, Darwin and the BSDs use 62.
/// Raw errno matching is required because `io::ErrorKind::FilesystemLoop`
/// is not available on the pinned toolchain; a single hardcoded 40 would
/// misclassify symlink rejections on every non-Linux unix target.
#[cfg(any(target_os = "linux", target_os = "android"))]
const ELOOP: i32 = 40;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const ELOOP: i32 = 62;

#[cfg(unix)]
fn is_symlink_open_error(source: &io::Error) -> bool {
    source.raw_os_error() == Some(ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_: &io::Error) -> bool {
    false
}
fn read_limited(path: &Path, maximum: u64) -> Result<Vec<u8>, InputError> {
    let mut file = open_regular_nofollow(path)?;
    let file_size = file
        .metadata()
        .map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?
        .len();
    if file_size > maximum {
        return Err(InputError::InputTooLarge {
            actual: maximum.saturating_add(1).min(file_size),
            maximum,
        });
    }
    let capacity = usize::try_from(file_size).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?;
    let actual = bytes.len() as u64;
    if actual > maximum {
        Err(InputError::InputTooLarge { actual, maximum })
    } else {
        Ok(bytes)
    }
}
fn reject_symlink_ancestors(path: &Path) -> Result<(), InputError> {
    let canonical = fs::canonicalize(path).map_err(|source| InputError::Io {
        path: path.to_owned(),
        source,
    })?;
    if canonical != path {
        return Err(InputError::Symlink(path.to_owned()));
    }
    Ok(())
}
fn reject_symlink_ancestors_below(root: &Path, path: &Path) -> Result<(), InputError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| InputError::PathTraversal(path.display().to_string()))?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|source| InputError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(InputError::Symlink(current));
        }
    }
    Ok(())
}
pub(crate) fn normalize_relative(path: &Path) -> Result<String, InputError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            PathComponent::Normal(value) => {
                parts.push(value.to_str().ok_or(InputError::NonUtf8Path)?)
            }
            PathComponent::CurDir => {}
            _ => return Err(InputError::PathTraversal(path.display().to_string())),
        }
    }
    if parts.is_empty() {
        return Err(InputError::PathTraversal(path.display().to_string()));
    }
    Ok(parts.join("/"))
}
fn sibling(path: &str, name: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| format!("{parent}/{name}"))
        .unwrap_or_else(|| name.to_owned())
}
fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
fn package_url(ecosystem: &str, name: &str, version: &str) -> String {
    // Name keeps `/` (composer/golang namespace paths) and escapes only the
    // bytes the purl grammar reserves (`?`/`#` delimit qualifiers and
    // fragments, so they must never leak into the purl body) or that
    // parsers leak into names.
    let encoded = name
        .replace('%', "%25")
        .replace('@', "%40")
        .replace(' ', "%20")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('?', "%3F")
        .replace('#', "%23");
    match concrete_version_specifier(version) {
        // Range constraints (^8.1, 1.24.*, >=2) are specifiers, not versions:
        // baking them in produced purls the spec rejects that could never
        // match an OSV advisory. A versionless purl keeps the component
        // honest (raw specifier stays on Component.version) and lets OSV
        // match the package across its versions.
        Some(version) => {
            let encoded_version = crate::util::percent_encode(&version, crate::util::is_purl_byte);
            format!("pkg:{ecosystem}/{encoded}@{encoded_version}")
        }
        None => format!("pkg:{ecosystem}/{encoded}"),
    }
}

/// Returns the concrete purl version for a specifier, stripping pnpm-style
/// `1.2.3(integrity)` annotations, or `None` for empty values and range
/// constraints (`^1.2`, `~1.2`, `>=1`, `1.*`, `a || b`, `git+https://…`).
fn concrete_version_specifier(version: &str) -> Option<String> {
    let trimmed = version.trim();
    let concrete = trimmed.split('(').next().unwrap_or(trimmed).trim_end();
    if concrete.is_empty()
        || concrete.chars().any(|c| {
            matches!(c, '^' | '~' | '>' | '<' | '*' | ',' | '|' | '!' | '=' | ':')
                || c.is_whitespace()
        })
    {
        return None;
    }
    Some(concrete.to_owned())
}

fn stable_asset(locator: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<AssetId, InputError> {
    let mut hash = Sha256::new();
    hash.update(locator.to_string_lossy().as_bytes());
    for (path, bytes) in files {
        hash.update(path.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    AssetId::new(format!("asset:sha256:{:x}", hash.finalize()))
        .map_err(|_| InputError::InvalidIdentifier)
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::util::sha256_hex(bytes))
}
fn utf8<'a>(bytes: &'a [u8], path: &str, format: &'static str) -> Result<&'a str, InputError> {
    std::str::from_utf8(bytes).map_err(|e| malformed(path, format, e))
}
fn malformed(
    path: impl ToString,
    format: &'static str,
    error: impl std::fmt::Display,
) -> InputError {
    InputError::Malformed {
        path: path.to_string(),
        format,
        message: error.to_string(),
    }
}
fn malformed_msg(path: impl ToString, format: &'static str, message: impl ToString) -> InputError {
    InputError::Malformed {
        path: path.to_string(),
        format,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    pub(crate) fn config() -> Config {
        Config {
            max_input_bytes: 1024 * 1024,
            max_archive_bytes: 1024 * 1024,
            max_archive_entries: 100,
            ..Config::default()
        }
    }

    pub(crate) fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    }

    pub(crate) fn write_tar(path: &Path, entries: &[(&str, &[u8])]) {
        fs::write(path, tar_bytes(entries)).unwrap();
    }

    #[test]
    fn scans_requirements_go_and_nuget() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            concat!(
                "requests==2.32.0 \\\n",
                "    --hash=sha256:abc \\\n",
                "    --hash=sha256:def\n",
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\nrequire (\n golang.org/x/text v0.3.0\n)\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("go.sum"),
            "golang.org/x/text v0.2.0 h1:old\ngolang.org/x/unused v9.9.9 h1:history\n",
        )
        .unwrap();
        fs::write(dir.path().join("packages.lock.json"), r#"{"dependencies":{"net8.0":{"A":{"type":"Direct","resolved":"1.0","dependencies":{"B":"2.0"}},"B":{"type":"Transitive","resolved":"2.0"}}}}"#).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 4);
        assert_eq!(inventory.dependencies.len(), 1);
        assert!(
            inventory
                .components
                .values()
                .any(|component| { component.name == "requests" && component.version == "2.32.0" })
        );
        assert!(inventory.components.values().any(|component| {
            component.name == "golang.org/x/text" && component.version == "v0.3.0"
        }));
        assert!(!inventory.components.values().any(|component| {
            component.name == "golang.org/x/unused" || component.version == "v0.2.0"
        }));
    }

    #[test]
    fn delegates_cyclonedx() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bom.cdx.json");
        fs::write(&path, r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#).unwrap();
        assert_eq!(scan_path(&path, &config()).unwrap().components.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_directory_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("requirements.txt"), "a==1\n").unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            ScanInput::detect(&link, &config()),
            Err(InputError::Symlink(_))
        ));
    }

    #[test]
    fn detection_reports_missing_empty_unsupported_and_oversized_inputs() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            ScanInput::detect(dir.path().join("missing"), &config()),
            Err(InputError::NotFound(_))
        ));
        assert!(matches!(
            ScanInput::detect(dir.path(), &config()),
            Err(InputError::UnsupportedFormat(_))
        ));

        let unsupported = dir.path().join("notes.txt");
        fs::write(&unsupported, "not an inventory").unwrap();
        assert!(matches!(
            ScanInput::detect(&unsupported, &config()),
            Err(InputError::UnsupportedFormat(_))
        ));

        let archive = dir.path().join("large.zip");
        fs::write(&archive, [0_u8; 5]).unwrap();
        let mut limited = config();
        limited.max_input_bytes = 4;
        assert!(matches!(
            ScanInput::detect(&archive, &limited),
            Err(InputError::InputTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn detection_routes_spdx_documents_by_extension_and_content() {
        let dir = tempdir().unwrap();
        let document = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x"}"#;
        for name in ["sbom.spdx.json", "plain.json"] {
            let path = dir.path().join(name);
            fs::write(&path, document).unwrap();
            assert!(
                matches!(
                    ScanInput::detect(&path, &config()),
                    Ok(ScanInput::CycloneDx(_))
                ),
                "{name} should route to the SBOM entry"
            );
        }
        let cyclonedx = dir.path().join("bom.json");
        fs::write(
            &cyclonedx,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
        )
        .unwrap();
        assert!(matches!(
            ScanInput::detect(&cyclonedx, &config()),
            Ok(ScanInput::CycloneDx(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn detection_rejects_non_file_non_directory_paths() {
        assert!(matches!(
            ScanInput::detect("/dev/null", &config()),
            Err(InputError::UnsupportedPath(_))
        ));
    }

    #[test]
    fn malformed_ecosystem_inputs_name_the_rejected_format() {
        let cases = [
            ("Cargo.lock", "not = [toml", "Cargo.lock"),
            ("package-lock.json", "{", "package-lock.json"),
            ("requirements.txt", "unpinned>=1\n", "requirements.txt"),
            ("go.mod", "require (\nmodule version\n", "go.mod"),
            ("packages.lock.json", "{}", "packages.lock.json"),
        ];
        for (name, contents, expected_format) in cases {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), contents).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(matches!(
                error,
                InputError::Malformed { format, .. } if format == expected_format
            ));
        }
    }

    #[test]
    fn malformed_structured_packages_report_missing_required_fields() {
        let cases = [
            ("Cargo.lock", "version=3\n[[package]]\nname='a'\n"),
            (
                "package-lock.json",
                r#"{"packages":{"node_modules/a":{"name":"a"}}}"#,
            ),
            (
                "packages.lock.json",
                r#"{"dependencies":{"net8.0":{"A":{"type":"Direct"}}}}"#,
            ),
        ];
        for (name, contents) in cases {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), contents).unwrap();
            assert!(matches!(
                scan_path(dir.path(), &config()),
                Err(InputError::Malformed { .. })
            ));
        }
    }

    #[test]
    fn zero_input_limit_rejects_nonempty_file_but_accepts_empty_file_size() {
        let mut file = NamedTempFile::new().unwrap();
        let mut zero = config();
        zero.max_input_bytes = 0;
        assert_eq!(read_limited(file.path(), 0).unwrap(), Vec::<u8>::new());
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        assert!(matches!(
            read_limited(file.path(), zero.max_input_bytes),
            Err(InputError::InputTooLarge {
                actual: 1,
                maximum: 0
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_symlink_and_reads_only_limit_plus_one() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, vec![b'x'; 1024 * 1024]).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            read_limited(&link, 4),
            Err(InputError::Symlink(_))
        ));
        assert!(matches!(
            read_limited(&real, 4),
            Err(InputError::InputTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    fn new_ecosystem_fixture(name: &str) -> &'static str {
        match name {
            "yarn.lock" => "a@1:\n  version \"1\"\n",
            "pnpm-lock.yaml" => {
                "lockfileVersion: '9.0'\npackages:\n  a@1:\n    resolution: {integrity: sha512-x}\n"
            }
            "poetry.lock" => "[[package]]\nname = 'a'\nversion = '1'\n",
            "Pipfile.lock" => "{}",
            "Gemfile.lock" => "GEM\n  specs:\n    a (1)\n",
            "Package.resolved" => "{\"pins\":[]}",
            "pubspec.lock" => "packages: {}\n",
            "Podfile.lock" => "PODS:\n  - A (1)\n",
            "composer.json" => "{}",
            "environment.yml" => "dependencies: []\n",
            _ => "apiVersion: v2\n",
        }
    }

    #[test]
    fn detects_new_ecosystem_project_directories() {
        for name in [
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "Pipfile.lock",
            "Gemfile.lock",
            "Package.resolved",
            "pubspec.lock",
            "Podfile.lock",
            "composer.json",
            "environment.yml",
            "Chart.yaml",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), new_ecosystem_fixture(name)).unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert_eq!(inventory.asset.kind, AssetKind::Repository, "{name}");
        }
    }

    #[test]
    fn scans_gemfile_and_package_resolved_locks() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Gemfile.lock"),
            concat!(
                "GEM\n",
                "  remote: https://rubygems.org/\n",
                "  specs:\n",
                "    rake (13.0.6)\n",
                "    nokogiri (1.15.2-x86_64-linux)\n",
                "    bundler (2.4.10, 2.4.19)\n",
                "\n",
                "PLATFORMS\n",
                "  ruby\n",
                "  x86_64-linux\n",
                "\n",
                "DEPENDENCIES\n",
                "  rake\n",
                "\n",
                "BUNDLED WITH\n",
                "   2.4.19\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let version_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.version.clone())
        };
        assert_eq!(version_of("rake").as_deref(), Some("13.0.6"));
        assert_eq!(version_of("nokogiri").as_deref(), Some("1.15.2"));
        assert_eq!(version_of("bundler").as_deref(), Some("2.4.10"));
        assert_eq!(inventory.components.len(), 3);

        let resolved = tempdir().unwrap();
        fs::write(
            resolved.path().join("Package.resolved"),
            r#"{"version":2,"pins":[{"identity":"swift-log","kind":"remoteSourceXCMerge","state":{"version":"1.5.3"}},{"identity":"swift-argument-parser","kind":"remoteSourceXCMerge","state":{"revision":"abc123","branch":"main"}}]}"#,
        )
        .unwrap();
        let inventory = scan_path(resolved.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "swift-log" && c.version == "1.5.3")
        );

        let legacy = tempdir().unwrap();
        fs::write(
            legacy.path().join("Package.resolved"),
            r#"{"object":{"pins":[{"package":"Alamofire","repositoryURL":"https://github.com/Alamofire/Alamofire.git","state":{"version":"5.8.0"}}]}}"#,
        )
        .unwrap();
        let inventory = scan_path(legacy.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "Alamofire" && c.version == "5.8.0")
        );
    }

    #[test]
    fn scans_pubspec_and_podfile_locks() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pubspec.lock"),
            concat!(
                "sdks:\n",
                "  dart: \">=3.0.0 <4.0.0\"\n",
                "packages:\n",
                "  http:\n",
                "    dependency: \"direct main\"\n",
                "    source: hosted\n",
                "    version: \"1.1.0\"\n",
                "  test:\n",
                "    dependency: \"direct dev\"\n",
                "    source: hosted\n",
                "    version: \"1.24.3\"\n",
                "  collection:\n",
                "    dependency: transitive\n",
                "    source: hosted\n",
                "    version: \"1.18.0\"\n",
                "  flutter:\n",
                "    dependency: \"direct main\"\n",
                "    source: sdk\n",
                "    version: \"0.0.0\"\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let scope_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.scope)
        };
        assert_eq!(scope_of("http"), Some(Scope::Runtime));
        assert_eq!(scope_of("test"), Some(Scope::Development));
        assert_eq!(scope_of("collection"), Some(Scope::Runtime));
        assert_eq!(inventory.components.len(), 3);

        let pods = tempdir().unwrap();
        fs::write(
            pods.path().join("Podfile.lock"),
            concat!(
                "PODS:\n",
                "  - SDWebImage/Core (5.15.5)\n",
                "  - SDWebImage/MapKit (5.15.5)\n",
                "  - Firebase/Auth (10.4.0)\n",
                "\n",
                "DEPENDENCIES:\n",
                "  - Firebase/Auth (= 10.4.0)\n",
                "\n",
                "SPEC REPOS:\n",
                "  trunk:\n",
                "    - Firebase\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(pods.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 2);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "SDWebImage" && c.version == "5.15.5")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "Firebase" && c.version == "10.4.0")
        );
    }

    #[test]
    fn scans_composer_conda_and_chart_inputs() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            r#"{"name":"acme/app","version":"1.2.3","require":{"php":">=8.1","ext-json":"*","symfony/console":"^6.3","monolog/monolog":"^3.0"},"require-dev":{"phpunit/phpunit":"^10.0"}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.version.as_deref(), Some("1.2.3"));
        let scope_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.scope)
        };
        assert_eq!(scope_of("symfony/console"), Some(Scope::Runtime));
        assert_eq!(scope_of("phpunit/phpunit"), Some(Scope::Development));
        assert!(
            !inventory
                .components
                .values()
                .any(|c| c.name == "php" || c.name == "ext-json")
        );
        assert_eq!(inventory.components.len(), 3);

        let conda = tempdir().unwrap();
        fs::write(
            conda.path().join("environment.yml"),
            concat!(
                "name: ml\n",
                "dependencies:\n",
                "  - python=3.11\n",
                "  - conda-forge::numpy=1.24.*\n",
                "  - pytorch>=2.0,<3\n",
                "  - pip\n",
                "  - pip:\n",
                "      - requests==2.31.0\n",
                "      - --index-url https://example.com/simple\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(conda.path(), &config()).unwrap();
        let version_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.version.clone())
        };
        assert_eq!(version_of("python").as_deref(), Some("3.11"));
        assert_eq!(version_of("numpy").as_deref(), Some("1.24.*"));
        assert_eq!(version_of("pytorch").as_deref(), Some("2.0"));
        assert_eq!(version_of("requests").as_deref(), Some("2.31.0"));
        assert_eq!(inventory.components.len(), 4);

        let chart = tempdir().unwrap();
        fs::write(
            chart.path().join("Chart.yaml"),
            concat!(
                "apiVersion: v2\n",
                "name: myapp\n",
                "version: 1.4.2\n",
                "dependencies:\n",
                "  - name: postgresql\n",
                "    version: \"13.2.0\"\n",
                "    repository: https://charts.bitnami.com/bitnami\n",
                "  - name: redis\n",
                "    version: \"17.15.0\"\n",
                "    condition: redis.enabled\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(chart.path(), &config()).unwrap();
        assert_eq!(inventory.asset.version.as_deref(), Some("1.4.2"));
        assert_eq!(inventory.components.len(), 2);
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "postgresql" && c.version == "13.2.0")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "redis" && c.version == "17.15.0")
        );
    }

    #[test]
    fn malformed_new_ecosystem_inputs_name_the_rejected_format() {
        let cases = [
            (
                "yarn.lock",
                "left-pad@^1.3.0\n  version \"1.3.0\"\n",
                "yarn.lock",
            ),
            ("pnpm-lock.yaml", "packages: 42\n", "pnpm-lock.yaml"),
            ("poetry.lock", "[[package]]\nname = 'a'\n", "poetry.lock"),
            ("Pipfile.lock", "[1,2]", "Pipfile.lock"),
            ("Gemfile.lock", "GEM\n  specs:\n    rake\n", "Gemfile.lock"),
            ("Package.resolved", "{\"pins\": 42}", "Package.resolved"),
            ("pubspec.lock", "packages: 42\n", "pubspec.lock"),
            ("Podfile.lock", "PODS:\n  - SDWebImage\n", "Podfile.lock"),
            ("composer.json", "[1]", "composer.json"),
            ("environment.yml", "dependencies: 42\n", "environment.yml"),
            ("Chart.yaml", "dependencies: [unclosed\n", "Chart.yaml"),
        ];
        for (name, contents, expected_format) in cases {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), contents).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(
                matches!(
                    error,
                    InputError::Malformed { format, .. } if format == expected_format
                ),
                "unexpected error for {name}"
            );
        }
    }

    #[test]
    fn lockfile_entry_bound_rejects_oversized_counts() {
        let error = entry_bound(MAX_LOCKFILE_ENTRIES + 1, "yarn.lock", "yarn.lock").unwrap_err();
        assert!(matches!(
            error,
            InputError::Malformed { format, .. } if format == "yarn.lock"
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "malformed yarn.lock document at yarn.lock: more than {MAX_LOCKFILE_ENTRIES} entries"
            )
        );
        assert!(entry_bound(MAX_LOCKFILE_ENTRIES, "yarn.lock", "yarn.lock").is_ok());
    }
    #[test]
    fn package_url_omits_range_constraints_and_encodes_versions() {
        // Range constraints are specifiers, not versions: they must not be
        // baked into purls (silent OSV misses).
        assert_eq!(
            package_url("composer", "symfony/console", "^6.3"),
            "pkg:composer/symfony/console"
        );
        assert_eq!(package_url("conda", "numpy", "1.24.*"), "pkg:conda/numpy");
        assert_eq!(package_url("npm", "a", ">=1.0 <2"), "pkg:npm/a");
        // pnpm annotates resolved versions with an integrity hash.
        assert_eq!(
            package_url("npm", "a", "1.2.3(integrity)"),
            "pkg:npm/a@1.2.3"
        );
        // Concrete versions keep their separator and gain spec encoding.
        assert_eq!(
            package_url("pypi", "requests[security]", "2.32.0"),
            "pkg:pypi/requests%5Bsecurity%5D@2.32.0"
        );
        assert_eq!(
            package_url("npm", "a", "1.0.0-beta.1+exp.sha.5114f85"),
            "pkg:npm/a@1.0.0-beta.1+exp.sha.5114f85"
        );
        assert_eq!(package_url("npm", "a", "50%"), "pkg:npm/a@50%25");
    }

    #[test]
    fn package_url_escapes_query_and_fragment_delimiters_in_name() {
        // '?' and '#' are purl grammar-reserved: without escaping they would
        // start a qualifier or fragment and strand the version outside it.
        assert_eq!(
            package_url("gem", "c#frag?q", "1.0"),
            "pkg:gem/c%23frag%3Fq@1.0"
        );
        assert_eq!(package_url("npm", "a#b", ""), "pkg:npm/a%23b");
    }

    #[test]
    fn pypi_and_nuget_names_normalize_to_canonical_purls() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "Django==5.0\ndjangO==5.0\nrequests[security]==2.32.0\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("Pipfile.lock"),
            r#"{"default":{"Foo_Bar":{"version":"==1.0"}}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("packages.lock.json"),
            r#"{"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let purl_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.purl.clone())
        };
        // Case variants collapse into one identity; extras are stripped.
        assert_eq!(purl_of("django").as_deref(), Some("pkg:pypi/django@5.0"));
        assert_eq!(
            purl_of("requests").as_deref(),
            Some("pkg:pypi/requests@2.32.0")
        );
        assert_eq!(purl_of("foo-bar").as_deref(), Some("pkg:pypi/foo-bar@1.0"));
        assert_eq!(
            purl_of("newtonsoft.json").as_deref(),
            Some("pkg:nuget/newtonsoft.json@13.0.1")
        );
        assert_eq!(inventory.components.len(), 4);
    }

    #[test]
    fn project_tar_with_web_manifest_is_scanned_as_archive() {
        let dir = tempdir().unwrap();
        let tar_path = dir.path().join("project.tar");
        write_tar(
            &tar_path,
            &[
                (
                    "manifest.json",
                    br#"{"name":"app","start_url":"/","icons":[]}"#,
                ),
                (
                    "package-lock.json",
                    br#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"version":"1.0"}}}"#,
                ),
            ],
        );
        let inventory = scan_path(&tar_path, &config()).unwrap();
        assert_eq!(inventory.asset.kind, AssetKind::Filesystem);
        assert!(inventory.components.values().any(|c| c.name == "a"));
    }

    #[test]
    fn previously_unbounded_parsers_reject_oversized_lockfiles() {
        let config = Config {
            max_input_bytes: 1 << 30,
            ..Config::default()
        };

        let requirements: String = (0..MAX_LOCKFILE_ENTRIES + 1)
            .map(|i| format!("p{i}==1.0.0\n"))
            .collect();
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), requirements).unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config),
            Err(InputError::Malformed { format, .. }) if format == "requirements.txt"
        ));

        let cargo: String = (0..MAX_LOCKFILE_ENTRIES + 1)
            .map(|i| format!("[[package]]\nname = 'p{i}'\nversion = '1.0.0'\n"))
            .collect();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.lock"),
            format!("version = 3\n{cargo}"),
        )
        .unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config),
            Err(InputError::Malformed { format, .. }) if format == "Cargo.lock"
        ));

        let go_mod: String = (0..MAX_LOCKFILE_ENTRIES + 1)
            .map(|i| format!("require g.org/p{i} v1.0.0\n"))
            .collect();
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("go.mod"), go_mod).unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config),
            Err(InputError::Malformed { format, .. }) if format == "go.mod"
        ));

        let entries: Vec<String> = (0..MAX_LOCKFILE_ENTRIES + 1)
            .map(|i| format!(r#""node_modules/p{i}":{{"name":"p{i}","version":"1.0.0"}}"#))
            .collect();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            format!(r#"{{"name":"app","packages":{{{}}}}}"#, entries.join(",")),
        )
        .unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config),
            Err(InputError::Malformed { format, .. }) if format == "package-lock.json"
        ));
    }
}
