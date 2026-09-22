use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    mem::MaybeUninit,
    path::{Component as PathComponent, Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::Config,
    filesystem::repository_walk,
    model::{
        Asset, AssetId, AssetKind, Component, ComponentId, DependencyEdge, Inventory, License,
        Scope, Source, SourceKind, stable_component_id,
    },
    sbom::{self, SbomError},
};

#[path = "parsers/mod.rs"]
mod parsers;

use self::parsers::{
    archive::{
        decompress_archive, read_entry_bounded, read_tar_file, read_zip_file, tar_entry_path,
    },
    bun::parse_bun_lock,
    cargo::parse_cargo_lock,
    conda::parse_conda_environment,
    dart::parse_pubspec_lock,
    elixir::parse_mix_lock,
    go::parse_go_mod,
    gradle::parse_gradle_lockfile,
    gradle_catalog::parse_gradle_catalog,
    haskell::{parse_cabal, parse_cabal_freeze},
    helm::{parse_chart_lock, parse_chart_yaml},
    image::{oci_layout_filesystem, oci_tar_filesystem, scan_oci_layout, scan_oci_tar},
    maven::parse_pom_xml,
    npm::parse_package_lock,
    nuget::{
        parse_csproj, parse_directory_packages_props, parse_nuget_lock, parse_packages_config,
    },
    php::{parse_composer_json, parse_composer_lock},
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
    #[error("OCI image layer uses unsupported media type {0}")]
    UnsupportedLayerMediaType(String),
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
            return Ok(Self::ProjectDirectory(canonical));
        }
        if !metadata.is_file() {
            return Err(InputError::UnsupportedPath(canonical));
        }
        // Archive inputs are container/archive payloads, not single input
        // files: bound them by the archive budget so a >100 MiB image tar
        // scans like the equivalent unpacked layout.
        let is_tar = canonical
            .file_name()
            .and_then(|v| v.to_str())
            .map(|name| {
                let name = name.to_ascii_lowercase();
                name.ends_with(".tar")
                    || name.ends_with(".tar.gz")
                    || name.ends_with(".tgz")
                    || name.ends_with(".tar.zst")
            })
            .unwrap_or(false);
        check_file_size(
            &canonical,
            if is_tar {
                config.max_archive_bytes
            } else {
                config.max_input_bytes
            },
        )?;
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
        if lower.ends_with(".tar")
            || lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".tar.zst")
        {
            if tar_is_image(
                decompress_archive(open_regular_nofollow(&canonical)?)?,
                config,
            )? {
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

    /// Extracted member contents for archive and image inputs, so filesystem
    /// scanners and license detection can evaluate what `scan_virtual_files`
    /// saw beyond lockfiles. `None` for real-directory and SBOM inputs
    /// (scanners walk those paths directly).
    pub fn virtual_files(
        &self,
        config: &Config,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>, InputError> {
        match self {
            Self::Archive {
                path,
                format: ArchiveFormat::Zip,
            } => Ok(Some(read_zip_file(path, config)?)),
            Self::Archive {
                path,
                format: ArchiveFormat::Tar,
            } => Ok(Some(read_tar_file(path, config)?)),
            Self::OciImageLayout(root) => Ok(Some(oci_layout_filesystem(root, config)?)),
            Self::OciImageTar(path) => Ok(Some(oci_tar_filesystem(path, config)?)),
            _ => Ok(None),
        }
    }
}

fn scan_directory(root: &Path, config: &Config) -> Result<Inventory, InputError> {
    reject_symlink_ancestors(root)?;
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for entry in repository_walk(root, false, None) {
        let entry = entry.map_err(|error| InputError::Io {
            path: root.to_owned(),
            source: io::Error::other(error),
        })?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| InputError::PathTraversal(entry.path().display().to_string()))?;
        if entry.file_type().is_some_and(|kind| kind.is_symlink()) {
            // The repository walk does not follow links here. Ignore nested links so a
            // repository containing ordinary package-manager or tooling
            // links remains scannable without admitting content outside root.
            continue;
        }
        if !entry.file_type().is_some_and(|kind| kind.is_file()) || !is_inventory_file(relative) {
            continue;
        }
        let bytes = read_limited_below(root, entry.path(), config.max_input_bytes)?;
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
type ManifestParser =
    fn(&str, &[u8], Option<&Vec<u8>>, &mut InventoryBuilder) -> Result<(), InputError>;

/// Lockfile parser that additionally sees the whole scanned file set (for
/// in-tree parent/manifest resolution, e.g. Maven `<parent>` POMs).
type TreeLockfileParser =
    fn(&str, &[u8], &BTreeMap<String, Vec<u8>>, &mut InventoryBuilder) -> Result<(), InputError>;

/// How a recognized inventory file is dispatched.
enum LockfileRoute {
    /// Plain lockfile parser.
    Lock(LockfileParser),
    /// Lockfile parser that receives the full scanned file set.
    LockTree(TreeLockfileParser),
    /// `Cargo.lock`, which additionally consumes the sibling `Cargo.toml`
    /// manifest for license inheritance.
    CargoLock,
    /// Manifest whose dependency declarations are superseded by a sibling
    /// lockfile (`composer.json`/`composer.lock`, `Chart.yaml`/`Chart.lock`,
    /// `package.json` plus any npm-family lockfile).
    Manifest {
        parse: ManifestParser,
        lock_names: &'static [&'static str],
    },
}

/// Single registry of recognized ecosystem lockfiles. Virtual-file dispatch,
/// directory inventory detection, and project-manifest detection all derive
/// from this table so the filename set cannot drift between them.
const LOCKFILES: &[(&str, LockfileRoute)] = &[
    ("Cargo.lock", LockfileRoute::CargoLock),
    ("package-lock.json", LockfileRoute::Lock(parse_package_lock)),
    (
        "npm-shrinkwrap.json",
        LockfileRoute::Lock(parse_package_lock),
    ),
    ("requirements.txt", LockfileRoute::Lock(parse_requirements)),
    ("go.mod", LockfileRoute::Lock(parse_go_mod)),
    ("packages.lock.json", LockfileRoute::Lock(parse_nuget_lock)),
    ("yarn.lock", LockfileRoute::Lock(parse_yarn_lock)),
    ("pnpm-lock.yaml", LockfileRoute::Lock(parse_pnpm_lock)),
    ("bun.lock", LockfileRoute::Lock(parse_bun_lock)),
    ("poetry.lock", LockfileRoute::Lock(parse_poetry_lock)),
    (
        "cabal.project.freeze",
        LockfileRoute::Lock(parse_cabal_freeze),
    ),
    ("Pipfile.lock", LockfileRoute::Lock(parse_pipfile_lock)),
    ("Gemfile.lock", LockfileRoute::Lock(parse_gemfile_lock)),
    ("mix.lock", LockfileRoute::Lock(parse_mix_lock)),
    (
        "Package.resolved",
        LockfileRoute::Lock(parse_package_resolved),
    ),
    ("pubspec.lock", LockfileRoute::Lock(parse_pubspec_lock)),
    ("Podfile.lock", LockfileRoute::Lock(parse_podfile_lock)),
    (
        "package.json",
        LockfileRoute::Manifest {
            parse: parse_package_json,
            lock_names: &[
                "package-lock.json",
                "npm-shrinkwrap.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                "bun.lock",
            ],
        },
    ),
    (
        "composer.json",
        LockfileRoute::Manifest {
            parse: parse_composer_json,
            lock_names: &["composer.lock"],
        },
    ),
    ("composer.lock", LockfileRoute::Lock(parse_composer_lock)),
    (
        "environment.yml",
        LockfileRoute::Lock(parse_conda_environment),
    ),
    (
        "Chart.yaml",
        LockfileRoute::Manifest {
            parse: parse_chart_yaml,
            lock_names: &["Chart.lock"],
        },
    ),
    ("Chart.lock", LockfileRoute::Lock(parse_chart_lock)),
    (
        "Directory.Packages.props",
        LockfileRoute::Lock(parse_directory_packages_props),
    ),
    (
        "packages.config",
        LockfileRoute::Lock(parse_packages_config),
    ),
    ("pom.xml", LockfileRoute::LockTree(parse_pom_xml)),
];

/// Repository files collected as inventory inputs that have no dedicated
/// parser of their own.
const MANIFEST_SIDECARS: &[&str] = &["Cargo.toml", "go.sum"];

/// Resolves an inventory file to its route. Most lockfiles match by exact
/// base name; MSBuild project files, Gradle dependency lockfiles, and Gradle
/// version catalogs are recognized by their `.csproj`/`.lockfile`/
/// `.versions.toml` extensions because the project, configuration, or
/// catalog name is part of the filename.
fn lockfile_route(name: &str) -> Option<&'static LockfileRoute> {
    if let Some(route) = LOCKFILES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, route)| route)
    {
        return Some(route);
    }
    if name.ends_with(".csproj") || name.ends_with(".fsproj") || name.ends_with(".vbproj") {
        return Some(&MSBUILD_PROJ_ROUTE);
    }
    if name.ends_with(".versions.toml") {
        return Some(&GRADLE_CATALOG_ROUTE);
    }
    if name.ends_with(".cabal") {
        return Some(&CABAL_ROUTE);
    }
    name.ends_with(".lockfile")
        .then_some(&GRADLE_LOCKFILE_ROUTE)
}

/// Routes for extension-matched files, stored as statics so
/// `lockfile_route` can return shared references.
static MSBUILD_PROJ_ROUTE: LockfileRoute = LockfileRoute::Lock(parse_csproj);
static GRADLE_LOCKFILE_ROUTE: LockfileRoute = LockfileRoute::Lock(parse_gradle_lockfile);
static GRADLE_CATALOG_ROUTE: LockfileRoute = LockfileRoute::Lock(parse_gradle_catalog);
static CABAL_ROUTE: LockfileRoute = LockfileRoute::LockTree(parse_cabal);

fn scan_virtual_files(
    locator: &Path,
    kind: AssetKind,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<Inventory, InputError> {
    let mut builder = InventoryBuilder::new(locator, kind);
    for (path, bytes) in &files {
        let Some(route) = lockfile_route(base_name(path)) else {
            continue;
        };
        match route {
            LockfileRoute::Lock(parse) => parse(path, bytes, &mut builder)?,
            LockfileRoute::LockTree(parse) => parse(path, bytes, &files, &mut builder)?,
            LockfileRoute::CargoLock => parse_cargo_lock(
                path,
                bytes,
                files.get(&sibling(path, "Cargo.toml")),
                &mut builder,
            )?,
            LockfileRoute::Manifest { parse, lock_names } => {
                // The manifest's declared constraints are superseded by any
                // sibling lockfile; the parser still receives the first
                // present lockfile so it can skip redundant work.
                let lock = lock_names
                    .iter()
                    .find_map(|name| files.get(&sibling(path, name)));
                parse(path, bytes, lock, &mut builder)?;
            }
        }
    }
    // A recognized container/archive kind that carries no lockfiles yields an
    // empty inventory, matching the directory contract.
    builder.finish(locator, &files)
}

struct InventoryBuilder {
    asset: Asset,
    components: BTreeMap<ComponentId, Component>,
    dependencies: BTreeSet<DependencyEdge>,
    /// Depth (path-separator count) of the lockfile that last claimed each
    /// asset identity field; `None` while the field is unclaimed.
    asset_name_depth: Option<usize>,
    asset_version_depth: Option<usize>,
}

impl InventoryBuilder {
    fn new(locator: &Path, kind: AssetKind) -> Self {
        Self {
            asset: Asset {
                // Placeholder: `finish` derives the stable identity from the
                // locator plus the claimed project name once parsing is done.
                id: AssetId::new("asset:unresolved").expect("static asset id is valid"),
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
            asset_name_depth: None,
            asset_version_depth: None,
        }
    }

    /// Applies a lockfile's asset identity claim. Asset identity is anchored
    /// to the lockfile closest to the scan root: a field claim applies only
    /// when no shallower lockfile already claimed that field, so nested
    /// lockfiles contribute components and edges but never override identity
    /// set closer to the root. Claims at equal depth keep the first-parsed
    /// value (lexically smallest path, since files are parsed in `BTreeMap`
    /// order). When no root-level lockfile declares identity, the shallowest
    /// nested declarer wins each field.
    fn claim_asset_identity(&mut self, path: &str, name: Option<String>, version: Option<String>) {
        let depth = path.matches('/').count();
        if let Some(name) = name
            && self.asset_name_depth.is_none_or(|claimed| depth < claimed)
        {
            self.asset.name = name;
            self.asset_name_depth = Some(depth);
        }
        if version.is_some()
            && self
                .asset_version_depth
                .is_none_or(|claimed| depth < claimed)
        {
            self.asset.version = version;
            self.asset_version_depth = Some(depth);
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
        self.add_with_purl(name, version, purl, scope, path, licenses)
    }

    fn add_with_purl(
        &mut self,
        name: &str,
        version: &str,
        purl: String,
        scope: Scope,
        path: &str,
        licenses: BTreeSet<License>,
    ) -> Result<ComponentId, InputError> {
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
                // Cross-file scope merge: when the same component is declared
                // under different scopes by different lockfiles, keep the
                // most-exposed scope rather than whichever file parsed first
                // — a `default`/`runtime` declaration must never be downgraded
                // by a `develop`/`test` one that sorted earlier.
                if scope_exposure(scope) > scope_exposure(component.scope) {
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

    fn finish(
        mut self,
        locator: &Path,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Inventory, InputError> {
        // Asset identity derives from the locator plus the claimed project
        // name — never file contents — so baselines and history survive
        // dependency updates. Without a claimed name the scanned file set
        // (paths only, not bytes) keys the asset.
        self.asset.id = stable_asset(locator, Some(&self.asset.name), files)?;
        // A lockfile that claimed the project identity without locking the
        // project itself as a component (npm-family, bundler, NuGet, …)
        // leaves dependency roots that are really direct dependencies; the
        // flag tells the dependency graph to synthesize a virtual root.
        let project_is_component = self
            .components
            .values()
            .any(|component| component.name == self.asset.name);
        if self.asset_name_depth.is_some() && !project_is_component {
            self.asset
                .metadata
                .insert(crate::graph::VIRTUAL_ROOT_METADATA.into(), json!(true));
        }
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

/// Exposure rank for cross-file scope merges in
/// `InventoryBuilder::add_with_purl`: mirrors the risk model's ordering
/// (runtime > build > optional > development > test) with `Unknown` ranked
/// lowest — it carries no information and is always overwritten by a
/// declared scope.
fn scope_exposure(scope: Scope) -> u8 {
    match scope {
        Scope::Runtime => 5,
        Scope::Build => 4,
        Scope::Optional => 3,
        Scope::Development => 2,
        Scope::Test => 1,
        Scope::Unknown => 0,
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

/// Streams entry names of a (possibly gzip- or zstd-compressed) `.tar` once
/// to decide whether it is an OCI/docker-save image archive, without
/// buffering entry contents. Enforces the same entry-count, link, and path
/// rules as `read_tar_with_expanded`; only `manifest.json` is materialized
/// because its array shape decides docker-save classification (see
/// `is_oci_markers`).
fn tar_is_image<R: Read>(reader: R, config: &Config) -> Result<bool, InputError> {
    // Bound the decompressed stream, not just extracted bytes: tar-rs drains
    // skipped entries through the reader, so a crafted archive whose
    // directory entries declare huge sizes would otherwise decompress
    // unboundedly during this detection pass.
    let mut archive = tar::Archive::new(BoundedReader::new(reader, config.max_archive_bytes));
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
        let Some(path) = tar_entry_path(&entry)? else {
            continue;
        };
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

fn is_inventory_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|v| lockfile_route(v).is_some() || MANIFEST_SIDECARS.contains(&v))
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
pub(crate) fn open_regular_nofollow(path: &Path) -> Result<File, InputError> {
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

/// `read_limited` variant that re-verifies the opened file still resolves
/// beneath `root`: `O_NOFOLLOW` guards only the final path component, so an
/// intermediate directory swapped for a symlink between the walk and the
/// open would redirect the read outside the scanned tree. On Linux the
/// opened descriptor's `/proc/self/fd` target is canonicalized and must stay
/// under `root`; elsewhere the parent directory is re-canonicalized before
/// opening (same check, narrower race window).
fn read_limited_below(root: &Path, path: &Path, maximum: u64) -> Result<Vec<u8>, InputError> {
    #[cfg(target_os = "linux")]
    {
        let file = open_regular_nofollow(path)?;
        let fd_path = PathBuf::from(format!("/proc/self/fd/{}", {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        }));
        let resolved = fs::canonicalize(&fd_path).map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !resolved.starts_with(root) {
            return Err(InputError::Symlink(path.to_owned()));
        }
        return read_file_bounded(file, path, maximum);
    }
    #[allow(unreachable_code)]
    {
        reject_symlink_ancestors_below(root, path)?;
        read_limited(path, maximum)
    }
}

fn read_file_bounded(mut file: File, path: &Path, maximum: u64) -> Result<Vec<u8>, InputError> {
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

/// Byte-counting `Read` wrapper that errors once the wrapped stream yields
/// more than `maximum` bytes. Wrap decompressed archive streams so skipped
/// entries (whose declared sizes tar-rs drains through the decompressor)
/// count against the same budget as extracted ones.
pub(crate) struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> BoundedReader<R> {
    pub(crate) fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            remaining: maximum,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other(
                "archive stream exceeded decompressed byte bound",
            ));
        }
        let limit = (self.remaining.min(buf.len() as u64)) as usize;
        let read = self.inner.read(&mut buf[..limit])?;
        self.remaining -= read as u64;
        Ok(read)
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

/// Asset identity key: locator + claimed project name + the scanned file
/// *paths* (never contents), so dependency updates keep the same asset id
/// and baselines/history survive lockfile churn.
fn stable_asset(
    locator: &Path,
    name: Option<&str>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<AssetId, InputError> {
    let mut hash = Sha256::new();
    hash.update(locator.to_string_lossy().as_bytes());
    if let Some(name) = name {
        hash.update([0]);
        hash.update(name.as_bytes());
    }
    for path in files.keys() {
        hash.update(path.as_bytes());
    }
    AssetId::new(format!(
        "asset:sha256:{}",
        crate::util::hex_lower(&hash.finalize())
    ))
    .map_err(|_| InputError::InvalidIdentifier)
}

/// Parses a `package.json` manifest: claims the project name/version and
/// registers declared dependencies as versionless constraint components,
/// matching the `composer.json` standalone-manifest contract. A sibling
/// npm-family lockfile supersedes these declarations.
fn parse_package_json(
    path: &str,
    bytes: &[u8],
    lock: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "package.json", e))?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed_msg(path, "package.json", "expected a JSON object"))?;
    let name = root
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let version = root
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    out.claim_asset_identity(path, name, version);
    if lock.is_some() {
        return Ok(());
    }
    for (section, scope) in [
        ("dependencies", Scope::Runtime),
        ("devDependencies", Scope::Development),
        ("optionalDependencies", Scope::Optional),
    ] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(packages.len(), path, "package.json")?;
        for (name, constraint) in packages {
            let Some(constraint) = constraint.as_str() else {
                continue;
            };
            if constraint.is_empty() {
                continue;
            }
            out.add("npm", name, constraint, scope, path, BTreeSet::new())?;
        }
    }
    Ok(())
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

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::util::sha256_hex(bytes))
}
/// Decodes bytes as UTF-8, tolerating a leading byte-order mark (real-world
/// YAML/XML/JSON files — including Helm's own `frobnitz_with_bom` testdata —
/// are BOM-prefixed) and failing closed on any other invalid sequence.
fn utf8<'a>(bytes: &'a [u8], path: &str, format: &'static str) -> Result<&'a str, InputError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
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

/// serde_yaml materializes every alias as a deep copy of its anchored
/// subtree, so a hostile document amplifies roughly quadratically: `n`
/// aliases replaying an `n`-node anchor produce `n²` nodes while serde_yaml's
/// own jump limit (100 jumps per event) never binds. The byte input cap
/// therefore does not bound the parsed `Value` — a ~100 KiB document can
/// already expand past a gigabyte of nodes. `yaml_expansion_within_budget`
/// walks the libyaml event stream (the same parser serde_yaml drives) and
/// computes exactly what `serde_yaml::from_str::<Value>` would materialize,
/// so callers can reject over-budget documents before that memory is
/// allocated.
///
/// The budget is `clamp(input_bytes × YAML_MATERIALIZED_RATIO,
/// MIN_YAML_MATERIALIZED, MAX_YAML_MATERIALIZED)` measured in materialized
/// units — one per `Value` node plus one per scalar byte: alias-free YAML
/// needs at least one input byte per node, so the ratio only binds on
/// alias amplification; the floor keeps small documents' legitimate anchor
/// reuse working, and the absolute cap bounds memory on large inputs.
const YAML_MATERIALIZED_RATIO: u64 = 8;
const MIN_YAML_MATERIALIZED: u64 = 256 * 1024;
const MAX_YAML_MATERIALIZED: u64 = 4 * 1024 * 1024;

/// Reports whether `text` parses as a YAML stream whose per-document
/// materialized `serde_yaml::Value` size stays within the alias-expansion
/// budget. Unparseable input reports `true`: the subsequent serde_yaml parse
/// surfaces the real syntax error, and nothing is materialized either way.
pub(crate) fn yaml_expansion_within_budget(text: &str) -> bool {
    let budget = (text.len() as u64)
        .saturating_mul(YAML_MATERIALIZED_RATIO)
        .clamp(MIN_YAML_MATERIALIZED, MAX_YAML_MATERIALIZED);
    /// One open collection: its anchor name (when declared) and the
    /// materialized size accumulated so far — the collection node itself
    /// plus every completed child.
    struct Frame {
        anchor: Option<Vec<u8>>,
        size: u64,
    }
    let mut stack: Vec<Frame> = Vec::new();
    // Anchor name → materialized size of the anchored node, per document
    // (anchors cannot be referenced across document boundaries).
    let mut anchors: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    // Materialized size of the current document so far.
    let mut total = 0_u64;
    /// Accounts one completed node of `cost` units: into the enclosing
    /// collection's size and the document total, which is checked against
    /// the budget. Returns false once the document is over budget.
    fn account(stack: &mut [Frame], total: &mut u64, cost: u64, budget: u64) -> bool {
        if let Some(frame) = stack.last_mut() {
            frame.size += cost;
        }
        *total += cost;
        *total <= budget
    }
    // Copies a NUL-terminated libyaml anchor name.
    unsafe fn anchor_name(anchor: *const u8) -> Vec<u8> {
        // SAFETY: libyaml anchor fields are NUL-terminated strings owned by
        // the event, which outlives this copy.
        unsafe { CStr::from_ptr(anchor.cast()) }.to_bytes().to_vec()
    }
    // SAFETY: `parser` is initialized before use, `text` outlives the parser
    // (libyaml reads the input in place), each event is deleted after its
    // data is copied out, and the parser is deleted on every exit path.
    unsafe {
        let mut parser = MaybeUninit::<unsafe_libyaml::yaml_parser_t>::uninit();
        if unsafe_libyaml::yaml_parser_initialize(parser.as_mut_ptr()).fail {
            return true;
        }
        let parser = parser.as_mut_ptr();
        unsafe_libyaml::yaml_parser_set_encoding(parser, unsafe_libyaml::YAML_UTF8_ENCODING);
        unsafe_libyaml::yaml_parser_set_input_string(parser, text.as_ptr(), text.len() as u64);
        let mut event = MaybeUninit::<unsafe_libyaml::yaml_event_t>::uninit();
        let mut within_budget = true;
        loop {
            if unsafe_libyaml::yaml_parser_parse(parser, event.as_mut_ptr()).fail {
                break;
            }
            let mut parsed_event = event.assume_init();
            match parsed_event.type_ {
                unsafe_libyaml::YAML_STREAM_END_EVENT => {
                    unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                    break;
                }
                unsafe_libyaml::YAML_DOCUMENT_START_EVENT => {
                    stack.clear();
                    anchors.clear();
                    total = 0;
                }
                unsafe_libyaml::YAML_MAPPING_START_EVENT
                | unsafe_libyaml::YAML_SEQUENCE_START_EVENT => {
                    let anchor = if parsed_event.type_ == unsafe_libyaml::YAML_MAPPING_START_EVENT {
                        parsed_event.data.mapping_start.anchor
                    } else {
                        parsed_event.data.sequence_start.anchor
                    };
                    if !account(&mut stack, &mut total, 1, budget) {
                        within_budget = false;
                        unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                        break;
                    }
                    stack.push(Frame {
                        anchor: (!anchor.is_null()).then(|| anchor_name(anchor)),
                        size: 1,
                    });
                }
                unsafe_libyaml::YAML_MAPPING_END_EVENT
                | unsafe_libyaml::YAML_SEQUENCE_END_EVENT => {
                    if let Some(frame) = stack.pop()
                        && let Some(anchor) = frame.anchor
                    {
                        anchors.insert(anchor, frame.size);
                    }
                }
                unsafe_libyaml::YAML_SCALAR_EVENT => {
                    let scalar = parsed_event.data.scalar;
                    if !scalar.anchor.is_null() {
                        // The anchored scalar's materialized size is one
                        // node plus its bytes.
                        anchors.insert(anchor_name(scalar.anchor), 1 + scalar.length);
                    }
                    if !account(&mut stack, &mut total, 1 + scalar.length, budget) {
                        within_budget = false;
                        unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                        break;
                    }
                }
                unsafe_libyaml::YAML_ALIAS_EVENT => {
                    let alias = parsed_event.data.alias;
                    // serde_yaml resolves aliases against the anchors seen so
                    // far and errors on unknown ones; an unresolved alias
                    // here means the document is rejected downstream without
                    // materializing anything further, so accounting stops.
                    let Some(size) = anchors.get(anchor_name(alias.anchor).as_slice()) else {
                        unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                        break;
                    };
                    if !account(&mut stack, &mut total, *size, budget) {
                        within_budget = false;
                        unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                        break;
                    }
                }
                _ => {}
            }
            unsafe_libyaml::yaml_event_delete(&mut parsed_event);
        }
        unsafe_libyaml::yaml_parser_delete(parser);
        within_budget
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

    #[cfg(unix)]
    #[test]
    fn skips_nested_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let root = dir.path().join("project");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("requirements.txt"), "inside==1\n").unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, "outside==9\n").unwrap();
        symlink(&outside, root.join("linked-requirements.txt")).unwrap();
        symlink(&outside, root.join("requirements-link.txt")).unwrap();

        let inventory = scan_path(&root, &config()).unwrap();
        assert!(
            inventory
                .components
                .values()
                .any(|component| component.name == "inside")
        );
        assert!(
            inventory
                .components
                .values()
                .all(|component| component.name != "outside")
        );
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
            Ok(ScanInput::ProjectDirectory(_))
        ));
        let empty_inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(empty_inventory.components.is_empty());
        assert!(empty_inventory.dependencies.is_empty());

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
            ("requirements.txt", "==1.0\n", "requirements.txt"),
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
    fn yaml_alias_expansion_budget_accepts_legitimate_anchor_reuse() {
        // Helm/Kubernetes-style defaults merging: a small anchored mapping
        // replayed across entries stays far under the floor budget.
        let mut doc = String::from("defaults: &defaults\n  retries: 3\n  tls: true\n");
        for index in 0..50 {
            doc.push_str(&format!(
                "service{index}:\n  <<: *defaults\n  port: {index}\n"
            ));
        }
        assert!(yaml_expansion_within_budget(&doc));
    }

    #[test]
    fn yaml_alias_expansion_budget_rejects_nested_alias_amplification() {
        // Each level replays the previous anchored subtree nine times, so
        // serde_yaml would materialize ~9^level nodes — quadratic-or-worse
        // amplification the byte cap cannot see — while the input stays
        // under a kilobyte.
        let mut doc = String::from("a: &a1 [x]\n");
        for level in 2..=10 {
            let refs = vec![format!("*a{}", level - 1); 9].join(", ");
            doc.push_str(&format!("b{level}: &a{level} [{refs}]\n"));
        }
        assert!(!yaml_expansion_within_budget(&doc));
    }

    #[test]
    fn yaml_alias_expansion_budget_rejects_replayed_large_subtrees() {
        // One moderately-sized anchored sequence replayed thousands of
        // times: each alias is a single jump (serde_yaml's 100× jump limit
        // never binds) yet materializes the whole subtree again.
        let mut doc = String::from("base: &base\n");
        for index in 0..200 {
            doc.push_str(&format!("  - key{index}: value{index}\n"));
        }
        for index in 0..20_000 {
            doc.push_str(&format!("ref{index}: *base\n"));
        }
        assert!(!yaml_expansion_within_budget(&doc));
    }

    #[test]
    fn yaml_alias_expansion_budget_defers_unparseable_documents() {
        // Syntax errors are serde_yaml's to report; the budget check only
        // bounds what a successful parse would materialize.
        assert!(yaml_expansion_within_budget("a: [unclosed\n"));
        assert!(yaml_expansion_within_budget("plain scalar"));
    }

    #[test]
    fn yaml_lockfiles_reject_alias_expansion_beyond_budget() {
        let mut lock = String::from(
            "lockfileVersion: '9.0'\n\npackages:\n  base: &a1 {resolution: {integrity: x}}\n",
        );
        for level in 2..=10 {
            let refs = vec![format!("*a{}", level - 1); 9].join(", ");
            lock.push_str(&format!("  k{level}: &a{level} [{refs}]\n"));
        }
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pnpm-lock.yaml"), lock).unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config()),
            Err(InputError::Malformed {
                format: "pnpm-lock.yaml",
                ..
            })
        ));
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
            "bun.lock" => r#"{"lockfileVersion":1,"packages":{"a":["a@1","",{},"sha512-x"]}}"#,
            "poetry.lock" => "[[package]]\nname = 'a'\nversion = '1'\n",
            "Pipfile.lock" => "{}",
            "Gemfile.lock" => "GEM\n  specs:\n    a (1)\n",
            "Package.resolved" => "{\"pins\":[]}",
            "pubspec.lock" => "packages: {}\n",
            "Podfile.lock" => "PODS:\n  - A (1)\n",
            "composer.json" => "{}",
            "composer.lock" => r#"{"packages":[]}"#,
            "Directory.Packages.props" => "<Project/>",
            "packages.config" => "<packages/>",
            "App.csproj" => "<Project/>",
            "Chart.lock" => "dependencies: []\n",
            "environment.yml" => "dependencies: []\n",
            _ => "apiVersion: v2\n",
        }
    }

    #[test]
    fn detects_new_ecosystem_project_directories() {
        for name in [
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "poetry.lock",
            "Pipfile.lock",
            "Gemfile.lock",
            "Package.resolved",
            "pubspec.lock",
            "Podfile.lock",
            "composer.json",
            "environment.yml",
            "Chart.yaml",
            "composer.lock",
            "Chart.lock",
            "Directory.Packages.props",
            "packages.config",
            "App.csproj",
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
            r#"{"version":2,"pins":[{"identity":"swift-log","kind":"remoteSourceControl","location":"https://github.com/apple/swift-log.git","state":{"version":"1.5.3"}},{"identity":"swift-argument-parser","kind":"remoteSourceControl","location":"https://github.com/apple/swift-argument-parser.git","state":{"revision":"abc123","branch":"main"}}]}"#,
        )
        .unwrap();
        let inventory = scan_path(resolved.path(), &config()).unwrap();
        // Branch-pinned packages carry no `version`; they stay in inventory
        // under a `0.0.0-<branch>` marker rather than being dropped.
        assert_eq!(inventory.components.len(), 2);
        assert!(inventory.components.values().any(|c| c.name == "swift-log"
            && c.version == "1.5.3"
            && c.purl == "pkg:swift/github.com/apple/swift-log@1.5.3"));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "swift-argument-parser" && c.version == "0.0.0-main")
        );

        let legacy = tempdir().unwrap();
        fs::write(
            legacy.path().join("Package.resolved"),
            r#"{"object":{"pins":[{"package":"Alamofire","repositoryURL":"https://github.com/Alamofire/Alamofire.git","state":{"version":"5.8.0"}}]}}"#,
        )
        .unwrap();
        let inventory = scan_path(legacy.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(inventory.components.values().any(|c| c.name == "Alamofire"
            && c.version == "5.8.0"
            && c.purl == "pkg:swift/github.com/Alamofire/Alamofire@5.8.0"));
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
    fn gemfile_lock_nested_dependencies_become_edges_not_components() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Gemfile.lock"),
            concat!(
                "GEM\n",
                "  remote: https://rubygems.org/\n",
                "  specs:\n",
                "    aws-sdk-core (3.241.4)\n",
                "      base64\n",
                "      jmespath (~> 1, >= 1.6.1)\n",
                "    base64 (0.3.0)\n",
                "    jmespath (1.6.2)\n",
                "\n",
                "PATH\n",
                "  remote: .\n",
                "  specs:\n",
                "    fastlane (2.228.0)\n",
                "\n",
                "PLATFORMS\n",
                "  ruby\n",
                "\n",
                "DEPENDENCIES\n",
                "  aws-sdk-core\n",
                "  fastlane!\n",
                "\n",
                "BUNDLED WITH\n",
                "   2.6.9\n",
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
        assert_eq!(version_of("aws-sdk-core").as_deref(), Some("3.241.4"));
        assert_eq!(version_of("base64").as_deref(), Some("0.3.0"));
        assert_eq!(version_of("jmespath").as_deref(), Some("1.6.2"));
        // PATH-sourced gems are real components.
        assert_eq!(version_of("fastlane").as_deref(), Some("2.228.0"));
        // Nested dep lines never become components or phantom versions.
        assert_eq!(inventory.components.len(), 4);
        assert!(
            inventory
                .components
                .values()
                .all(|c| !c.version.contains('~') && !c.version.contains('>'))
        );
        // Nested deps resolve to edges against the locked specs.
        let name_of = |id: &ComponentId| inventory.components[id].name.as_str();
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| { name_of(&e.from) == "aws-sdk-core" && name_of(&e.to) == "base64" })
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| { name_of(&e.from) == "aws-sdk-core" && name_of(&e.to) == "jmespath" })
        );
        assert_eq!(inventory.dependencies.len(), 2);
    }

    #[test]
    fn podfile_lock_nested_dependencies_become_edges_not_components() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Podfile.lock"),
            concat!(
                "PODS:\n",
                "  - libwebp (1.5.0):\n",
                "    - libwebp/webp (= 1.5.0)\n",
                "  - libwebp/demux (1.5.0):\n",
                "    - libwebp/webp\n",
                "  - libwebp/webp (1.5.0)\n",
                "  - SDWebImageWebPCoder (0.14.6):\n",
                "    - libwebp (~> 1.0)\n",
                "\n",
                "DEPENDENCIES:\n",
                "  - libwebp\n",
                "  - SDWebImageWebPCoder\n",
                "\n",
                "COCOAPODS: 1.15.2\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        // Subspecs collapse to the parent pod; nested deps add no components.
        assert_eq!(inventory.components.len(), 2);
        let version_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.version.clone())
        };
        // Parent specs with children keep a clean version (no trailing `):`).
        assert_eq!(version_of("libwebp").as_deref(), Some("1.5.0"));
        assert_eq!(version_of("SDWebImageWebPCoder").as_deref(), Some("0.14.6"));
        let name_of = |id: &ComponentId| inventory.components[id].name.as_str();
        assert!(
            inventory.dependencies.iter().any(|e| {
                name_of(&e.from) == "SDWebImageWebPCoder" && name_of(&e.to) == "libwebp"
            })
        );
        // `libwebp` -> `libwebp` self-edges collapse; only the cross-pod
        // edge remains.
        assert_eq!(inventory.dependencies.len(), 1);
    }

    #[test]
    fn cross_file_scope_merge_prefers_runtime_over_development() {
        // The same purl declared `develop` in the root lockfile and
        // `default` in a nested one must resolve to runtime regardless of
        // lexical walk order.
        for nested_dir in ["aaa", "zzz"] {
            let dir = tempdir().unwrap();
            fs::write(
                dir.path().join("Pipfile.lock"),
                r#"{"_meta":{"requires":{}},"default":{},"develop":{"idna":{"version":"==3.15","hashes":["sha256:aaa"]}}}"#,
            )
            .unwrap();
            let sub = dir.path().join(nested_dir);
            fs::create_dir(&sub).unwrap();
            fs::write(
                sub.join("Pipfile.lock"),
                r#"{"_meta":{"requires":{}},"default":{"idna":{"version":"==3.15","hashes":["sha256:bbb"]}},"develop":{}}"#,
            )
            .unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert_eq!(inventory.components.len(), 1);
            let component = inventory.components.values().next().unwrap();
            assert_eq!(component.purl, "pkg:pypi/idna@3.15");
            assert_eq!(
                component.scope,
                Scope::Runtime,
                "nested dir {nested_dir}: runtime declaration must win over develop"
            );
            assert_eq!(component.provenance.len(), 2);
        }
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
        assert_eq!(version_of("pytorch").as_deref(), Some(">=2.0,<3"));
        assert_eq!(version_of("pip").as_deref(), Some("*"));
        assert_eq!(version_of("requests").as_deref(), Some("2.31.0"));
        assert_eq!(inventory.components.len(), 5);
        let purl_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.purl.clone())
        };
        assert_eq!(purl_of("python").as_deref(), Some("pkg:conda/python@3.11"));
        assert_eq!(purl_of("numpy").as_deref(), Some("pkg:conda/numpy"));
        assert_eq!(purl_of("pytorch").as_deref(), Some("pkg:conda/pytorch"));
        assert_eq!(purl_of("pip").as_deref(), Some("pkg:conda/pip"));

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
            ("composer.lock", "{}", "composer.lock"),
            ("Chart.lock", "digest: sha256:abc\n", "Chart.lock"),
            (
                "Directory.Packages.props",
                "<Project>",
                "Directory.Packages.props",
            ),
            ("packages.config", "<packages>", "packages.config"),
            ("App.csproj", "<Project", "csproj"),
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
