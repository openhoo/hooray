use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read},
    path::{Component as PathComponent, Path, PathBuf},
};

use serde::Deserialize;
use serde_json::{Value, json};
use serde_yaml::Value as Yaml;
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
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("SBOM error: {0}")]
    Sbom(#[from] SbomError),
    #[error("invalid generated inventory: {0}")]
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
            let files = read_tar_file(&canonical, config)?;
            if is_oci_files(&files) {
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

fn scan_virtual_files(
    locator: &Path,
    kind: AssetKind,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<Inventory, InputError> {
    let asset_id = stable_asset(locator, &files)?;
    let mut builder = InventoryBuilder::new(asset_id, locator, kind);
    let mut recognized = false;
    for (path, bytes) in &files {
        match base_name(path) {
            "Cargo.lock" => {
                parse_cargo_lock(
                    path,
                    bytes,
                    files.get(&sibling(path, "Cargo.toml")),
                    &mut builder,
                )?;
                recognized = true;
            }
            "package-lock.json" => {
                parse_package_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "requirements.txt" => {
                parse_requirements(path, bytes, &mut builder)?;
                recognized = true;
            }
            "go.mod" => {
                parse_go_mod(path, bytes, &mut builder)?;
                recognized = true;
            }
            "packages.lock.json" => {
                parse_nuget_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "yarn.lock" => {
                parse_yarn_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "pnpm-lock.yaml" => {
                parse_pnpm_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "poetry.lock" => {
                parse_poetry_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "Pipfile.lock" => {
                parse_pipfile_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "Gemfile.lock" => {
                parse_gemfile_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "Package.resolved" => {
                parse_package_resolved(path, bytes, &mut builder)?;
                recognized = true;
            }
            "pubspec.lock" => {
                parse_pubspec_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "Podfile.lock" => {
                parse_podfile_lock(path, bytes, &mut builder)?;
                recognized = true;
            }
            "composer.json" => {
                parse_composer_json(path, bytes, &mut builder)?;
                recognized = true;
            }
            "environment.yml" => {
                parse_conda_environment(path, bytes, &mut builder)?;
                recognized = true;
            }
            "Chart.yaml" => {
                parse_chart_yaml(path, bytes, &mut builder)?;
                recognized = true;
            }
            _ => {}
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

fn parse_cargo_lock(
    path: &str,
    bytes: &[u8],
    manifest: Option<&Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "Cargo.lock")?;
    let value: toml::Value = toml::from_str(text).map_err(|e| malformed(path, "Cargo.lock", e))?;
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| malformed_msg(path, "Cargo.lock", "missing package array"))?;
    entry_bound(packages.len(), path, "Cargo.lock")?;
    let declared_license = manifest
        .and_then(|b| toml::from_str::<toml::Value>(std::str::from_utf8(b).ok()?).ok())
        .and_then(|v| {
            v.get("package")?
                .get("license")?
                .as_str()
                .map(str::to_owned)
        });
    let mut ids = BTreeMap::<(String, String), ComponentId>::new();
    for package in packages {
        let name = required_toml(package, "name", path)?;
        let version = required_toml(package, "version", path)?;
        let licenses = declared_license
            .as_ref()
            .filter(|_| packages.len() == 1)
            .map(|v| {
                BTreeSet::from([License {
                    expression: Some(v.clone()),
                    name: None,
                    url: None,
                }])
            })
            .unwrap_or_default();
        let id = out.add("cargo", name, version, Scope::Runtime, path, licenses)?;
        ids.insert((name.to_owned(), version.to_owned()), id);
    }
    for package in packages {
        let from = &ids[&(
            required_toml(package, "name", path)?.to_owned(),
            required_toml(package, "version", path)?.to_owned(),
        )];
        for dependency in package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(spec) = dependency.as_str() else {
                continue;
            };
            let mut parts = spec.split_whitespace();
            let Some(name) = parts.next() else { continue };
            let version = parts.next();
            let target = version
                .and_then(|v| ids.get(&(name.to_owned(), v.to_owned())))
                .or_else(|| ids.iter().find(|((n, _), _)| n == name).map(|(_, id)| id));
            if let Some(to) = target.cloned() {
                out.edge(from, &to, Scope::Runtime, false);
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct NpmLock {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    packages: BTreeMap<String, NpmPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmDependency>,
}
#[derive(Deserialize, Default)]
struct NpmPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
}
#[derive(Deserialize, Default)]
struct NpmDependency {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmDependency>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
}

fn parse_package_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let lock: NpmLock =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "package-lock.json", e))?;
    if !lock.packages.is_empty() {
        entry_bound(lock.packages.len(), path, "package-lock.json")?;
        let mut ids = BTreeMap::new();
        for (key, package) in &lock.packages {
            if key.is_empty() {
                out.asset.version = package.version.clone().or_else(|| lock.version.clone());
                continue;
            }
            let name = package
                .name
                .clone()
                .or_else(|| key.rsplit("node_modules/").next().map(str::to_owned))
                .ok_or_else(|| malformed_msg(path, "package-lock.json", "package has no name"))?;
            let version = package.version.as_deref().ok_or_else(|| {
                malformed_msg(path, "package-lock.json", "package has no version")
            })?;
            let scope = if package.dev {
                Scope::Development
            } else if package.optional {
                Scope::Optional
            } else {
                Scope::Runtime
            };
            let licenses = package
                .license
                .as_ref()
                .map(|v| {
                    BTreeSet::from([License {
                        expression: Some(v.clone()),
                        name: None,
                        url: None,
                    }])
                })
                .unwrap_or_default();
            ids.insert(
                key.clone(),
                out.add("npm", &name, version, scope, path, licenses)?,
            );
        }
        for (key, package) in &lock.packages {
            let Some(from) = ids.get(key) else { continue };
            for (name, optional, scope) in package
                .dependencies
                .keys()
                .map(|n| (n, false, Scope::Runtime))
                .chain(
                    package
                        .dev_dependencies
                        .keys()
                        .map(|n| (n, false, Scope::Development)),
                )
                .chain(
                    package
                        .optional_dependencies
                        .keys()
                        .map(|n| (n, true, Scope::Optional)),
                )
            {
                if let Some(to) = resolve_npm_key(key, name, &ids).cloned() {
                    out.edge(from, &to, scope, optional);
                }
            }
        }
    } else {
        fn collect(
            name: &str,
            dependency: &NpmDependency,
            parent: Option<ComponentId>,
            path: &str,
            out: &mut InventoryBuilder,
        ) -> Result<ComponentId, InputError> {
            let version = dependency.version.as_deref().ok_or_else(|| {
                malformed_msg(path, "package-lock.json", "dependency has no version")
            })?;
            let scope = if dependency.dev {
                Scope::Development
            } else if dependency.optional {
                Scope::Optional
            } else {
                Scope::Runtime
            };
            entry_bound(out.components.len() + 1, path, "package-lock.json")?;
            let id = out.add("npm", name, version, scope, path, BTreeSet::new())?;
            if let Some(parent) = parent {
                out.edge(&parent, &id, scope, dependency.optional);
            }
            for (child, value) in &dependency.dependencies {
                collect(child, value, Some(id.clone()), path, out)?;
            }
            Ok(id)
        }
        for (name, dependency) in &lock.dependencies {
            collect(name, dependency, None, path, out)?;
        }
    }
    if let Some(name) = lock.name {
        out.asset.name = name;
    }
    Ok(())
}
fn resolve_npm_key<'a>(
    parent: &str,
    name: &str,
    ids: &'a BTreeMap<String, ComponentId>,
) -> Option<&'a ComponentId> {
    let nested = if parent.is_empty() {
        format!("node_modules/{name}")
    } else {
        format!("{parent}/node_modules/{name}")
    };
    ids.get(&nested)
        .or_else(|| ids.get(&format!("node_modules/{name}")))
}

fn parse_requirements(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut logical = String::new();
    for raw in utf8(bytes, path, "requirements.txt")?.lines() {
        let trimmed = raw.trim();
        logical.push_str(trimmed.strip_suffix('\\').unwrap_or(trimmed));
        if trimmed.ends_with('\\') {
            logical.push(' ');
            continue;
        }
        let line = logical.split('#').next().unwrap_or_default().trim();
        if !line.is_empty() && !line.starts_with('-') {
            let (name, pinned) = line.split_once("==").ok_or_else(|| {
                malformed_msg(
                    path,
                    "requirements.txt",
                    "requirements must be pinned with ==",
                )
            })?;
            let version = pinned
                .split(';')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or_default();
            if name.trim().is_empty() || version.is_empty() {
                return Err(malformed_msg(
                    path,
                    "requirements.txt",
                    "empty package name or version",
                ));
            }
            entry_bound(out.components.len() + 1, path, "requirements.txt")?;
            out.add(
                "pypi",
                &normalize_pypi_name(name),
                version,
                Scope::Runtime,
                path,
                BTreeSet::new(),
            )?;
        }
        logical.clear();
    }
    if !logical.trim().is_empty() {
        return Err(malformed_msg(
            path,
            "requirements.txt",
            "unterminated line continuation",
        ));
    }
    Ok(())
}

fn parse_go_mod(path: &str, bytes: &[u8], out: &mut InventoryBuilder) -> Result<(), InputError> {
    let mut in_require = false;
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
    Ok(())
}

fn parse_nuget_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "packages.lock.json", e))?;
    let frameworks = value
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed_msg(path, "packages.lock.json", "missing dependencies object"))?;
    let mut ids = BTreeMap::new();
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    malformed_msg(
                        path,
                        "packages.lock.json",
                        "package missing resolved version",
                    )
                })?;
            let scope = match package.get("type").and_then(Value::as_str) {
                Some("Direct") => Scope::Runtime,
                Some("Transitive") => Scope::Runtime,
                _ => Scope::Unknown,
            };
            ids.insert(
                (name.to_ascii_lowercase(), version.to_owned()),
                out.add(
                    "nuget",
                    &name.to_ascii_lowercase(),
                    version,
                    scope,
                    path,
                    BTreeSet::new(),
                )?,
            );
        }
    }
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(from) = ids.get(&(name.to_ascii_lowercase(), version.to_owned())) else {
                continue;
            };
            for (dependency, constraint) in package
                .get("dependencies")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let requested = constraint.as_str().unwrap_or_default();
                let target = ids
                    .get(&(dependency.to_ascii_lowercase(), requested.to_owned()))
                    .or_else(|| {
                        ids.iter()
                            .find(|((n, _), _)| n == &dependency.to_ascii_lowercase())
                            .map(|(_, id)| id)
                    });
                if let Some(to) = target.cloned() {
                    out.edge(from, &to, Scope::Runtime, false);
                }
            }
        }
    }
    Ok(())
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

/// Splits an npm-style `name@locator` descriptor into package name and locator,
/// honoring `@scope/name` packages and optional pnpm `/`-prefixed lockfile keys.
fn split_descriptor(descriptor: &str) -> Option<(&str, &str)> {
    let rest = descriptor.strip_prefix('/').unwrap_or(descriptor);
    if let Some(scoped) = rest.strip_prefix('@') {
        let at = scoped.find('@')?;
        Some((&rest[..at + 1], &rest[at + 2..]))
    } else {
        let at = rest.find('@')?;
        Some((&rest[..at], &rest[at + 1..]))
    }
}

type YarnEntries = BTreeMap<String, (String, Vec<(String, bool)>)>;
type YarnCurrent = (String, String, Vec<(String, bool)>);

fn parse_yarn_lock(path: &str, bytes: &[u8], out: &mut InventoryBuilder) -> Result<(), InputError> {
    let text = utf8(bytes, path, "yarn.lock")?;
    if text.starts_with("__metadata:") || text.contains("\n__metadata:") {
        parse_yarn_berry(path, text, out)
    } else {
        parse_yarn_classic(path, text, out)
    }
}

fn parse_yarn_classic(
    path: &str,
    text: &str,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut entries: YarnEntries = BTreeMap::new();
    let mut current: Option<YarnCurrent> = None;
    let mut mode = 0_u8;
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
            mode = 0;
            continue;
        }
        let Some((_, version, deps)) = current.as_mut() else {
            return Err(malformed_msg(
                path,
                "yarn.lock",
                format!("unexpected indented line {trimmed:?}"),
            ));
        };
        match mode {
            0 => {
                if let Some(value) = trimmed.strip_prefix("version ") {
                    *version = value.trim().trim_matches('"').to_owned();
                } else if trimmed == "dependencies:" {
                    mode = 1;
                } else if trimmed == "optionalDependencies:" {
                    mode = 2;
                }
            }
            _ => {
                if trimmed == "dependencies:" {
                    mode = 1;
                } else if trimmed == "optionalDependencies:" {
                    mode = 2;
                } else if let Some(dep) = trimmed.split_whitespace().next() {
                    deps.push((dep.to_owned(), mode == 2));
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

fn parse_pnpm_lock(path: &str, bytes: &[u8], out: &mut InventoryBuilder) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "pnpm-lock.yaml")?)
        .map_err(|e| malformed(path, "pnpm-lock.yaml", e))?;
    let packages = doc.get("packages").and_then(Yaml::as_mapping);
    let importers = doc.get("importers").and_then(Yaml::as_mapping);
    if packages.is_none() && importers.is_none() {
        return Err(malformed_msg(
            path,
            "pnpm-lock.yaml",
            "missing packages and importers sections",
        ));
    }
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    if let Some(packages) = packages {
        entry_bound(packages.len(), path, "pnpm-lock.yaml")?;
        for (key, entry) in packages {
            let Some(key) = key.as_str() else { continue };
            let Some((name, key_version)) = pnpm_key_parts(key) else {
                continue;
            };
            let version = entry
                .get("version")
                .and_then(Yaml::as_str)
                .unwrap_or(key_version);
            if version.is_empty() {
                continue;
            }
            let dev = entry.get("dev").and_then(Yaml::as_bool).unwrap_or(false);
            let optional = entry
                .get("optional")
                .and_then(Yaml::as_bool)
                .unwrap_or(false);
            let scope = if dev {
                Scope::Development
            } else if optional {
                Scope::Optional
            } else {
                Scope::Runtime
            };
            let id = out.add("npm", name, version, scope, path, BTreeSet::new())?;
            ids.insert(name.to_owned(), id);
        }
        for (key, entry) in packages {
            let Some((name, _)) = key.as_str().and_then(pnpm_key_parts) else {
                continue;
            };
            let Some(from) = ids.get(name) else { continue };
            let Some(deps) = entry.get("dependencies").and_then(Yaml::as_mapping) else {
                continue;
            };
            for (dep, _) in deps {
                if let Some(to) = dep.as_str().and_then(|dep| ids.get(dep)) {
                    out.edge(from, to, Scope::Runtime, false);
                }
            }
        }
    }
    if let Some(importers) = importers {
        for importer in importers.values() {
            for (field, scope) in [
                ("dependencies", Scope::Runtime),
                ("devDependencies", Scope::Development),
                ("optionalDependencies", Scope::Optional),
            ] {
                let Some(deps) = importer.get(field).and_then(Yaml::as_mapping) else {
                    continue;
                };
                for (dep, spec) in deps {
                    let Some(dep) = dep.as_str() else { continue };
                    if ids.contains_key(dep) {
                        continue;
                    }
                    let Some(version) = pnpm_spec_version(spec) else {
                        continue;
                    };
                    if version.is_empty() {
                        continue;
                    }
                    let id = out.add("npm", dep, &version, scope, path, BTreeSet::new())?;
                    ids.insert(dep.to_owned(), id);
                }
            }
        }
    }
    Ok(())
}

fn pnpm_key_parts(key: &str) -> Option<(&str, &str)> {
    let (name, version) = split_descriptor(key)?;
    let version = version.split('(').next().unwrap_or(version);
    (!version.is_empty()).then_some((name, version))
}

fn pnpm_spec_version(spec: &Yaml) -> Option<String> {
    let Some(text) = spec.as_str() else {
        return spec
            .get("version")
            .and_then(Yaml::as_str)
            .map(str::to_owned);
    };
    if ["link:", "workspace:", "file:", "portal:"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return None;
    }
    if let Some((_, version)) = pnpm_key_parts(text) {
        return Some(version.to_owned());
    }
    (!text.is_empty()).then(|| text.to_owned())
}

fn parse_poetry_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "poetry.lock")?;
    let value: toml::Value = toml::from_str(text).map_err(|e| malformed(path, "poetry.lock", e))?;
    let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
        return Err(malformed_msg(
            path,
            "poetry.lock",
            "missing [[package]] entries",
        ));
    };
    entry_bound(packages.len(), path, "poetry.lock")?;
    let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| malformed_msg(path, "poetry.lock", "package missing name"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                malformed_msg(
                    path,
                    "poetry.lock",
                    format!("package {name} missing version"),
                )
            })?;
        let category = package
            .get("category")
            .and_then(toml::Value::as_str)
            .unwrap_or("main");
        let optional = package
            .get("optional")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let scope = if category == "dev" {
            Scope::Development
        } else if optional {
            Scope::Optional
        } else {
            Scope::Runtime
        };
        let id = out.add(
            "pypi",
            &normalize_pypi_name(name),
            version,
            scope,
            path,
            BTreeSet::new(),
        )?;
        ids.insert(name.to_ascii_lowercase(), id);
    }
    for package in packages {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(from) = ids.get(&name.to_ascii_lowercase()) else {
            continue;
        };
        let Some(deps) = package.get("dependencies").and_then(toml::Value::as_table) else {
            continue;
        };
        for dep in deps.keys() {
            if dep == "python" {
                continue;
            }
            if let Some(to) = ids.get(&dep.to_ascii_lowercase()) {
                out.edge(from, to, Scope::Runtime, false);
            }
        }
    }
    Ok(())
}

fn parse_pipfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "Pipfile.lock", e))?;
    let Some(root) = value.as_object() else {
        return Err(malformed_msg(
            path,
            "Pipfile.lock",
            "expected a JSON object",
        ));
    };
    for (section, scope) in [("default", Scope::Runtime), ("develop", Scope::Development)] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(packages.len(), path, "Pipfile.lock")?;
        for (name, entry) in packages {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let version = version.strip_prefix("==").unwrap_or(version);
            if version.is_empty() {
                continue;
            }
            out.add(
                "pypi",
                &normalize_pypi_name(name),
                version,
                scope,
                path,
                BTreeSet::new(),
            )?;
        }
    }
    Ok(())
}

fn parse_gemfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "Gemfile.lock")?;
    let mut section = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim_end().trim();
        if trimmed.is_empty() {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            section = trimmed.to_owned();
            continue;
        }
        if section != "GEM" {
            continue;
        }
        let spec = trimmed;
        if spec == "specs:" || spec.starts_with("remote:") {
            continue;
        }
        let Some(open) = spec.find(" (") else {
            return Err(malformed_msg(
                path,
                "Gemfile.lock",
                format!("invalid gem spec {spec:?}"),
            ));
        };
        let name = &spec[..open];
        let versions = spec[open + 2..].trim_end_matches(')');
        let version = versions.split(", ").next().unwrap_or(versions);
        let version = version.split('-').next().unwrap_or(version);
        if name.is_empty() || version.is_empty() {
            return Err(malformed_msg(
                path,
                "Gemfile.lock",
                format!("invalid gem spec {spec:?}"),
            ));
        }
        entry_bound(out.components.len() + 1, path, "Gemfile.lock")?;
        out.add("gem", name, version, Scope::Runtime, path, BTreeSet::new())?;
    }
    Ok(())
}

fn parse_package_resolved(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "Package.resolved", e))?;
    let pins = value
        .get("pins")
        .and_then(Value::as_array)
        .or_else(|| {
            value
                .get("object")
                .and_then(|object| object.get("pins"))
                .and_then(Value::as_array)
        })
        .ok_or_else(|| malformed_msg(path, "Package.resolved", "missing pins array"))?;
    entry_bound(pins.len(), path, "Package.resolved")?;
    for pin in pins {
        let name = pin
            .get("identity")
            .or_else(|| pin.get("package"))
            .and_then(Value::as_str);
        let version = pin
            .get("state")
            .and_then(|state| state.get("version"))
            .and_then(Value::as_str);
        let (Some(name), Some(version)) = (name, version) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.add(
            "swift",
            name,
            version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

fn parse_pubspec_lock(
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
        let Some(name) = key.as_str() else { continue };
        let Some(source) = entry.get("source").and_then(Yaml::as_str) else {
            continue;
        };
        if source != "hosted" {
            continue;
        }
        let Some(version) = entry.get("version").and_then(Yaml::as_str) else {
            continue;
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

fn parse_podfile_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let text = utf8(bytes, path, "Podfile.lock")?;
    let mut section = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim_end().trim();
        if trimmed.is_empty() {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            section = trimmed.trim_end_matches(':').to_owned();
            continue;
        }
        if section != "PODS" {
            continue;
        }
        let Some(entry) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let Some(open) = entry.find(" (") else {
            return Err(malformed_msg(
                path,
                "Podfile.lock",
                format!("pod entry missing version {entry:?}"),
            ));
        };
        let full_name = &entry[..open];
        let name = full_name.split('/').next().unwrap_or(full_name);
        let versions = entry[open + 2..].trim_end_matches(')');
        let version = versions.split(", ").next().unwrap_or(versions);
        if name.is_empty() || version.is_empty() {
            return Err(malformed_msg(
                path,
                "Podfile.lock",
                format!("pod entry missing version {entry:?}"),
            ));
        }
        entry_bound(out.components.len() + 1, path, "Podfile.lock")?;
        out.add(
            "cocoapods",
            name,
            version,
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

fn parse_composer_json(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "composer.json", e))?;
    let root = value
        .as_object()
        .ok_or_else(|| malformed_msg(path, "composer.json", "expected a JSON object"))?;
    if let Some(version) = root
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        out.asset.version = Some(version.to_owned());
    }
    for (section, scope) in [
        ("require", Scope::Runtime),
        ("require-dev", Scope::Development),
    ] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        entry_bound(packages.len(), path, "composer.json")?;
        for (name, constraint) in packages {
            // Platform packages (php, ext-*, lib-*, composer) carry no vendor/name pair.
            if !name.contains('/') {
                continue;
            }
            let Some(constraint) = constraint.as_str() else {
                continue;
            };
            if constraint.is_empty() {
                continue;
            }
            out.add("composer", name, constraint, scope, path, BTreeSet::new())?;
        }
    }
    Ok(())
}

fn parse_conda_environment(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "environment.yml")?)
        .map_err(|e| malformed(path, "environment.yml", e))?;
    let Some(dependencies) = doc.get("dependencies").and_then(Yaml::as_sequence) else {
        return Err(malformed_msg(
            path,
            "environment.yml",
            "missing dependencies list",
        ));
    };
    entry_bound(dependencies.len(), path, "environment.yml")?;
    let mut pip = Vec::new();
    for entry in dependencies {
        if let Some(spec) = entry.as_str() {
            add_conda_spec(path, spec, out)?;
        } else if let Some(lines) = entry.get("pip").and_then(Yaml::as_sequence) {
            for line in lines {
                if let Some(cleaned) = line.as_str().and_then(clean_pip_requirement) {
                    pip.push(cleaned);
                }
            }
        }
    }
    if !pip.is_empty() {
        let requirements = pip.join("\n");
        parse_requirements(path, requirements.as_bytes(), out)?;
    }
    Ok(())
}

fn add_conda_spec(path: &str, spec: &str, out: &mut InventoryBuilder) -> Result<(), InputError> {
    let spec = spec.split('#').next().unwrap_or(spec).trim();
    let spec = spec.rsplit("::").next().unwrap_or(spec);
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
        .unwrap_or(spec.len());
    let name = &spec[..name_end];
    if name.is_empty() {
        return Ok(());
    }
    let version = spec[name_end..]
        .trim_start_matches(|c: char| "=<>!~ ".contains(c))
        .split([',', ';', ' ', '\t'])
        .next()
        .unwrap_or_default();
    if version.is_empty() {
        return Ok(());
    }
    entry_bound(out.components.len() + 1, path, "environment.yml")?;
    out.add(
        "conda",
        name,
        version,
        Scope::Runtime,
        path,
        BTreeSet::new(),
    )?;
    Ok(())
}

fn clean_pip_requirement(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("--")
        || trimmed.starts_with("-r")
        || trimmed.starts_with("-e")
    {
        return None;
    }
    let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
    trimmed.contains("==").then(|| trimmed.to_owned())
}

fn parse_chart_yaml(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let doc: Yaml = serde_yaml::from_str(utf8(bytes, path, "Chart.yaml")?)
        .map_err(|e| malformed(path, "Chart.yaml", e))?;
    if let Some(version) = doc
        .get("version")
        .and_then(Yaml::as_str)
        .filter(|v| !v.is_empty())
    {
        out.asset.version = Some(version.to_owned());
    }
    let Some(dependencies) = doc.get("dependencies").and_then(Yaml::as_sequence) else {
        return Ok(());
    };
    entry_bound(dependencies.len(), path, "Chart.yaml")?;
    for dependency in dependencies {
        let Some(name) = dependency.get("name").and_then(Yaml::as_str) else {
            continue;
        };
        let Some(version) = dependency.get("version").and_then(Yaml::as_str) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.add("helm", name, version, Scope::Runtime, path, BTreeSet::new())?;
    }
    Ok(())
}

fn scan_oci_layout(root: &Path, config: &Config) -> Result<Inventory, InputError> {
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
        apply_layer(&bytes, config, &mut expanded, &mut filesystem)?;
    }
    let mut inventory = scan_virtual_files(root, AssetKind::ContainerImage, filesystem)?;
    inventory
        .asset
        .metadata
        .insert("manifest_digest".into(), json!(descriptor.digest));
    add_oci_config_metadata(&mut inventory.asset, &config_bytes);
    Ok(inventory)
}

fn scan_oci_tar(path: &Path, config: &Config) -> Result<Inventory, InputError> {
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
                apply_layer(bytes, config, &mut expanded, &mut filesystem)?;
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
                apply_layer(bytes, config, &mut expanded, &mut filesystem)?;
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
    config: &Config,
    expanded: &mut u64,
    filesystem: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), InputError> {
    let layer = read_tar_with_expanded(Cursor::new(bytes), config, expanded)?;
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

fn read_zip_file(path: &Path, config: &Config) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    read_zip(
        File::open(path).map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?,
        config,
    )
}

fn read_zip<R: Read + io::Seek>(
    reader: R,
    config: &Config,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut archive = zip::ZipArchive::new(reader)?;
    if archive.len() > config.max_archive_entries {
        return Err(InputError::TooManyArchiveEntries {
            maximum: config.max_archive_entries,
        });
    }
    let mut files = BTreeMap::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| InputError::PathTraversal(entry.name().to_owned()))?;
        let path = normalize_relative(&path)?;
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(InputError::ArchiveLink(path));
        }
        if !entry.is_file() {
            continue;
        }
        let expected = entry.size();
        expanded = add_archive_size(expanded, expected, config)?;
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(expected.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| InputError::Io {
                path: PathBuf::from(&path),
                source,
            })?;
        if bytes.len() as u64 != expected {
            return Err(malformed_msg(&path, "ZIP", "entry size mismatch"));
        }
        files.insert(path, bytes);
    }
    Ok(files)
}

fn read_tar_file(path: &Path, config: &Config) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    read_tar(
        Cursor::new(read_limited(path, config.max_input_bytes)?),
        config,
    )
}

fn read_tar<R: Read>(reader: R, config: &Config) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut expanded = 0;
    read_tar_with_expanded(reader, config, &mut expanded)
}

fn read_tar_with_expanded<R: Read>(
    reader: R,
    config: &Config,
    expanded: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut archive = tar::Archive::new(reader);
    let mut files = BTreeMap::new();
    let mut count = 0_usize;
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
        *expanded = add_archive_size(*expanded, entry.size(), config)?;
        let expected = entry.size();
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(expected.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| InputError::Io {
                path: PathBuf::from(&path),
                source,
            })?;
        if bytes.len() as u64 != expected {
            return Err(malformed_msg(&path, "TAR", "entry size mismatch"));
        }
        files.insert(path, bytes);
    }
    Ok(files)
}

fn add_archive_size(current: u64, entry: u64, config: &Config) -> Result<u64, InputError> {
    let actual = current.saturating_add(entry);
    if actual > config.max_archive_bytes {
        Err(InputError::ArchiveTooLarge {
            actual,
            maximum: config.max_archive_bytes,
        })
    } else {
        Ok(actual)
    }
}

fn has_project_manifest(root: &Path) -> Result<bool, InputError> {
    for name in [
        "Cargo.lock",
        "package-lock.json",
        "requirements.txt",
        "go.mod",
        "packages.lock.json",
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
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_inventory_file(path: &Path) -> bool {
    path.file_name().and_then(|v| v.to_str()).is_some_and(|v| {
        matches!(
            v,
            "Cargo.lock"
                | "Cargo.toml"
                | "package-lock.json"
                | "requirements.txt"
                | "go.mod"
                | "go.sum"
                | "packages.lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "poetry.lock"
                | "Pipfile.lock"
                | "Gemfile.lock"
                | "Package.resolved"
                | "pubspec.lock"
                | "Podfile.lock"
                | "composer.json"
                | "environment.yml"
                | "Chart.yaml"
        )
    })
}
fn is_oci_files(files: &BTreeMap<String, Vec<u8>>) -> bool {
    (files.contains_key("oci-layout") && files.contains_key("index.json"))
        || files.get("manifest.json").is_some_and(|bytes| {
            // Only an array-shaped manifest.json marks a docker-save archive.
            // Object-shaped manifests are web app manifests (PWA); routing
            // project tarballs that carry one into the image parser rejected
            // valid archives with Malformed instead of scanning their
            // lockfiles. The bytes are already fully in memory, so parsing
            // adds no new cap pressure.
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
        if source.raw_os_error() == Some(40) {
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
fn normalize_relative(path: &Path) -> Result<String, InputError> {
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
    // bytes the purl grammar reserves or that parsers leak into names.
    let encoded = name
        .replace('%', "%25")
        .replace('@', "%40")
        .replace(' ', "%20")
        .replace('[', "%5B")
        .replace(']', "%5D");
    match purl_version(version) {
        // Range constraints (^8.1, 1.24.*, >=2) are specifiers, not versions:
        // baking them in produced purls the spec rejects that could never
        // match an OSV advisory. A versionless purl keeps the component
        // honest (raw specifier stays on Component.version) and lets OSV
        // match the package across its versions.
        Some(version) => format!("pkg:{ecosystem}/{encoded}@{}", percent_encode(&version)),
        None => format!("pkg:{ecosystem}/{encoded}"),
    }
}

/// Returns the concrete purl version for a specifier, stripping pnpm-style
/// `1.2.3(integrity)` annotations, or `None` for empty values and range
/// constraints (`^1.2`, `~1.2`, `>=1`, `1.*`, `a || b`, `git+https://…`).
fn purl_version(version: &str) -> Option<String> {
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

/// Percent-encodes a purl version: keeps RFC 3986 unreserved bytes plus `+`
/// and escapes everything else (including `%` and `@`) uppercase-hex.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' | b'+' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// PEP 503 PyPI name normalization plus extras stripping (`Requests[security]`),
/// so one package cannot split into several component identities or purls.
fn normalize_pypi_name(name: &str) -> String {
    let base = name.split('[').next().unwrap_or(name).trim();
    let mut normalized = String::with_capacity(base.len());
    let mut separator = false;
    for ch in base.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
            }
            separator = true;
        } else {
            separator = false;
            normalized.extend(ch.to_lowercase());
        }
    }
    normalized
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
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn required_toml<'a>(
    value: &'a toml::Value,
    field: &'static str,
    path: &str,
) -> Result<&'a str, InputError> {
    value
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| malformed_msg(path, "Cargo.lock", format!("package missing {field}")))
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

    fn config() -> Config {
        Config {
            max_input_bytes: 1024 * 1024,
            max_archive_bytes: 1024 * 1024,
            max_archive_entries: 100,
            ..Config::default()
        }
    }

    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
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

    fn write_tar(path: &Path, entries: &[(&str, &[u8])]) {
        fs::write(path, tar_bytes(entries)).unwrap();
    }

    fn digest(value: u8) -> String {
        format!("sha256:{}", format!("{value:02x}").repeat(32))
    }

    fn blob_name(digest: &str) -> String {
        format!("blobs/sha256/{}", digest.strip_prefix("sha256:").unwrap())
    }

    #[test]
    fn scans_cargo_graph_and_declared_license() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='app'\nversion='1.0.0'\nlicense='MIT'\n",
        )
        .unwrap();
        fs::write(dir.path().join("Cargo.lock"), "version = 3\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['dep 2.0.0']\n[[package]]\nname='dep'\nversion='2.0.0'\n").unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 2);
        assert_eq!(inventory.dependencies.len(), 1);
    }

    #[test]
    fn scans_npm_v3_relationships() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package-lock.json"), r#"{"name":"app","packages":{"":{"version":"1"},"node_modules/a":{"name":"a","version":"1.2.3","license":"MIT","dependencies":{"b":"^2"}},"node_modules/b":{"name":"b","version":"2.0.0"}}}"#).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "app");
        assert_eq!(inventory.dependencies.len(), 1);
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

    #[test]
    fn scans_zip_and_rejects_traversal() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("requirements.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"a==1\n").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert_eq!(read_zip(Cursor::new(bytes), &config()).unwrap().len(), 1);
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(matches!(
            read_zip(Cursor::new(bytes), &config()),
            Err(InputError::PathTraversal(_))
        ));
    }

    #[test]
    fn rejects_tar_links_and_expansion_limit() {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            header.set_link_name("target").unwrap();
            builder
                .append_data(&mut header, "link", io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            read_tar(Cursor::new(bytes), &config()),
            Err(InputError::ArchiveLink(_))
        ));
        let mut small = config();
        small.max_archive_bytes = 2;
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_cksum();
            builder
                .append_data(&mut header, "requirements.txt", &b"abc"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            read_tar(Cursor::new(bytes), &small),
            Err(InputError::ArchiveTooLarge { .. })
        ));
    }

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
        apply_layer(&first, &config(), &mut expanded, &mut filesystem).unwrap();
        apply_layer(&second, &config(), &mut expanded, &mut filesystem).unwrap();
        assert!(!filesystem.contains_key("app/requirements.txt"));
        assert_eq!(filesystem["requirements.txt"], b"new==2\n");
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
    fn npm_v3_preserves_development_optional_and_direct_edge_scopes() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"app","version":"3","packages":{"":{"version":"3"},"node_modules/root":{"name":"root","version":"1","dependencies":{"runtime":"1"},"devDependencies":{"dev":"1"},"optionalDependencies":{"optional":"1"}},"node_modules/runtime":{"name":"runtime","version":"1"},"node_modules/dev":{"name":"dev","version":"1","dev":true},"node_modules/optional":{"name":"optional","version":"1","optional":true}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.version.as_deref(), Some("3"));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "dev" && c.scope == Scope::Development)
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "optional" && c.scope == Scope::Optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Development && !e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Optional && e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Runtime && !e.optional)
        );
    }

    #[test]
    fn npm_v1_dependencies_preserve_nested_dev_and_optional_contracts() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"legacy","dependencies":{"parent":{"version":"1","dependencies":{"dev":{"version":"2","dev":true},"optional":{"version":"3","optional":true}}}}}"#,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.asset.name, "legacy");
        assert_eq!(inventory.components.len(), 3);
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Development && !e.optional)
        );
        assert!(
            inventory
                .dependencies
                .iter()
                .any(|e| e.scope == Scope::Optional && e.optional)
        );
    }

    #[test]
    fn scans_tar_file_end_to_end_and_rejects_empty_archive() {
        let dir = tempdir().unwrap();
        let tar_path = dir.path().join("project.tar");
        write_tar(&tar_path, &[("nested/requirements.txt", b"safe==1\n")]);
        let inventory = scan_path(&tar_path, &config()).unwrap();
        assert_eq!(inventory.asset.kind, AssetKind::Filesystem);
        assert!(inventory.components.values().any(|c| c.name == "safe"));

        let empty_path = dir.path().join("empty.tar");
        write_tar(&empty_path, &[]);
        assert!(matches!(
            scan_path(&empty_path, &config()),
            Err(InputError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn zip_enforces_entry_count_size_links_and_ignores_directories() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .add_directory("dir/", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file("dir/a", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"a").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut one_entry = config();
        one_entry.max_archive_entries = 1;
        assert!(matches!(
            read_zip(Cursor::new(bytes.clone()), &one_entry),
            Err(InputError::TooManyArchiveEntries { maximum: 1 })
        ));
        assert_eq!(read_zip(Cursor::new(bytes), &config()).unwrap().len(), 1);

        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("large", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"ab").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut one_byte = config();
        one_byte.max_archive_bytes = 1;
        assert!(matches!(
            read_zip(Cursor::new(bytes), &one_byte),
            Err(InputError::ArchiveTooLarge {
                actual: 2,
                maximum: 1
            })
        ));

        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .add_symlink("link", "target", zip::write::SimpleFileOptions::default())
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(matches!(
            read_zip(Cursor::new(bytes), &config()),
            Err(InputError::ArchiveLink(path)) if path == "link"
        ));
    }

    #[test]
    fn archive_zero_limits_reject_nonempty_inputs_at_the_boundary() {
        let tar = tar_bytes(&[("a", b"x")]);
        let mut zero_entries = config();
        zero_entries.max_archive_entries = 0;
        assert!(matches!(
            read_tar(Cursor::new(tar.clone()), &zero_entries),
            Err(InputError::TooManyArchiveEntries { maximum: 0 })
        ));
        let mut zero_bytes = config();
        zero_bytes.max_archive_bytes = 0;
        assert!(matches!(
            read_tar(Cursor::new(tar), &zero_bytes),
            Err(InputError::ArchiveTooLarge {
                actual: 1,
                maximum: 0
            })
        ));
        assert_eq!(
            add_archive_size(u64::MAX, 1, &config())
                .unwrap_err()
                .to_string(),
            format!(
                "archive expanded size {} exceeds maximum {} bytes",
                u64::MAX,
                config().max_archive_bytes
            )
        );
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
        apply_layer(&first, &config(), &mut expanded, &mut filesystem).unwrap();
        apply_layer(&second, &config(), &mut expanded, &mut filesystem).unwrap();
        assert!(!filesystem.contains_key("app/requirements.txt"));
        assert!(filesystem.contains_key("other/requirements.txt"));
        assert!(filesystem.contains_key("app/package-lock.json"));
        assert!(!filesystem.contains_key("app/.wh..wh..opq"));
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

    #[test]
    fn image_archive_limit_is_cumulative_across_layers_and_whiteouts() {
        let first = tar_bytes(&[("old", b"1234")]);
        let second = tar_bytes(&[(".wh.old", b""), ("requirements.txt", b"a==1\n")]);
        let mut limited = config();
        limited.max_archive_bytes = 5;
        let mut filesystem = BTreeMap::new();
        let mut expanded = 0;
        apply_layer(&first, &limited, &mut expanded, &mut filesystem).unwrap();
        assert!(matches!(
            apply_layer(&second, &limited, &mut expanded, &mut filesystem),
            Err(InputError::ArchiveTooLarge {
                actual: 9,
                maximum: 5
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
    fn scans_pnpm_lock_importers_and_packages() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            concat!(
                "lockfileVersion: '9.0'\n",
                "\n",
                "importers:\n",
                "  .:\n",
                "    dependencies:\n",
                "      lodash:\n",
                "        specifier: ^4.17.21\n",
                "        version: 4.17.21\n",
                "    devDependencies:\n",
                "      typescript:\n",
                "        specifier: ^5.0.0\n",
                "        version: 5.2.2\n",
                "\n",
                "packages:\n",
                "\n",
                "  lodash@4.17.21:\n",
                "    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg}\n",
                "    dev: false\n",
                "\n",
                "  typescript@5.2.2:\n",
                "    resolution: {integrity: sha512-mIbW0Sf0MfmZIkWwZlNdcLYy4EBEOJaCKdqXmQOf9zQiEUxJ0jEroBNkdwgY2PLq9mRlMkORLp+V0OsdbNQPA}\n",
                "    dev: true\n",
                "\n",
                "  chokidar@3.5.3:\n",
                "    resolution: {integrity: sha512-ynBi1dZ7l5dXKUeXlV+1dCBJbAwxWfllPhtuK1qN5G5pXGDX1n7IvYiA3TQmRfHFRhXk2QBWmVBQlBlyYCUAA}\n",
                "    optional: true\n",
                "    hasBin: true\n",
                "    dependencies:\n",
                "      anymatch: '3.1.3'\n",
                "\n",
                "  anymatch@3.1.3:\n",
                "    resolution: {integrity: sha512-z4s7hNABNkPnHhVBMuUoCJhJSxkwkutdBmM9E2jY0GkqGnJGdyxpmVdMk9HtNi2F4}\n",
                "\n",
                "  left-pad@1.3.0:\n",
                "    resolution: {integrity: sha512-xIxjYzfAtRcAwY6CwSChWBFjJXyInpY3wLjWkgOaKQ3JDmGmoRV4vSuYqQoVOyjKw}\n",
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
        assert_eq!(scope_of("lodash"), Some(Scope::Runtime));
        assert_eq!(scope_of("typescript"), Some(Scope::Development));
        assert_eq!(scope_of("chokidar"), Some(Scope::Optional));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "left-pad" && c.version == "1.3.0")
        );
        assert!(inventory.dependencies.iter().any(|e| {
            inventory.components.get(&e.from).map(|c| c.name.as_str()) == Some("chokidar")
                && inventory.components.get(&e.to).map(|c| c.name.as_str()) == Some("anymatch")
        }));
    }

    #[test]
    fn scans_poetry_and_pipfile_python_locks() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("poetry.lock"),
            concat!(
                "[metadata]\n",
                "lock-version = \"2.0\"\n",
                "\n",
                "[[package]]\n",
                "name = \"requests\"\n",
                "version = \"2.31.0\"\n",
                "optional = false\n",
                "category = \"main\"\n",
                "dependencies = { charset-normalizer = { version = \"^3.0\" } }\n",
                "\n",
                "[[package]]\n",
                "name = \"charset-normalizer\"\n",
                "version = \"3.3.2\"\n",
                "category = \"main\"\n",
                "\n",
                "[[package]]\n",
                "name = \"pytest\"\n",
                "version = \"7.4.2\"\n",
                "category = \"dev\"\n",
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
        assert_eq!(scope_of("requests"), Some(Scope::Runtime));
        assert_eq!(scope_of("pytest"), Some(Scope::Development));
        assert_eq!(inventory.components.len(), 3);
        assert!(inventory.dependencies.iter().any(|e| {
            inventory.components.get(&e.from).map(|c| c.name.as_str()) == Some("requests")
                && inventory.components.get(&e.to).map(|c| c.name.as_str())
                    == Some("charset-normalizer")
        }));

        let pipfile = tempdir().unwrap();
        fs::write(
            pipfile.path().join("Pipfile.lock"),
            r#"{"_meta":{"requires":{}},"default":{"requests":{"version":"==2.31.0","hashes":["sha256:abc"]}},"develop":{"pytest":{"version":"==7.4.2"}}}"#,
        )
        .unwrap();
        let inventory = scan_path(pipfile.path(), &config()).unwrap();
        let scope_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.scope)
        };
        assert_eq!(scope_of("requests"), Some(Scope::Runtime));
        assert_eq!(scope_of("pytest"), Some(Scope::Development));
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "requests" && c.version == "2.31.0")
        );
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
