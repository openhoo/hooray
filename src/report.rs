use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as FmtWrite},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component as PathComponent, Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{ffi::CString, os::unix::ffi::OsStrExt};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    ApplicabilityStatus, AssetKind, Component, ComponentId, Finding, FindingId, FindingStatus,
    Location, LocationId, PolicyDecision, PolicyOutcome, ScanReport, Scope, Severity, SourceKind,
};

pub const CANONICAL_REPORT_VERSION: &str = "1.0.0";
pub const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 1_000_000;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportFormat {
    Json,
    Yaml,
    Table,
    Sarif,
    GitLabSarif,
    Junit,
    Html,
    CycloneDxVex,
    GitLabCycloneDx,
    Spdx,
    GitLabCodeQuality,
    JsonLines,
}

impl ReportFormat {
    pub const ALL: [Self; 12] = [
        Self::Json,
        Self::Yaml,
        Self::Table,
        Self::Sarif,
        Self::GitLabSarif,
        Self::Junit,
        Self::Html,
        Self::CycloneDxVex,
        Self::GitLabCycloneDx,
        Self::Spdx,
        Self::GitLabCodeQuality,
        Self::JsonLines,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Table => "table",
            Self::Sarif => "sarif",
            Self::GitLabSarif => "gitlab-sarif",
            Self::Junit => "junit",
            Self::Html => "html",
            Self::CycloneDxVex => "cyclonedx-vex",
            Self::GitLabCycloneDx => "gitlab-cyclonedx",
            Self::Spdx => "spdx",
            Self::GitLabCodeQuality => "gitlab-code-quality",
            Self::JsonLines => "jsonl",
        }
    }

    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json | Self::Spdx | Self::GitLabCodeQuality => "json",
            Self::Yaml => "yaml",
            Self::Table => "txt",
            Self::Sarif | Self::GitLabSarif => "sarif",
            Self::Junit => "xml",
            Self::Html => "html",
            Self::CycloneDxVex | Self::GitLabCycloneDx => "cdx.json",
            Self::JsonLines => "jsonl",
        }
    }

    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json | Self::Spdx | Self::GitLabCodeQuality => "application/json",
            Self::Yaml => "application/yaml",
            Self::Table => "text/plain; charset=utf-8",
            Self::Sarif => "application/sarif+json",
            Self::GitLabSarif => "application/sarif+json",
            Self::Junit => "application/xml",
            Self::Html => "text/html; charset=utf-8",
            Self::CycloneDxVex => "application/vnd.cyclonedx+json",
            Self::GitLabCycloneDx => "application/vnd.cyclonedx+json",
            Self::JsonLines => "application/x-ndjson",
        }
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ReportFormat {
    type Err = ParseReportFormatError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            "table" | "text" => Ok(Self::Table),
            "sarif" | "sarif-2.1.0" => Ok(Self::Sarif),
            "gitlab-sarif" | "gitlab-sarif-2.1.0" => Ok(Self::GitLabSarif),
            "junit" | "junit-xml" => Ok(Self::Junit),
            "html" => Ok(Self::Html),
            "cyclonedx" | "cyclonedx-vex" | "cdx" | "cdx-vex" => Ok(Self::CycloneDxVex),
            "gitlab-cyclonedx" | "gitlab-cyclonedx-1.6" => Ok(Self::GitLabCycloneDx),
            "spdx" | "spdx-json" | "spdx-2.3" => Ok(Self::Spdx),
            "gitlab" | "gitlab-code-quality" | "code-quality" => Ok(Self::GitLabCodeQuality),
            "jsonl" | "ndjson" | "json-lines" => Ok(Self::JsonLines),
            _ => Err(ParseReportFormatError(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported report format '{0}'")]
pub struct ParseReportFormatError(String);

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("report model is invalid: {0}")]
    InvalidModel(#[from] crate::model::ModelInvariantError),
    #[error("report exceeds safety limit: {0}")]
    Limit(String),
    #[error("could not serialize report: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not serialize YAML report: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("could not write report: {0}")]
    Io(#[from] io::Error),
    #[error("invalid GitLab artifact destination '{path}': {reason}")]
    InvalidDestination { path: PathBuf, reason: String },
    #[error("GitLab artifact destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error("atomic no-clobber publication is unsupported on this platform for '{0}'")]
    UnsupportedAtomicPublication(PathBuf),
    #[error("could not create GitLab artifact staging directory '{path}': {source}")]
    StagingCreate { path: PathBuf, source: io::Error },
    #[error("could not write GitLab artifact '{path}': {source}")]
    StagingWrite { path: PathBuf, source: io::Error },
    #[error("could not synchronize GitLab artifact staging directory '{path}': {source}")]
    StagingSync { path: PathBuf, source: io::Error },
    #[error(
        "could not atomically publish GitLab artifacts from '{staging}' to '{destination}': {source}"
    )]
    Publish {
        staging: PathBuf,
        destination: PathBuf,
        source: io::Error,
    },
    #[error(
        "GitLab artifacts were fully published at '{destination}', but synchronizing parent '{parent}' failed: {source}; do not delete or overwrite the completed bundle"
    )]
    PublishedNotDurable {
        destination: PathBuf,
        parent: PathBuf,
        source: io::Error,
    },
    #[error("{primary}; additionally could not clean staging directory '{path}': {cleanup}")]
    Cleanup {
        primary: Box<ReportError>,
        path: PathBuf,
        cleanup: io::Error,
    },
}

#[derive(Serialize)]
struct CanonicalEnvelope<'a> {
    format: &'static str,
    format_version: &'static str,
    report: &'a ScanReport,
}

#[derive(Serialize)]
struct JsonLineEnvelope<'a> {
    format: &'static str,
    format_version: &'static str,
    report_schema_version: &'a str,
    run_id: &'a str,
    finding: &'a Finding,
    dependency_paths: Vec<Vec<&'a str>>,
    policy_outcomes: Vec<&'a PolicyDecision>,
}

pub fn render(report: &ScanReport, format: ReportFormat) -> Result<Vec<u8>, ReportError> {
    render_with_limit(report, format, MAX_REPORT_BYTES)
}

fn render_with_limit(
    report: &ScanReport,
    format: ReportFormat,
    limit: usize,
) -> Result<Vec<u8>, ReportError> {
    report.validate()?;
    validate_limits(report)?;
    let sanitized = sanitize_report(report)?;
    match format {
        ReportFormat::Json => render_json(&sanitized, limit),
        ReportFormat::Yaml => render_yaml(&sanitized, limit),
        ReportFormat::Table => render_table(&sanitized, limit, &ReportIndex::new(&sanitized)),
        ReportFormat::Sarif => render_sarif(&sanitized, limit, &ReportIndex::new(&sanitized)),
        ReportFormat::GitLabSarif => {
            render_gitlab_sarif(&sanitized, limit, &ReportIndex::new(&sanitized))
        }
        ReportFormat::Junit => render_junit(&sanitized, limit, &ReportIndex::new(&sanitized)),
        ReportFormat::Html => render_html(&sanitized, limit, &ReportIndex::new(&sanitized)),
        ReportFormat::CycloneDxVex => {
            render_cyclonedx_vex(&sanitized, limit, &ReportIndex::new(&sanitized))
        }
        ReportFormat::GitLabCycloneDx => {
            render_gitlab_cyclonedx(&sanitized, limit, &ReportIndex::new(&sanitized))
        }
        ReportFormat::Spdx => render_spdx(&sanitized, limit, &ReportIndex::new(&sanitized)),
        ReportFormat::GitLabCodeQuality => {
            render_gitlab(&sanitized, limit, &ReportIndex::new(&sanitized))
        }
        ReportFormat::JsonLines => {
            render_json_lines(&sanitized, limit, &ReportIndex::new(&sanitized))
        }
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }

    fn finish(self) -> Result<Vec<u8>, ReportError> {
        if self.exceeded {
            Err(report_limit(self.limit))
        } else {
            Ok(self.bytes)
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("report output limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn report_limit(limit: usize) -> ReportError {
    ReportError::Limit(format!("rendered output exceeds maximum of {limit} bytes"))
}
fn bounded_write_all(output: &mut BoundedWriter, value: &[u8]) -> Result<(), ReportError> {
    output.write_all(value).map_err(|error| {
        if output.exceeded {
            report_limit(output.limit)
        } else {
            error.into()
        }
    })
}

struct BoundedText {
    text: String,
    limit: usize,
    exceeded: bool,
}

impl BoundedText {
    fn new(limit: usize) -> Self {
        Self {
            text: String::new(),
            limit,
            exceeded: false,
        }
    }

    fn from(value: &str, limit: usize) -> Self {
        let mut output = Self::new(limit);
        output.push_str(value);
        output
    }

    fn push_str(&mut self, value: &str) {
        if value.len() > self.limit.saturating_sub(self.text.len()) {
            self.exceeded = true;
        } else {
            self.text.push_str(value);
        }
    }

    fn push(&mut self, value: char) {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes));
    }

    fn finish(self) -> Result<Vec<u8>, ReportError> {
        if self.exceeded {
            Err(report_limit(self.limit))
        } else {
            Ok(self.text.into_bytes())
        }
    }
}

impl fmt::Write for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_str(value);
        if self.exceeded {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}
pub fn render_to_string(report: &ScanReport, format: ReportFormat) -> Result<String, ReportError> {
    String::from_utf8(render(report, format)?)
        .map_err(|error| ReportError::Io(io::Error::new(io::ErrorKind::InvalidData, error)))
}

pub fn write_atomic(
    path: impl AsRef<Path>,
    report: &ScanReport,
    format: ReportFormat,
) -> Result<(), ReportError> {
    let bytes = render(report, format)?;
    write_bytes_atomic(path.as_ref(), &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReportError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "report path has no file name")
    })?;
    let mut temporary = PathBuf::from(parent);
    temporary.push(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));

    let result = (|| -> Result<(), io::Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        replace_file(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(ReportError::Io)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                || error.kind() == io::ErrorKind::PermissionDenied =>
        {
            fs::remove_file(destination)?;
            fs::rename(source, destination)
        }
        Err(error) => Err(error),
    }
}

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn write_gitlab_artifacts(
    output_dir: impl AsRef<Path>,
    report: &ScanReport,
) -> Result<(), ReportError> {
    report.validate()?;
    validate_limits(report)?;
    let report = sanitize_report(report)?;
    let destination = output_dir.as_ref();
    if destination.as_os_str().is_empty()
        || destination == Path::new("-")
        || destination.file_name().is_none_or(|name| name.is_empty())
    {
        return Err(ReportError::InvalidDestination {
            path: destination.to_path_buf(),
            reason: "expected a non-empty named directory destination other than '-'".into(),
        });
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(ReportError::InvalidDestination {
            path: destination.to_path_buf(),
            reason: "parent directory does not exist".into(),
        });
    }
    if destination.exists() {
        return Err(ReportError::DestinationExists(destination.to_path_buf()));
    }
    let index = ReportIndex::new(&report);
    let denied = report.policy_summary.denied;
    let files = [
        (
            "gl-code-quality-report.json",
            render_gitlab(&report, MAX_REPORT_BYTES, &index)?,
        ),
        (
            "gl-sarif-report.sarif",
            render_gitlab_sarif(&report, MAX_REPORT_BYTES, &index)?,
        ),
        (
            "gl-sbom-hooray.cdx.json",
            render_gitlab_cyclonedx(&report, MAX_REPORT_BYTES, &index)?,
        ),
        (
            "gl-junit-report.xml",
            render_junit(&report, MAX_REPORT_BYTES, &index)?,
        ),
        (
            "hooray.env",
            format!(
                "HOORAY_POLICY_DENIED={}\nHOORAY_POLICY_DENIED_COUNT={}\n",
                denied > 0,
                denied
            )
            .into_bytes(),
        ),
    ];
    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(".hooray-gitlab-{}-{counter}", std::process::id()));
    fs::create_dir(&staging).map_err(|source| ReportError::StagingCreate {
        path: staging.clone(),
        source,
    })?;
    let operation = (|| {
        for (name, bytes) in files {
            write_bundle_file(&staging.join(name), &bytes)?;
        }
        File::open(&staging)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ReportError::StagingSync {
                path: staging.clone(),
                source,
            })?;
        publish_directory_no_replace(&staging, destination)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ReportError::PublishedNotDurable {
                destination: destination.to_path_buf(),
                parent: parent.to_path_buf(),
                source,
            })?;
        Ok(())
    })();
    match operation {
        Ok(()) => Ok(()),
        Err(error @ ReportError::PublishedNotDurable { .. }) => Err(error),
        Err(error) => match fs::remove_dir_all(&staging) {
            Ok(()) => Err(error),
            Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
            Err(cleanup) => Err(ReportError::Cleanup {
                primary: Box::new(error),
                path: staging,
                cleanup,
            }),
        },
    }
}

fn write_bundle_file(path: &Path, bytes: &[u8]) -> Result<(), ReportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| ReportError::StagingWrite {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| ReportError::StagingWrite {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn publish_directory_no_replace(staging: &Path, destination: &Path) -> Result<(), ReportError> {
    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    unsafe extern "C" {
        fn renameat2(
            olddirfd: i32,
            oldpath: *const i8,
            newdirfd: i32,
            newpath: *const i8,
            flags: u32,
        ) -> i32;
    }
    let old = CString::new(staging.as_os_str().as_bytes()).map_err(|_| {
        ReportError::InvalidDestination {
            path: staging.to_path_buf(),
            reason: "staging path contains NUL".into(),
        }
    })?;
    let new = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        ReportError::InvalidDestination {
            path: destination.to_path_buf(),
            reason: "destination path contains NUL".into(),
        }
    })?;
    // SAFETY: both pointers reference live NUL-terminated byte strings for this call; AT_FDCWD
    // resolves relative paths against the unchanged process cwd, and no Rust aliases are exposed.
    let result = unsafe {
        renameat2(
            AT_FDCWD,
            old.as_ptr(),
            AT_FDCWD,
            new.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::AlreadyExists {
        Err(ReportError::DestinationExists(destination.to_path_buf()))
    } else {
        Err(ReportError::Publish {
            staging: staging.to_path_buf(),
            destination: destination.to_path_buf(),
            source,
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn publish_directory_no_replace(_staging: &Path, destination: &Path) -> Result<(), ReportError> {
    Err(ReportError::UnsupportedAtomicPublication(
        destination.to_path_buf(),
    ))
}

fn render_json(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    pretty_json(
        &CanonicalEnvelope {
            format: "hooray-canonical-report",
            format_version: CANONICAL_REPORT_VERSION,
            report,
        },
        limit,
    )
}

fn render_yaml(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    let envelope = CanonicalEnvelope {
        format: "hooray-canonical-report",
        format_version: CANONICAL_REPORT_VERSION,
        report,
    };
    let mut output = BoundedWriter::new(limit);
    bounded_write_all(&mut output, b"---\n")?;
    if let Err(error) = serde_yaml::to_writer(&mut output, &envelope) {
        if output.exceeded {
            return Err(report_limit(limit));
        }
        return Err(error.into());
    }
    if !output.bytes.ends_with(b"\n") {
        bounded_write_all(&mut output, b"\n")?;
    }
    output.finish()
}

fn render_table(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let mut output = BoundedText::new(limit);
    output.push_str("HOORAY REPORT v");
    output.push_str(CANONICAL_REPORT_VERSION);
    output.push('\n');
    output.push_str(&format!(
        "Run: {}  Asset: {}  Components: {}  Findings: {}  Policy: allow={} warn={} deny={}\n\n",
        report.run.id,
        clean_cell(&report.inventory.asset.name),
        report.inventory.components.len(),
        report.findings.len(),
        report.policy_summary.allowed,
        report.policy_summary.warned,
        report.policy_summary.denied
    ));
    output.push_str("SEVERITY | KIND             | ID                       | COMPONENT                | LOCATION                 | SUMMARY\n");
    output.push_str("---------+------------------+--------------------------+--------------------------+--------------------------+------------------------------\n");
    for finding in report.findings.values() {
        let component = finding.component_id.as_ref().map_or("-", |id| id.as_str());
        let location = finding.location_id.as_ref().map_or("-", |id| id.as_str());
        output.push_str(&format!(
            "{:<8} | {:<16} | {:<24} | {:<24} | {:<24} | {}\n",
            finding.severity.as_str(),
            finding.kind.as_str(),
            truncate_cell(finding.id.as_str(), 24),
            truncate_cell(component, 24),
            truncate_cell(location, 24),
            clean_cell(finding.summary.as_deref().unwrap_or(""))
        ));
        let paths = index.paths(finding);
        for path in paths {
            output.push_str("          path: ");
            output.push_str(&path.join(" -> "));
            output.push('\n');
        }
        if let Some(remediation) = &finding.remediation {
            output.push_str("          remediation: ");
            output.push_str(&clean_cell(&remediation.description));
            if !remediation.fixed_versions.is_empty() {
                output.push_str(" [fixed: ");
                output.push_str(
                    &remediation
                        .fixed_versions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                output.push(']');
            }
            output.push('\n');
        }
        for evidence in &finding.evidence {
            output.push_str("          evidence: ");
            output.push_str(&clean_cell(&evidence.description));
            output.push('\n');
            for (key, value) in &evidence.properties {
                output.push_str(&format!("            {key}: {}\n", clean_cell(value)));
            }
        }
        for decision in index.policies(&finding.id) {
            output.push_str(&format!(
                "          policy: {}={} ({})\n",
                decision.policy_id,
                policy_outcome(decision.outcome),
                clean_cell(&decision.reason)
            ));
        }
    }
    output.finish()
}

pub(crate) struct ReportIndex<'a> {
    roots: BTreeSet<&'a ComponentId>,
    adjacency: BTreeMap<&'a ComponentId, Vec<&'a ComponentId>>,
    locations: BTreeMap<&'a LocationId, &'a Location>,
    policies: BTreeMap<&'a FindingId, Vec<&'a PolicyDecision>>,
}

impl<'a> ReportIndex<'a> {
    pub(crate) fn new(report: &'a ScanReport) -> Self {
        let mut roots: BTreeSet<_> = report.inventory.components.keys().collect();
        let mut adjacency: BTreeMap<_, Vec<_>> = report
            .inventory
            .components
            .keys()
            .map(|id| (id, Vec::new()))
            .collect();
        for edge in &report.inventory.dependencies {
            roots.remove(&edge.to);
            adjacency.entry(&edge.from).or_default().push(&edge.to);
        }
        if roots.is_empty() {
            roots.extend(report.inventory.components.keys());
        }
        let locations = report
            .inventory
            .locations
            .iter()
            .chain(
                report
                    .inventory
                    .components
                    .values()
                    .flat_map(|component| component.locations.iter()),
            )
            .map(|location| (&location.id, location))
            .collect();
        let mut policies: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for decision in &report.policy_decisions {
            if let Some(finding_id) = &decision.finding_id {
                policies.entry(finding_id).or_default().push(decision);
            }
        }
        Self {
            roots,
            adjacency,
            locations,
            policies,
        }
    }

    fn paths(&self, finding: &'a Finding) -> Vec<Vec<&'a str>> {
        let Some(target) = finding.component_id.as_ref() else {
            return Vec::new();
        };
        let mut paths = Vec::new();
        for root in &self.roots {
            let mut stack = vec![(*root, vec![*root], BTreeSet::from([*root]))];
            while let Some((node, path, visited)) = stack.pop() {
                if node == target {
                    paths.push(path.into_iter().map(ComponentId::as_str).collect());
                    if paths.len() >= 100 {
                        return paths;
                    }
                    continue;
                }
                if let Some(children) = self.adjacency.get(node) {
                    for child in children.iter().rev() {
                        if !visited.contains(child) {
                            let mut next_path = path.clone();
                            next_path.push(child);
                            let mut next_visited = visited.clone();
                            next_visited.insert(child);
                            stack.push((child, next_path, next_visited));
                        }
                    }
                }
            }
        }
        paths.sort();
        paths
    }

    fn policies(&self, finding_id: &FindingId) -> &[&'a PolicyDecision] {
        self.policies.get(finding_id).map_or(&[], Vec::as_slice)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitLabFindingLocation {
    pub(crate) path: String,
    pub(crate) line: u32,
}

pub(crate) fn gitlab_repository_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("//")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
            && normalized
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
    {
        return None;
    }
    let lower = normalized.to_ascii_lowercase();
    if lower.starts_with("bom-ref:")
        || lower.starts_with("purl:")
        || lower.starts_with("pkg:")
        || lower.split_once(':').is_some_and(|(scheme, value)| {
            !value.is_empty()
                && matches!(
                    scheme,
                    "md5"
                        | "sha1"
                        | "sha224"
                        | "sha256"
                        | "sha384"
                        | "sha512"
                        | "blake2"
                        | "blake3"
                )
        })
    {
        return None;
    }
    let path = Path::new(&normalized);
    if path.is_absolute() {
        return None;
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            PathComponent::CurDir => {}
            PathComponent::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            PathComponent::ParentDir | PathComponent::RootDir | PathComponent::Prefix(_) => {
                return None;
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

pub(crate) fn gitlab_finding_location(
    report: &ScanReport,
    index: &ReportIndex<'_>,
    finding: &Finding,
) -> Option<GitLabFindingLocation> {
    let direct = finding.location_id.iter();
    let evidence = finding
        .evidence
        .iter()
        .flat_map(|item| item.locations.iter());
    for id in direct.chain(evidence) {
        let Some(location) = index.locations.get(id) else {
            continue;
        };
        if let Some(path) = gitlab_repository_path(&location.path) {
            return Some(GitLabFindingLocation {
                path,
                line: location.start.map_or(1, |position| position.line.max(1)),
            });
        }
    }
    finding
        .component_id
        .as_ref()
        .and_then(|id| report.inventory.components.get(id))
        .and_then(gitlab_component_input_file)
        .map(|path| GitLabFindingLocation { path, line: 1 })
}

pub(crate) fn gitlab_component_input_file(component: &Component) -> Option<String> {
    component
        .provenance
        .iter()
        .filter(|source| matches!(source.kind, SourceKind::Lockfile | SourceKind::Manifest))
        .find_map(|source| gitlab_repository_path(&source.locator))
}

pub(crate) fn gitlab_code_quality_entry(
    _report: &ScanReport,
    index: &ReportIndex<'_>,
    finding: &Finding,
    location: &GitLabFindingLocation,
) -> Value {
    json!({
        "description": finding_detail_text(index, finding),
        "check_name": finding.rule_id.as_str(),
        "fingerprint": finding.id.as_str(),
        "severity": gitlab_severity(finding.severity),
        "location": {"path": location.path, "lines": {"begin": location.line}},
        "categories": [finding.kind.as_str()],
        "hooray": {
            "format_version": CANONICAL_REPORT_VERSION,
            "finding_id": finding.id.as_str(),
            "component_id": finding.component_id.as_ref().map(|id| id.as_str()),
            "dependency_paths": index.paths(finding),
            "remediation": finding.remediation,
            "policy_outcomes": index.policies(&finding.id),
            "evidence": finding.evidence
        }
    })
}
fn render_sarif(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let mut representatives = BTreeMap::new();
    for finding in report.findings.values() {
        representatives
            .entry(finding.rule_id.as_str())
            .or_insert(finding);
    }
    let rules: Vec<Value> = representatives
        .into_iter()
        .map(|(rule_id, representative)| json!({
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": representative.summary.as_deref().unwrap_or(rule_id)},
            "fullDescription": {"text": representative.details.as_deref().or(representative.summary.as_deref()).unwrap_or(rule_id)},
            "defaultConfiguration": {"level": sarif_level(representative.severity)},
            "properties": {"tags": [representative.kind.as_str()]}
        }))
        .collect();

    let results: Vec<Value> = report.findings.values().map(|finding| {
        let locations = sarif_locations(index, finding);
        let paths = index.paths(finding);
        let evidence: Vec<Value> = finding.evidence.iter().map(|item| json!({
            "description": item.description,
            "locations": item.locations.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
            "references": item.references,
            "properties": item.properties,
            "redacted": item.redacted
        })).collect();
        let policies: Vec<Value> = index.policies(&finding.id).iter().map(|decision| json!({
            "policyId": decision.policy_id.as_str(), "outcome": policy_outcome(decision.outcome),
            "reason": decision.reason, "exceptionId": decision.exception_id
        })).collect();
        let remediation = finding.remediation.as_ref().map(|item| json!({
            "description": item.description, "fixedVersions": item.fixed_versions, "references": item.references
        }));
        let mut result = json!({
            "ruleId": finding.rule_id.as_str(),
            "level": sarif_level(finding.severity),
            "message": {"text": finding.summary.as_deref().unwrap_or(finding.rule_id.as_str())},
            "fingerprints": {"hoorayFindingId/v1": finding.id.as_str()},
            "partialFingerprints": {"primaryLocationLineHash": finding.id.as_str()},
            "properties": {
                "findingId": finding.id.as_str(), "kind": finding.kind.as_str(),
                "severity": finding.severity.as_str(), "componentId": finding.component_id.as_ref().map(|id| id.as_str()),
                "dependencyPaths": paths, "remediation": remediation, "policyOutcomes": policies,
                "evidence": evidence, "applicability": finding.applicability
            }
        });
        if !locations.is_empty() {
            result["locations"] = Value::Array(locations);
        }
        result
    }).collect();

    pretty_json(
        &json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "hooray", "semanticVersion": report.run.scanner_version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION")),
                    "informationUri": "https://github.com/openhoo/hooray", "rules": rules
                }},
                "automationDetails": {"id": report.run.id.as_str()},
                "results": results,
                "properties": {"reportFormatVersion": CANONICAL_REPORT_VERSION, "policySummary": report.policy_summary}
            }]
        }),
        limit,
    )
}

const GITLAB_SARIF_MAX_RESULTS: usize = 5_000;
const GITLAB_SARIF_MAX_BYTES: usize = 10_000_000;

fn render_gitlab_sarif(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let mut omitted_resolved = 0usize;
    let mut omitted_without_location = 0usize;
    let mut candidates = Vec::new();
    for finding in report.findings.values() {
        if finding.status == FindingStatus::Resolved {
            omitted_resolved += 1;
        } else if let Some(location) = gitlab_finding_location(report, index, finding) {
            candidates.push((gitlab_rank(finding), finding, location));
        } else {
            omitted_without_location += 1;
        }
    }
    candidates.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.id.cmp(&right.1.id))
    });
    let total_candidates = candidates.len();
    candidates.truncate(GITLAB_SARIF_MAX_RESULTS);
    let byte_limit = limit.min(GITLAB_SARIF_MAX_BYTES);
    let render_prefix = |count: usize| {
        gitlab_sarif_document(
            report,
            index,
            &candidates[..count],
            omitted_resolved,
            omitted_without_location,
            total_candidates.saturating_sub(count),
        )
    };
    let full = serde_json::to_vec(&render_prefix(candidates.len()))?;
    if full.len() < byte_limit {
        let mut bytes = full;
        bytes.push(b'\n');
        return Ok(bytes);
    }
    let empty = serde_json::to_vec(&render_prefix(0))?;
    if empty.len() >= byte_limit {
        return Err(report_limit(byte_limit));
    }
    let mut low = 0usize;
    let mut high = candidates.len();
    while low < high {
        let middle = (low + high).div_ceil(2);
        if serde_json::to_vec(&render_prefix(middle))?.len() < byte_limit {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let mut bytes = serde_json::to_vec(&render_prefix(low))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn gitlab_sarif_document(
    report: &ScanReport,
    index: &ReportIndex<'_>,
    candidates: &[(f64, &Finding, GitLabFindingLocation)],
    omitted_resolved: usize,
    omitted_without_location: usize,
    omitted_by_limit: usize,
) -> Value {
    let canonical_ids = canonical_sarif_rule_ids(candidates.iter().map(|(_, finding, _)| *finding));
    let mut representatives = BTreeMap::new();
    let results: Vec<Value> = candidates
        .iter()
        .map(|(rank, finding, location)| {
            let rule_id = canonical_ids
                .get(&finding.id)
                .expect("every retained finding has a canonical rule ID");
            representatives.entry(rule_id.clone()).or_insert(*finding);
            let policies: Vec<Value> = index
                .policies(&finding.id)
                .iter()
                .map(|decision| json!({"policyId": decision.policy_id.as_str(), "outcome": policy_outcome(decision.outcome), "reason": truncate_chars(&decision.reason, 1024)}))
                .collect();
            json!({
                "ruleId": rule_id,
                "level": sarif_level(finding.severity),
                "rank": rank,
                "message": {"text": truncate_chars(finding.summary.as_deref().or(finding.details.as_deref()).unwrap_or(finding.rule_id.as_str()), 1024)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": location.path}, "region": {"startLine": location.line}}}],
                "fingerprints": {"hoorayFindingId/v1": finding.id.as_str()},
                "partialFingerprints": {"primaryLocationLineHash": finding.id.as_str()},
                "properties": {
                    "findingId": finding.id.as_str(), "originalRuleId": finding.rule_id.as_str(), "kind": finding.kind.as_str(),
                    "componentId": finding.component_id.as_ref().map(|id| id.as_str()), "policyOutcomes": policies,
                    "remediation": finding.remediation.as_ref().map(|item| truncate_chars(&item.description, 1024))
                }
            })
        })
        .collect();
    let rules: Vec<Value> = representatives
        .into_iter()
        .map(|(id, finding)| json!({
            "id": id,
            "name": truncate_chars(finding.rule_id.as_str(), 255),
            "shortDescription": {"text": truncate_chars(finding.summary.as_deref().unwrap_or(finding.rule_id.as_str()), 1024)},
            "fullDescription": {"text": truncate_chars(finding.details.as_deref().or(finding.summary.as_deref()).unwrap_or(finding.rule_id.as_str()), 1024)},
            "defaultConfiguration": {"level": sarif_level(finding.severity)},
            "properties": {"tags": gitlab_sarif_tags(finding)}
        }))
        .collect();
    let version = report
        .run
        .scanner_version
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Hooray", "organization": "OpenHoo", "informationUri": "https://github.com/openhoo/hooray", "version": version, "semanticVersion": version, "rules": rules}},
            "automationDetails": {"id": report.run.id.as_str()}, "results": results,
            "properties": {"totalFindings": report.findings.len(), "includedFindings": candidates.len(), "omittedResolved": omitted_resolved, "omittedWithoutLocation": omitted_without_location, "omittedByLimit": omitted_by_limit}
        }]
    })
}

fn canonical_sarif_rule_ids<'a>(
    findings: impl IntoIterator<Item = &'a Finding>,
) -> BTreeMap<FindingId, String> {
    let findings: Vec<_> = findings.into_iter().collect();
    let mut bases: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in &findings {
        let base = normalized_cve(finding.advisory_id.as_deref().unwrap_or(""))
            .unwrap_or_else(|| finding.rule_id.as_str().to_owned());
        bases
            .entry(base)
            .or_default()
            .insert(finding.rule_id.as_str().to_owned());
    }
    findings
        .into_iter()
        .map(|finding| {
            let base = normalized_cve(finding.advisory_id.as_deref().unwrap_or(""))
                .unwrap_or_else(|| finding.rule_id.as_str().to_owned());
            let id = if bases[&base].len() > 1 {
                let digest = Sha256::digest(finding.rule_id.as_str().as_bytes());
                format!("{base}-{}", hex_prefix(&digest, 8))
            } else {
                base
            };
            (finding.id.clone(), id)
        })
        .collect()
}

fn gitlab_rank(finding: &Finding) -> f64 {
    finding.risk.as_ref().map_or_else(
        || match finding.severity {
            Severity::Critical => 95.0,
            Severity::High => 80.0,
            Severity::Medium => 55.0,
            Severity::Low => 25.0,
            Severity::Unknown => 0.0,
        },
        |risk| f64::from(risk.score()) / 100.0,
    )
}

fn gitlab_sarif_tags(finding: &Finding) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for candidate in finding.advisory_id.iter().chain(finding.aliases.iter()) {
        if let Some(cve) = normalized_cve(candidate) {
            tags.insert(format!("cve:{}", &cve[4..]));
        }
        if let Some(cwe) = normalized_cwe(candidate) {
            tags.insert(format!("cwe:{cwe}"));
        }
    }
    tags.insert(format!("hooray:{}", finding.kind.as_str()));
    tags.into_iter().take(10).collect()
}

fn normalized_cve(value: &str) -> Option<String> {
    let upper = value.trim().to_ascii_uppercase();
    let rest = upper.strip_prefix("CVE-")?;
    let (year, number) = rest.split_once('-')?;
    (year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && number.len() >= 4
        && number.chars().all(|c| c.is_ascii_digit()))
    .then_some(format!("CVE-{year}-{number}"))
}

fn normalized_cwe(value: &str) -> Option<String> {
    let upper = value.trim().to_ascii_uppercase();
    let number = upper
        .strip_prefix("CWE-")
        .or_else(|| upper.strip_prefix("CWE:"))?;
    (!number.is_empty() && number.chars().all(|c| c.is_ascii_digit())).then(|| number.to_owned())
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes[..count]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn render_gitlab_cyclonedx(
    report: &ScanReport,
    limit: usize,
    _index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let asset_ref = format!(
        "asset:{}",
        Sha256::digest(report.inventory.asset.id.as_str().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut metadata_component = json!({
        "type": cyclonedx_asset_type(report.inventory.asset.kind),
        "bom-ref": asset_ref,
        "name": report.inventory.asset.name
    });
    if let Some(version) = &report.inventory.asset.version {
        metadata_component["version"] = json!(version);
    }
    let components: Vec<Value> = report.inventory.components.values().map(|component| {
        let mut properties = Vec::new();
        if let Some(path) = gitlab_component_input_file(component) {
            properties.push(json!({"name": "gitlab:dependency_scanning:input_file:path", "value": path}));
            if let Some((manager, language)) = gitlab_package_metadata(&component.purl) {
                properties.push(json!({"name": "gitlab:dependency_scanning:package_manager:name", "value": manager}));
                properties.push(json!({"name": "gitlab:dependency_scanning:language:name", "value": language}));
            }
        }
        if let Some(category) = gitlab_dependency_category(component.scope) {
            properties.push(json!({"name": "gitlab:dependency_scanning:category", "value": category}));
        }
        let mut value = json!({
            "type": "library", "bom-ref": component.identity.as_str(), "name": component.name,
            "version": component.version, "purl": component.purl
        });
        if !properties.is_empty() { value["properties"] = Value::Array(properties); }
        if let Some(licenses) = cyclonedx_licenses(component) { value["licenses"] = licenses; }
        value
    }).collect();
    let dependencies: Vec<Value> = report
        .inventory
        .components
        .keys()
        .map(|id| {
            let depends_on: Vec<&str> = report
                .inventory
                .dependencies
                .iter()
                .filter(|edge| &edge.from == id)
                .map(|edge| edge.to.as_str())
                .collect();
            json!({"ref": id.as_str(), "dependsOn": depends_on})
        })
        .collect();
    pretty_json(
        &json!({
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{}", deterministic_uuid(report.run.id.as_str())), "version": 1,
            "metadata": {
                "timestamp": report.run.started_at,
                "tools": {"components": [{"type": "application", "name": "hooray", "version": report.run.scanner_version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION"))}]},
                "component": metadata_component,
                "properties": [{"name": "gitlab:meta:schema_version", "value": "1"}]
            },
            "components": components, "dependencies": dependencies
        }),
        limit,
    )
}

fn cyclonedx_asset_type(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Repository | AssetKind::Other => "application",
        AssetKind::Filesystem => "file",
        AssetKind::ContainerImage => "container",
        AssetKind::Sbom => "data",
        AssetKind::Package => "library",
    }
}

fn gitlab_package_metadata(purl: &str) -> Option<(&'static str, &'static str)> {
    let kind = purl
        .strip_prefix("pkg:")?
        .split('/')
        .next()?
        .to_ascii_lowercase();
    match kind.as_str() {
        "cargo" => Some(("cargo", "Rust")),
        "npm" => Some(("npm", "JavaScript")),
        "pypi" => Some(("pip", "Python")),
        "golang" => Some(("go", "Go")),
        "maven" => Some(("maven", "Java")),
        "nuget" => Some(("nuget", "C#")),
        _ => None,
    }
}

fn gitlab_dependency_category(scope: Scope) -> Option<&'static str> {
    match scope {
        Scope::Runtime | Scope::Optional => Some("production"),
        Scope::Build | Scope::Development => Some("development"),
        Scope::Test => Some("test"),
        Scope::Unknown => None,
    }
}

fn cyclonedx_licenses(component: &Component) -> Option<Value> {
    let records: Vec<_> = component
        .licenses
        .iter()
        .filter_map(|license| {
            let expression = license
                .expression
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let name = license
                .name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let url = license
                .url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            (expression.is_some() || name.is_some()).then_some((expression, name, url))
        })
        .collect();
    if records.len() == 1 {
        let (Some(expression), None, _) = records[0] else {
            return cyclonedx_license_objects(&records);
        };
        if spdx::Expression::parse(expression).is_ok() {
            return Some(json!([{"expression": expression}]));
        }
    }
    cyclonedx_license_objects(&records)
}

fn cyclonedx_license_objects(
    records: &[(Option<&str>, Option<&str>, Option<&str>)],
) -> Option<Value> {
    let mut rendered = BTreeSet::new();
    for (expression, name, url) in records {
        let single_id = expression.and_then(single_spdx_id);
        let mut license = serde_json::Map::new();
        if let Some(id) = single_id {
            license.insert("id".into(), json!(id));
        } else if let Some(name) = name {
            license.insert("name".into(), json!(name));
        } else {
            continue;
        }
        if let Some(url) = url {
            license.insert("url".into(), json!(url));
        }
        rendered.insert(
            serde_json::to_string(&json!({"license": license}))
                .expect("license JSON is serializable"),
        );
    }
    (!rendered.is_empty()).then(|| {
        Value::Array(
            rendered
                .into_iter()
                .map(|item| serde_json::from_str(&item).expect("rendered license JSON parses"))
                .collect(),
        )
    })
}

fn single_spdx_id(expression: &str) -> Option<&str> {
    let trimmed = expression.trim();
    spdx::license_id(trimmed).map(|_| trimmed)
}

fn render_junit(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let failures = report
        .findings
        .values()
        .filter(|finding| finding.status != crate::model::FindingStatus::Resolved)
        .count();
    let mut output = BoundedText::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", limit);
    output.push_str(&format!(
        "<testsuites name=\"hooray\" tests=\"{}\" failures=\"{}\">\n  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" timestamp=\"{}\">\n",
        report.findings.len(), failures, xml_attr(&report.inventory.asset.name), report.findings.len(), failures,
        xml_attr(&report.run.started_at)
    ));
    for finding in report.findings.values() {
        let file = gitlab_finding_location(report, index, finding)
            .map(|location| format!(" file=\"{}\"", xml_attr(&location.path)))
            .unwrap_or_default();
        output.push_str(&format!(
            "    <testcase classname=\"hooray.{}\" name=\"{}\"{}>\n",
            finding.kind.as_str(),
            xml_attr(finding.id.as_str()),
            file
        ));
        let body = finding_detail_text(index, finding);
        if finding.status != FindingStatus::Resolved {
            output.push_str(&format!(
                "      <failure type=\"{}\" message=\"{}\">{}</failure>\n",
                xml_attr(finding.severity.as_str()),
                xml_attr(
                    finding
                        .summary
                        .as_deref()
                        .unwrap_or(finding.rule_id.as_str())
                ),
                xml_text(&body)
            ));
        }
        output.push_str(&format!(
            "      <system-out>{}</system-out>\n",
            xml_text(&body)
        ));
        output.push_str("    </testcase>\n");
    }
    output.push_str("  </testsuite>\n</testsuites>\n");
    output.finish()
}

fn render_html(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let mut rows = BoundedText::new(limit);
    for finding in report.findings.values() {
        let details = finding_detail_text(index, finding);
        rows.push_str(&format!(
            "<tr><td><span class=\"severity {}\">{}</span></td><td>{}</td><td><code>{}</code></td><td>{}</td><td><details><summary>{}</summary><pre>{}</pre></details></td></tr>",
            finding.severity.as_str(), html_text(finding.severity.as_str()), html_text(finding.kind.as_str()),
            html_text(finding.id.as_str()),
            html_text(finding.component_id.as_ref().map_or("-", |id| id.as_str())),
            html_text(finding.summary.as_deref().unwrap_or(finding.rule_id.as_str())), html_text(&details)
        ));
    }
    let mut output = BoundedText::new(limit);
    let _ = write!(
        output,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\"><title>Hooray security report</title><style>:root{{color-scheme:light dark;font-family:system-ui,sans-serif}}body{{max-width:1200px;margin:auto;padding:2rem}}header{{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:1rem}}.card{{border:1px solid #7777;border-radius:.5rem;padding:1rem}}table{{border-collapse:collapse;width:100%;margin-top:2rem}}th,td{{padding:.65rem;border-bottom:1px solid #7777;text-align:left;vertical-align:top}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.severity{{font-weight:700}}</style></head><body><h1>Hooray security report</h1><header><div class=\"card\"><b>Run</b><br><code>{}</code></div><div class=\"card\"><b>Asset</b><br>{}</div><div class=\"card\"><b>Inventory</b><br>{} components</div><div class=\"card\"><b>Findings</b><br>{}</div><div class=\"card\"><b>Policy</b><br>{} allow / {} warn / {} deny</div></header><table><thead><tr><th>Severity</th><th>Kind</th><th>Finding</th><th>Component</th><th>Summary and evidence</th></tr></thead><tbody>{}</tbody></table><footer>Hooray canonical format v{}</footer></body></html>",
        html_text(report.run.id.as_str()),
        html_text(&report.inventory.asset.name),
        report.inventory.components.len(),
        report.findings.len(),
        report.policy_summary.allowed,
        report.policy_summary.warned,
        report.policy_summary.denied,
        rows.text,
        CANONICAL_REPORT_VERSION
    );
    output.finish()
}
fn render_cyclonedx_vex(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let components: Vec<Value> = report.inventory.components.values().map(|component| {
        json!({
            "type": "library", "bom-ref": component.identity.as_str(), "name": component.name,
            "version": component.version, "purl": component.purl,
            "properties": [{"name": "hooray:scope", "value": format!("{:?}", component.scope).to_ascii_lowercase()}]
        })
    }).collect();
    let vulnerabilities: Vec<Value> = report.findings.values().map(|finding| {
        let affects: Vec<Value> = finding.component_id.as_ref().map(|id| vec![json!({"ref": id.as_str()})]).unwrap_or_default();
        let analysis = cdx_analysis(finding);
        let advisories: Vec<Value> = finding.evidence.iter().flat_map(|evidence| evidence.references.iter()).map(|url| json!({"url": url})).collect();
        let ratings = vec![json!({"severity": cdx_severity(finding.severity), "method": "other"})];
        let properties = common_properties(index, finding);
        json!({
            "bom-ref": finding.id.as_str(), "id": finding.advisory_id.as_deref().unwrap_or(finding.rule_id.as_str()),
            "source": {"name": "hooray"}, "ratings": ratings,
            "description": finding.details.as_deref().or(finding.summary.as_deref()).unwrap_or(finding.rule_id.as_str()),
            "advisories": advisories, "analysis": analysis, "affects": affects, "properties": properties
        })
    }).collect();
    let dependencies: Vec<Value> = report
        .inventory
        .components
        .keys()
        .map(|id| {
            let depends_on: Vec<&str> = report
                .inventory
                .dependencies
                .iter()
                .filter(|edge| &edge.from == id)
                .map(|edge| edge.to.as_str())
                .collect();
            json!({"ref": id.as_str(), "dependsOn": depends_on})
        })
        .collect();
    pretty_json(
        &json!({
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{}", deterministic_uuid(report.run.id.as_str())), "version": 1,
            "metadata": {"timestamp": report.run.started_at, "tools": {"components": [{"type": "application", "name": "hooray", "version": report.run.scanner_version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION"))}]},
                "component": {"type": "application", "bom-ref": report.inventory.asset.id.as_str(), "name": report.inventory.asset.name, "version": report.inventory.asset.version.as_deref().unwrap_or("unknown")}},
            "components": components, "dependencies": dependencies, "vulnerabilities": vulnerabilities
        }),
        limit,
    )
}

fn render_spdx(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let ids: BTreeMap<_, _> = report
        .inventory
        .components
        .keys()
        .map(|id| (id.clone(), spdx_id(id.as_str())))
        .collect();
    let packages: Vec<Value> = report.inventory.components.values().map(|component| {
        let licenses = component.licenses.iter().filter_map(|license| license.expression.as_deref()).collect::<Vec<_>>();
        json!({
            "SPDXID": ids.get(&component.identity).expect("all component IDs are mapped"), "name": component.name, "versionInfo": component.version,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
            "licenseConcluded": if licenses.is_empty() {"NOASSERTION".to_owned()} else {licenses.join(" AND ")},
            "licenseDeclared": if licenses.is_empty() {"NOASSERTION".to_owned()} else {licenses.join(" AND ")},
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component.purl}],
            "annotations": [{"annotationDate": report.run.started_at, "annotationType": "OTHER", "annotator": "Tool: hooray", "comment": format!("Hooray component stable ID: {}", component.identity)}]
        })
    }).collect();
    let mut relationships: Vec<Value> = report.inventory.dependencies.iter().map(|edge| json!({
        "spdxElementId": ids.get(&edge.from).expect("dependency source is mapped"), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ids.get(&edge.to).expect("dependency target is mapped"),
        "comment": format!("scope={:?}; optional={}", edge.scope, edge.optional)
    })).collect();
    for mapped in ids.values() {
        relationships.push(json!({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": mapped}));
    }
    let annotations: Vec<Value> = report.findings.values().map(|finding| json!({
        "annotationDate": report.run.started_at, "annotationType": "REVIEW", "annotator": "Tool: hooray",
        "comment": serde_json::to_string(&json!({
            "type": "hooray-finding", "schemaVersion": CANONICAL_REPORT_VERSION, "findingId": finding.id.as_str(),
            "ruleId": finding.rule_id.as_str(), "kind": finding.kind.as_str(), "severity": finding.severity.as_str(),
            "componentId": finding.component_id.as_ref().map(|id| id.as_str()), "dependencyPaths": index.paths(finding),
            "summary": finding.summary, "details": finding.details, "applicability": finding.applicability,
            "remediation": finding.remediation, "evidence": finding.evidence, "policyOutcomes": index.policies(&finding.id)
        })).expect("finding annotation contains only serializable report values")
    })).collect();
    pretty_json(
        &json!({
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": format!("hooray-{}", report.run.id),
            "documentNamespace": format!("https://openhoo.github.io/hooray/spdx/{}/{}", url_segment(report.run.id.as_str()), deterministic_uuid(report.run.id.as_str())),
            "creationInfo": {"created": report.run.started_at, "creators": [format!("Tool: hooray-{}", report.run.scanner_version.as_deref().unwrap_or(env!("CARGO_PKG_VERSION")))], "licenseListVersion": "3.25"},
            "documentDescribes": ids.values().collect::<Vec<_>>(),
            "packages": packages, "relationships": relationships, "annotations": annotations
        }),
        limit,
    )
}

fn render_gitlab(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let findings: Vec<Value> = report
        .findings
        .values()
        .filter(|finding| finding.status != FindingStatus::Resolved)
        .filter_map(|finding| {
            let location = gitlab_finding_location(report, index, finding)?;
            Some(gitlab_code_quality_entry(report, index, finding, &location))
        })
        .collect();
    pretty_json(&findings, limit)
}

fn render_json_lines(
    report: &ScanReport,
    limit: usize,
    index: &ReportIndex<'_>,
) -> Result<Vec<u8>, ReportError> {
    let mut output = BoundedWriter::new(limit);
    for finding in report.findings.values() {
        let envelope = JsonLineEnvelope {
            format: "hooray-finding",
            format_version: CANONICAL_REPORT_VERSION,
            report_schema_version: &report.schema_version,
            run_id: report.run.id.as_str(),
            finding,
            dependency_paths: index.paths(finding),
            policy_outcomes: index.policies(&finding.id).to_vec(),
        };
        if let Err(error) = serde_json::to_writer(&mut output, &envelope) {
            if output.exceeded {
                return Err(report_limit(limit));
            }
            return Err(error.into());
        }
        bounded_write_all(&mut output, b"\n")?;
    }
    output.finish()
}

fn pretty_json(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, ReportError> {
    let mut output = BoundedWriter::new(limit);
    let mut serializer = serde_json::Serializer::pretty(&mut output);
    if let Err(error) = value.serialize(&mut serializer) {
        if output.exceeded {
            return Err(report_limit(limit));
        }
        return Err(error.into());
    }
    bounded_write_all(&mut output, b"\n")?;
    output.finish()
}

fn validate_limits(report: &ScanReport) -> Result<(), ReportError> {
    for (label, count) in [
        ("components", report.inventory.components.len()),
        ("dependencies", report.inventory.dependencies.len()),
        ("findings", report.findings.len()),
        ("policy decisions", report.policy_decisions.len()),
    ] {
        if count > MAX_ITEMS {
            return Err(ReportError::Limit(format!(
                "{label} count {count} exceeds {MAX_ITEMS}"
            )));
        }
    }
    check_text("asset name", &report.inventory.asset.name)?;
    check_text("run start", &report.run.started_at)?;
    for component in report.inventory.components.values() {
        check_text("component name", &component.name)?;
        check_text("component version", &component.version)?;
        check_text("component purl", &component.purl)?;
    }
    for finding in report.findings.values() {
        for value in [
            finding.summary.as_deref(),
            finding.details.as_deref(),
            finding.first_seen.as_deref(),
            finding.last_seen.as_deref(),
            finding.modified.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            check_text("finding text", value)?;
        }
        for evidence in &finding.evidence {
            check_text("evidence description", &evidence.description)?;
            for (key, value) in &evidence.properties {
                check_text("evidence property key", key)?;
                check_text("evidence property value", value)?;
            }
        }
    }
    Ok(())
}

fn check_text(label: &str, value: &str) -> Result<(), ReportError> {
    if value.len() > MAX_TEXT_BYTES {
        Err(ReportError::Limit(format!(
            "{label} is {} bytes; maximum is {MAX_TEXT_BYTES}",
            value.len()
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn sanitize_report(report: &ScanReport) -> Result<ScanReport, ReportError> {
    let mut value = serde_json::to_value(report)?;
    redact_sensitive_values(&mut value, None);
    Ok(serde_json::from_value(value)?)
}
pub(crate) fn sanitize_value(value: &mut Value) {
    redact_sensitive_values(value, None);
}

fn redact_sensitive_values(value: &mut Value, key: Option<&str>) {
    if key.is_some_and(is_sensitive_key) {
        *value = Value::String(REDACTED.to_owned());
        return;
    }
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                redact_sensitive_values(child, Some(child_key));
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_sensitive_values(child, None);
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "token",
        "password",
        "credential",
        "authorization",
        "apikey",
        "privatekey",
        "clientsecret",
        "accesskey",
        "sessioncookie",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn sarif_locations(index: &ReportIndex<'_>, finding: &Finding) -> Vec<Value> {
    let mut ids = BTreeSet::new();
    if let Some(id) = &finding.location_id {
        ids.insert(id);
    }
    for evidence in &finding.evidence {
        ids.extend(&evidence.locations);
    }
    ids.into_iter().filter_map(|id| {
        let location = index.locations.get(id)?;
        let mut region = serde_json::Map::new();
        if let Some(start) = location.start {
            region.insert("startLine".into(), json!(start.line.max(1)));
            region.insert("startColumn".into(), json!(start.column.max(1)));
        }
        if let Some(end) = location.end {
            region.insert("endLine".into(), json!(end.line.max(1)));
            region.insert("endColumn".into(), json!(end.column.max(1)));
        }
        let mut physical = json!({"artifactLocation": {"uri": path_uri(&location.path)}});
        if !region.is_empty() {
            physical["region"] = Value::Object(region);
        }
        Some(json!({"physicalLocation": physical, "properties": {"locationId": location.id.as_str()}}))
    }).collect()
}

fn common_properties(index: &ReportIndex<'_>, finding: &Finding) -> Vec<Value> {
    let mut properties = vec![
        json!({"name": "hooray:finding-id", "value": finding.id.as_str()}),
        json!({"name": "hooray:kind", "value": finding.kind.as_str()}),
        json!({"name": "hooray:dependency-paths", "value": serde_json::to_string(&index.paths(finding)).expect("dependency paths are serializable")}),
        json!({"name": "hooray:evidence", "value": serde_json::to_string(&finding.evidence).expect("evidence is serializable")}),
        json!({"name": "hooray:policy-outcomes", "value": serde_json::to_string(index.policies(&finding.id)).expect("policy outcomes are serializable")}),
    ];
    if let Some(remediation) = &finding.remediation {
        properties.push(json!({"name": "hooray:remediation", "value": serde_json::to_string(remediation).expect("remediation is serializable")}));
    }
    properties
}

fn cdx_analysis(finding: &Finding) -> Value {
    let (state, justification) = match finding.applicability.as_ref().map(|item| item.status) {
        Some(ApplicabilityStatus::Affected) => ("exploitable", None),
        Some(ApplicabilityStatus::NotAffected) => ("not_affected", Some("code_not_reachable")),
        Some(ApplicabilityStatus::Fixed) => ("resolved", None),
        Some(ApplicabilityStatus::UnderInvestigation)
        | Some(ApplicabilityStatus::Unknown)
        | None => ("in_triage", None),
    };
    let mut analysis = json!({"state": state, "detail": finding.applicability.as_ref().and_then(|item| item.rationale.as_deref()).unwrap_or("Hooray applicability assessment")});
    if let Some(justification) = justification {
        analysis["justification"] = json!(justification);
    }
    analysis
}

fn finding_detail_text(index: &ReportIndex<'_>, finding: &Finding) -> String {
    let mut lines = vec![
        format!("Finding: {}", finding.id),
        format!("Rule: {}", finding.rule_id),
        format!("Severity: {}", finding.severity),
        format!("Kind: {}", finding.kind.as_str()),
    ];
    if let Some(summary) = &finding.summary {
        lines.push(format!("Summary: {summary}"));
    }
    if let Some(details) = &finding.details {
        lines.push(format!("Details: {details}"));
    }
    if let Some(component) = &finding.component_id {
        lines.push(format!("Component: {component}"));
    }
    for path in index.paths(finding) {
        lines.push(format!("Dependency path: {}", path.join(" -> ")));
    }
    if let Some(remediation) = &finding.remediation {
        lines.push(format!("Remediation: {}", remediation.description));
        if !remediation.fixed_versions.is_empty() {
            lines.push(format!(
                "Fixed versions: {}",
                remediation
                    .fixed_versions
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for evidence in &finding.evidence {
        lines.push(format!(
            "Evidence: {} [redacted={}]",
            evidence.description, evidence.redacted
        ));
        for (key, value) in &evidence.properties {
            lines.push(format!("Evidence {key}: {value}"));
        }
    }
    for decision in index.policies(&finding.id) {
        lines.push(format!(
            "Policy {}: {} — {}",
            decision.policy_id,
            policy_outcome(decision.outcome),
            decision.reason
        ));
    }
    lines.join("\n")
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

fn cdx_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn gitlab_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Unknown => "info",
        Severity::Low => "minor",
        Severity::Medium => "major",
        Severity::High => "critical",
        Severity::Critical => "blocker",
    }
}

fn policy_outcome(outcome: PolicyOutcome) -> &'static str {
    match outcome {
        PolicyOutcome::Allow => "allow",
        PolicyOutcome::Warn => "warn",
        PolicyOutcome::Deny => "deny",
    }
}

fn clean_cell(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ").replace('|', "\\|")
}
fn truncate_cell(value: &str, limit: usize) -> String {
    clean_cell(value).chars().take(limit).collect()
}

fn xml_text(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '\t' | '\n' | '\r' => character.to_string(),
            c if is_valid_xml_char(c) => c.to_string(),
            _ => "�".into(),
        })
        .collect()
}
fn xml_attr(value: &str) -> String {
    xml_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn html_text(value: &str) -> String {
    xml_attr(value)
}

fn is_valid_xml_char(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{a}' | '\u{d}')
        || matches!(character as u32, 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
}

fn path_uri(path: &str) -> String {
    path.bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~') {
                vec![char::from(byte)]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

fn url_segment(value: &str) -> String {
    path_uri(value).replace('/', "%2F")
}

fn spdx_id(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let body: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let digest = Sha256::digest(value.as_bytes());
    let suffix: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("SPDXRef-{body}-{suffix}")
}

fn deterministic_uuid(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "{:08x}-{:04x}-5{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes(digest[0..4].try_into().expect("fixed digest")),
        u16::from_be_bytes(digest[4..6].try_into().expect("fixed digest")),
        u16::from_be_bytes(digest[6..8].try_into().expect("fixed digest")) & 0x0fff,
        (u16::from_be_bytes(digest[8..10].try_into().expect("fixed digest")) & 0x3fff) | 0x8000,
        u64::from_be_bytes([
            0, 0, digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]
        ])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Applicability, Asset, AssetId, AssetKind, Component, ComponentId, Confidence,
        DependencyEdge, Evidence, FindingKind, FindingStatus, Inventory, LocationId, Position,
        Remediation, Risk, RuleId, RunId, RunMetadata, Scope,
    };

    fn fixture() -> ScanReport {
        let asset_id = AssetId::new("asset:<root>").unwrap();
        let root_id = ComponentId::new("component:root").unwrap();
        let component_id = ComponentId::new("component:dep").unwrap();
        let location_id = LocationId::new("location:dep").unwrap();
        let finding_id = FindingId::new("finding:stable-1").unwrap();
        let mut components = BTreeMap::new();
        components.insert(
            root_id.clone(),
            Component {
                identity: root_id.clone(),
                name: "root & app".into(),
                version: "1.0.0".into(),
                purl: "pkg:cargo/root@1.0.0".into(),
                scope: Scope::Runtime,
                provenance: BTreeSet::new(),
                licenses: BTreeSet::new(),
                locations: BTreeSet::new(),
            },
        );
        components.insert(
            component_id.clone(),
            Component {
                identity: component_id.clone(),
                name: "unsafe <dep>".into(),
                version: "1.2.3".into(),
                purl: "pkg:cargo/dep@1.2.3".into(),
                scope: Scope::Runtime,
                provenance: BTreeSet::new(),
                licenses: BTreeSet::new(),
                locations: BTreeSet::from([Location {
                    id: location_id.clone(),
                    asset_id: asset_id.clone(),
                    path: "src/a & b.rs".into(),
                    start: Some(Position { line: 7, column: 3 }),
                    end: Some(Position { line: 7, column: 9 }),
                }]),
            },
        );
        let evidence = Evidence {
            description: "matched <script>alert(1)</script> & token".into(),
            locations: BTreeSet::from([location_id.clone()]),
            references: BTreeSet::from(["https://example.invalid/advisory?a=1&b=2".into()]),
            properties: BTreeMap::from([("masked".into(), "ab***yz".into())]),
            redacted: true,
        };
        let finding = Finding {
            id: finding_id.clone(),
            kind: FindingKind::Vulnerability,
            rule_id: RuleId::new("OSV-<1>").unwrap(),
            advisory_id: Some("CVE-2026-0001".into()),
            component_id: Some(component_id.clone()),
            location_id: Some(location_id),
            aliases: BTreeSet::from(["GHSA-test".into()]),
            summary: Some("unsafe <tag> & issue".into()),
            details: Some("details ]]> <script>alert(1)</script>".into()),
            severity: Severity::High,
            confidence: Confidence::High,
            evidence: BTreeSet::from([evidence]),
            applicability: Some(Applicability {
                status: ApplicabilityStatus::Affected,
                rationale: Some("reachable".into()),
            }),
            remediation: Some(Remediation {
                description: "upgrade & verify".into(),
                fixed_versions: BTreeSet::from(["2.0.0".into()]),
                references: BTreeSet::new(),
            }),
            risk: Some(Risk::new(9000).unwrap()),
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        };
        let decisions = BTreeSet::from([PolicyDecision {
            policy_id: crate::model::PolicyId::new("policy:enterprise").unwrap(),
            finding_id: Some(finding_id.clone()),
            outcome: PolicyOutcome::Deny,
            reason: "high risk <blocked>".into(),
            exception_id: None,
        }]);
        ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new("run:stable").unwrap(),
                started_at: "2026-07-21T12:00:00Z".into(),
                completed_at: Some("2026-07-21T12:00:01Z".into()),
                scanner_version: Some("1.2.3".into()),
                metadata: BTreeMap::from([
                    ("api_token".into(), json!("never-print-me")),
                    ("branch".into(), json!("main")),
                ]),
            },
            inventory: Inventory {
                asset: Asset {
                    id: asset_id,
                    name: "repo <enterprise>".into(),
                    kind: AssetKind::Repository,
                    version: Some("abc123".into()),
                    metadata: BTreeMap::from([("credential".into(), json!("hidden"))]),
                },
                components,
                locations: BTreeSet::new(),
                dependencies: BTreeSet::from([DependencyEdge {
                    from: root_id,
                    to: component_id,
                    scope: Scope::Runtime,
                    optional: false,
                }]),
            },
            findings: BTreeMap::from([(finding_id, finding)]),
            policy_summary: crate::model::PolicySummary::from_decisions(&decisions),
            policy_decisions: decisions,
        }
    }

    #[test]
    fn every_format_is_deterministic_utf8_and_redacts_metadata() {
        let report = fixture();
        for format in ReportFormat::ALL {
            let first = render(&report, format).unwrap();
            let second = render(&report, format).unwrap();
            assert_eq!(first, second, "{format}");
            let text = String::from_utf8(first).unwrap();
            assert!(!text.contains("never-print-me"), "{format}");
            assert!(!text.contains("hidden"), "{format}");
            if format != ReportFormat::Html {
                assert!(text.ends_with('\n'), "{format}");
            }
        }
    }

    #[test]
    fn canonical_json_has_version_and_complete_native_model() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::Json).unwrap()).unwrap();
        assert_eq!(value["format"], "hooray-canonical-report");
        assert_eq!(value["format_version"], CANONICAL_REPORT_VERSION);
        assert_eq!(
            value["report"]["findings"]["finding:stable-1"]["remediation"]["fixed_versions"][0],
            "2.0.0"
        );
        assert_eq!(value["report"]["policy_summary"]["denied"], 1);
        assert_eq!(value["report"]["run"]["metadata"]["api_token"], REDACTED);
    }

    #[test]
    fn yaml_has_document_marker_version_and_redaction() {
        let text = render_to_string(&fixture(), ReportFormat::Yaml).unwrap();
        assert!(text.starts_with("---\nformat: hooray-canonical-report\nformat_version: 1.0.0\n"));
        assert!(text.contains("api_token: '[REDACTED]'"));
        let value: Value = serde_yaml::from_str(&text).unwrap();
        assert_eq!(
            value["report"]["findings"]["finding:stable-1"]["id"],
            "finding:stable-1"
        );
    }

    #[test]
    fn table_is_stable_and_flattens_hostile_cells() {
        let text = render_to_string(&fixture(), ReportFormat::Table).unwrap();
        assert!(text.contains("HOORAY REPORT v1.0.0"));
        assert!(text.contains("component:root -> component:dep"));
        assert!(text.contains("remediation: upgrade & verify [fixed: 2.0.0]"));
        assert!(text.contains("policy: policy:enterprise=deny"));
    }

    #[test]
    fn sarif_21_has_rules_results_locations_and_properties() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::Sarif).unwrap()).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "OSV-<1>"
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert_eq!(
            value["runs"][0]["results"][0]["fingerprints"]["hoorayFindingId/v1"],
            "finding:stable-1"
        );
        assert_eq!(
            value["runs"][0]["results"][0]["properties"]["policyOutcomes"][0]["outcome"],
            "deny"
        );
    }

    #[test]
    fn junit_is_well_formed_by_construction_and_escapes_payloads() {
        let text = render_to_string(&fixture(), ReportFormat::Junit).unwrap();
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(text.contains("name=\"finding:stable-1\""));
        assert!(text.contains("unsafe &lt;tag&gt; &amp; issue"));
        assert!(!text.contains("<script>"));
        assert_eq!(
            text.matches("<testcase ").count(),
            text.matches("</testcase>").count()
        );
    }

    #[test]
    fn html_is_self_contained_csp_hardened_and_escaped() {
        let text = render_to_string(&fixture(), ReportFormat::Html).unwrap();
        assert!(text.starts_with("<!doctype html>"));
        assert!(text.contains("default-src 'none'"));
        assert!(!text.contains("<script>alert(1)</script>"));
        assert!(text.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!text.contains("src=\"http"));
    }

    #[test]
    fn cyclonedx_16_vex_has_valid_analysis_and_graph() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::CycloneDxVex).unwrap())
                .unwrap();
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.6");
        assert_eq!(
            value["vulnerabilities"][0]["analysis"]["state"],
            "exploitable"
        );
        assert_eq!(
            value["vulnerabilities"][0]["affects"][0]["ref"],
            "component:dep"
        );
        assert_eq!(value["dependencies"][0]["ref"], "component:dep");
        assert!(
            value["vulnerabilities"][0]["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["name"] == "hooray:remediation")
        );
    }

    #[test]
    fn vex_maps_all_applicability_states_to_cyclonedx_states() {
        let cases = [
            (ApplicabilityStatus::Affected, "exploitable"),
            (ApplicabilityStatus::NotAffected, "not_affected"),
            (ApplicabilityStatus::Fixed, "resolved"),
            (ApplicabilityStatus::UnderInvestigation, "in_triage"),
            (ApplicabilityStatus::Unknown, "in_triage"),
        ];
        for (status, expected) in cases {
            let mut report = fixture();
            report
                .findings
                .values_mut()
                .next()
                .unwrap()
                .applicability
                .as_mut()
                .unwrap()
                .status = status;
            let value: Value =
                serde_json::from_slice(&render(&report, ReportFormat::CycloneDxVex).unwrap())
                    .unwrap();
            assert_eq!(value["vulnerabilities"][0]["analysis"]["state"], expected);
        }
    }

    #[test]
    fn spdx_23_has_packages_relationships_and_structured_finding_annotations() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::Spdx).unwrap()).unwrap();
        assert_eq!(value["spdxVersion"], "SPDX-2.3");
        assert_eq!(value["dataLicense"], "CC0-1.0");
        assert_eq!(value["packages"].as_array().unwrap().len(), 2);
        assert!(
            value["relationships"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["relationshipType"] == "DEPENDS_ON")
        );
        let finding: Value =
            serde_json::from_str(value["annotations"][0]["comment"].as_str().unwrap()).unwrap();
        assert_eq!(finding["findingId"], "finding:stable-1");
        assert_eq!(finding["policyOutcomes"][0]["outcome"], "deny");
    }

    #[test]
    fn spdx_ids_are_distinct_valid_and_reused_by_relationships() {
        let mut report = fixture();
        let first = ComponentId::new("component:a/b").unwrap();
        let second = ComponentId::new("component:a?b").unwrap();
        let mut template = report.inventory.components.values().next().unwrap().clone();
        template.locations.clear();
        report.inventory.components.clear();
        report.inventory.components.insert(
            first.clone(),
            Component {
                identity: first.clone(),
                name: "first".into(),
                purl: "pkg:cargo/first@1".into(),
                ..template.clone()
            },
        );
        report.inventory.components.insert(
            second.clone(),
            Component {
                identity: second.clone(),
                name: "second".into(),
                purl: "pkg:cargo/second@1".into(),
                ..template
            },
        );
        report.inventory.dependencies = BTreeSet::from([DependencyEdge {
            from: first,
            to: second,
            scope: Scope::Runtime,
            optional: false,
        }]);
        report.findings.clear();
        report.policy_decisions.clear();
        report.policy_summary = crate::model::PolicySummary::default();

        let value: Value =
            serde_json::from_slice(&render(&report, ReportFormat::Spdx).unwrap()).unwrap();
        let package_ids: BTreeSet<_> = value["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| package["SPDXID"].as_str().unwrap())
            .collect();
        assert_eq!(package_ids.len(), 2);
        assert!(package_ids.iter().all(|id| id.starts_with("SPDXRef-")
            && id[8..].chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
            )));
        let dependency = value["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["relationshipType"] == "DEPENDS_ON")
            .unwrap();
        assert!(package_ids.contains(dependency["spdxElementId"].as_str().unwrap()));
        assert!(package_ids.contains(dependency["relatedSpdxElement"].as_str().unwrap()));
        assert_eq!(
            value["documentDescribes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            package_ids
        );
    }

    #[test]
    fn gitlab_code_quality_has_expected_shape_and_valid_location() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::GitLabCodeQuality).unwrap())
                .unwrap();
        assert_eq!(value[0]["check_name"], "OSV-<1>");
        assert_eq!(value[0]["fingerprint"], "finding:stable-1");
        assert_eq!(value[0]["severity"], "critical");
        assert_eq!(value[0]["location"]["lines"]["begin"], 7);
        assert_eq!(
            value[0]["hooray"]["dependency_paths"][0][1],
            "component:dep"
        );
    }

    #[test]
    fn json_lines_is_one_canonical_object_per_finding() {
        let text = render_to_string(&fixture(), ReportFormat::JsonLines).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(value["format"], "hooray-finding");
        assert_eq!(value["finding"]["id"], "finding:stable-1");
        assert_eq!(
            value["dependency_paths"][0],
            json!(["component:root", "component:dep"])
        );
        assert_eq!(value["policy_outcomes"][0]["outcome"], "deny");
    }

    #[test]
    fn format_parsing_extensions_and_media_types_cover_every_renderer() {
        for format in ReportFormat::ALL {
            assert_eq!(ReportFormat::from_str(format.as_str()).unwrap(), format);
            assert!(!format.extension().is_empty());
            assert!(!format.media_type().is_empty());
        }
        assert_eq!(
            ReportFormat::from_str("ndjson").unwrap(),
            ReportFormat::JsonLines
        );
        assert!(ReportFormat::from_str("legacy").is_err());
    }

    #[test]
    fn oversized_untrusted_text_is_rejected_before_rendering() {
        let mut report = fixture();
        report.findings.values_mut().next().unwrap().details = Some("x".repeat(MAX_TEXT_BYTES + 1));
        assert!(matches!(
            render(&report, ReportFormat::Json),
            Err(ReportError::Limit(_))
        ));
    }

    #[test]
    fn structured_and_textual_renderers_abort_at_output_bound() {
        let report = fixture();
        for format in [
            ReportFormat::Json,
            ReportFormat::Yaml,
            ReportFormat::JsonLines,
            ReportFormat::Table,
            ReportFormat::Junit,
            ReportFormat::Html,
        ] {
            assert!(
                matches!(
                    render_with_limit(&report, format, 64),
                    Err(ReportError::Limit(_))
                ),
                "{format}"
            );
        }
    }

    #[test]
    fn gitlab_paths_locations_and_code_quality_are_truthful() {
        for invalid in [
            "",
            ".",
            "../secret",
            "/etc/passwd",
            "C:\\repo\\file.rs",
            "//server/share/file.rs",
            "\\\\server\\share\\file.rs",
            "bom-ref:x",
            "purl:x",
            "sha256:abc",
        ] {
            assert_eq!(gitlab_repository_path(invalid), None, "{invalid}");
        }
        assert_eq!(
            gitlab_repository_path("./src/main.rs"),
            Some("src/main.rs".into())
        );
        assert_eq!(
            gitlab_repository_path(" report.txt "),
            Some(" report.txt ".into())
        );
        let mut report = fixture();
        let locations = report
            .inventory
            .components
            .values()
            .flat_map(|component| component.locations.iter().cloned())
            .collect();
        report.inventory.locations = locations;
        for component in report.inventory.components.values_mut() {
            component.locations.clear();
        }
        let index = ReportIndex::new(&report);
        let finding = report.findings.values().next().unwrap();
        assert_eq!(
            gitlab_finding_location(&report, &index, finding)
                .unwrap()
                .path,
            "src/a & b.rs"
        );
        report.findings.values_mut().next().unwrap().status = FindingStatus::Resolved;
        let value: Value =
            serde_json::from_slice(&render(&report, ReportFormat::GitLabCodeQuality).unwrap())
                .unwrap();
        assert_eq!(value, json!([]));
    }

    #[test]
    fn gitlab_sarif_has_gitlab_identity_rank_counts_and_location() {
        let value: Value =
            serde_json::from_slice(&render(&fixture(), ReportFormat::GitLabSarif).unwrap())
                .unwrap();
        let run = &value["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "Hooray");
        assert_eq!(run["tool"]["driver"]["organization"], "OpenHoo");
        assert_eq!(run["results"][0]["ruleId"], "CVE-2026-0001");
        assert_eq!(run["results"][0]["rank"], 90.0);
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/a & b.rs"
        );
        assert_eq!(run["properties"]["includedFindings"], 1);
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
    }

    struct CycloneDxSchemaRetriever;

    impl jsonschema::Retrieve for CycloneDxSchemaRetriever {
        fn retrieve(
            &self,
            uri: &jsonschema::Uri<String>,
        ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
            let content = match uri.as_str() {
                "http://cyclonedx.org/schema/spdx.schema.json"
                | "https://cyclonedx.org/schema/spdx.schema.json" => {
                    include_str!("../tests/fixtures/cyclonedx-1.6/spdx.schema.json")
                }
                "http://cyclonedx.org/schema/jsf-0.82.schema.json"
                | "https://cyclonedx.org/schema/jsf-0.82.schema.json" => {
                    include_str!("../tests/fixtures/cyclonedx-1.6/jsf-0.82.schema.json")
                }
                _ => return Err(format!("offline schema not found: {uri}").into()),
            };
            Ok(serde_json::from_str(content)?)
        }
    }

    #[test]
    fn gitlab_cyclonedx_has_inventory_gitlab_metadata_and_input_file() {
        let mut report = fixture();
        let component = report
            .inventory
            .components
            .get_mut(&ComponentId::new("component:dep").unwrap())
            .unwrap();
        component.provenance.insert(crate::model::Source {
            kind: SourceKind::Lockfile,
            locator: "./Cargo.lock".into(),
            digest: None,
        });
        component.licenses.insert(crate::model::License {
            expression: Some("MIT".into()),
            name: None,
            url: None,
        });
        let bytes = render(&report, ReportFormat::GitLabCycloneDx).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["metadata"]["properties"][0]["name"],
            "gitlab:meta:schema_version"
        );
        assert!(value.get("vulnerabilities").is_none());
        let dep = value["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["bom-ref"] == "component:dep")
            .unwrap();
        assert!(
            dep["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |item| item["name"] == "gitlab:dependency_scanning:input_file:path"
                        && item["value"] == "Cargo.lock"
                )
        );
        assert_eq!(dep["licenses"][0]["expression"], "MIT");
        let schema: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/cyclonedx-1.6/bom-1.6.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .with_retriever(CycloneDxSchemaRetriever)
            .build(&schema)
            .unwrap();
        assert!(
            validator.is_valid(&value),
            "{:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn gitlab_cyclonedx_does_not_render_license_refs_as_spdx_ids() {
        let mut report = fixture();
        let component = report.inventory.components.values_mut().next().unwrap();
        component.licenses.insert(crate::model::License {
            expression: Some("LicenseRef-Proprietary".into()),
            name: Some("Proprietary".into()),
            url: None,
        });
        let component_id = component.identity.clone();
        let value: Value =
            serde_json::from_slice(&render(&report, ReportFormat::GitLabCycloneDx).unwrap())
                .unwrap();
        let rendered = value["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["bom-ref"] == component_id.as_str())
            .unwrap();
        assert_eq!(rendered["licenses"][0]["license"]["name"], "Proprietary");
        assert!(rendered["licenses"][0]["license"].get("id").is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn gitlab_artifact_bundle_is_complete_private_and_no_clobber() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("bundle");
        assert!(matches!(
            write_gitlab_artifacts("", &fixture()),
            Err(ReportError::InvalidDestination { .. })
        ));
        write_gitlab_artifacts(&destination, &fixture()).unwrap();
        let names: BTreeSet<_> = fs::read_dir(&destination)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            BTreeSet::from([
                "gl-code-quality-report.json".into(),
                "gl-sarif-report.sarif".into(),
                "gl-sbom-hooray.cdx.json".into(),
                "gl-junit-report.xml".into(),
                "hooray.env".into()
            ])
        );
        for name in &names {
            assert_eq!(
                fs::metadata(destination.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::read_to_string(destination.join("hooray.env")).unwrap(),
            "HOORAY_POLICY_DENIED=true\nHOORAY_POLICY_DENIED_COUNT=1\n"
        );
        assert!(matches!(
            write_gitlab_artifacts(&destination, &fixture()),
            Err(ReportError::DestinationExists(_))
        ));
        assert!(directory.path().read_dir().unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".hooray-gitlab-")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_replaces_target_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, &fixture(), ReportFormat::Json).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["format_version"], CANONICAL_REPORT_VERSION);
        assert!(directory.path().read_dir().unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
}
