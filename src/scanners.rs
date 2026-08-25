use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::WalkDir;
use zip::ZipArchive;

use crate::model::{
    Applicability, ApplicabilityStatus, AssetId, Confidence, Evidence, Finding, FindingKind,
    FindingStatus, Location, Position, Remediation, Risk, RuleId, Severity, stable_finding_id,
    stable_location_id,
};

const SECRET_ALLOWLIST_MARKERS: &[&str] = &[
    "hooray:allow-secret",
    "pragma: allowlist secret",
    "gitleaks:allow",
    "nosec",
];
const MAX_TEXT_LINE_BYTES: usize = 64 * 1024;
const ARCHIVE_RATIO_LIMIT: u64 = 100;
const ARCHIVE_ENTRY_SIZE_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScannerConfig {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub secret_entropy_threshold_milli: u16,
    pub max_archive_entries: usize,
    pub max_archive_uncompressed_bytes: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_files: 100_000,
            max_depth: 64,
            follow_symlinks: false,
            secret_entropy_threshold_milli: 3_500,
            max_archive_entries: 100_000,
            max_archive_uncompressed_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MalwareSignatures {
    /// Lowercase SHA-256 hex digest to a non-secret signature name.
    pub sha256: BTreeMap<String, String>,
}

impl MalwareSignatures {
    pub fn validate(&self) -> Result<(), ScanError> {
        for (digest, name) in &self.sha256 {
            if digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                || digest.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(ScanError::InvalidSignatureDigest(digest.clone()));
            }
            if name.trim().is_empty() {
                return Err(ScanError::InvalidSignatureName(digest.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanOutput {
    pub locations: BTreeSet<Location>,
    pub findings: Vec<Finding>,
    pub scanned_files: usize,
    pub scanned_bytes: u64,
    pub skipped_files: usize,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("cannot inspect '{path}': {source}")]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot read '{path}': {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("filesystem traversal failed at '{path}': {source}")]
    Walk {
        path: PathBuf,
        source: walkdir::Error,
    },
    #[error("scan root '{0}' is neither a regular file nor a directory")]
    UnsupportedRoot(PathBuf),
    #[error("malware signature digest is not canonical lowercase SHA-256: {0}")]
    InvalidSignatureDigest(String),
    #[error("malware signature name is empty for digest {0}")]
    InvalidSignatureName(String),
    #[error("scanner bound '{0}' must be greater than zero")]
    InvalidBound(&'static str),
}

pub fn scan_path(
    root: &Path,
    asset_id: &AssetId,
    config: &ScannerConfig,
    signatures: &MalwareSignatures,
) -> Result<ScanOutput, ScanError> {
    validate_config(config)?;
    signatures.validate()?;
    let metadata = fs::symlink_metadata(root).map_err(|source| ScanError::Metadata {
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() && !config.follow_symlinks {
        return Ok(ScanOutput {
            skipped_files: 1,
            ..ScanOutput::default()
        });
    }

    let mut paths = Vec::new();
    if metadata.is_file() || (metadata.file_type().is_symlink() && config.follow_symlinks) {
        paths.push(root.to_owned());
    } else if metadata.is_dir() {
        for entry in WalkDir::new(root)
            .follow_links(config.follow_symlinks)
            .max_depth(config.max_depth)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|source| ScanError::Walk {
                path: source.path().unwrap_or(root).to_owned(),
                source,
            })?;
            if entry.file_type().is_file() {
                paths.push(entry.into_path());
                if paths.len() > config.max_files {
                    break;
                }
            }
        }
    } else {
        return Err(ScanError::UnsupportedRoot(root.to_owned()));
    }
    paths.sort();

    let mut output = ScanOutput::default();
    let mut admitted = Vec::new();
    let mut admitted_bytes = 0_u64;
    for path in paths {
        if output.scanned_files >= config.max_files {
            output.skipped_files += 1;
            continue;
        }
        let remaining = config.max_total_bytes.saturating_sub(output.scanned_bytes);
        let limit = config.max_file_bytes.min(remaining);
        if limit == 0 {
            output.skipped_files += 1;
            continue;
        }
        let Some(bytes) = read_path_bounded(&path, limit, config.follow_symlinks)? else {
            output.skipped_files += 1;
            continue;
        };
        let display_path = path
            .strip_prefix(root)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or_else(|| path.file_name().map(Path::new).unwrap_or(&path))
            .to_string_lossy()
            .replace('\\', "/");
        output.scanned_files += 1;
        output.scanned_bytes += bytes.len() as u64;
        admitted_bytes += bytes.len() as u64;
        admitted.push((display_path, bytes));
        if admitted.len() >= 32 || admitted_bytes >= 16 * 1024 * 1024 {
            analyze_admitted(&mut admitted, &mut output, asset_id, config, signatures);
            admitted_bytes = 0;
        }
    }
    analyze_admitted(&mut admitted, &mut output, asset_id, config, signatures);
    output
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(output)
}

fn analyze_admitted(
    admitted: &mut Vec<(String, Vec<u8>)>,
    output: &mut ScanOutput,
    asset_id: &AssetId,
    config: &ScannerConfig,
    signatures: &MalwareSignatures,
) {
    if admitted.is_empty() {
        return;
    }
    let batch = std::mem::take(admitted);
    let analyzed: Vec<_> = if batch.len() >= 32 {
        batch
            .par_iter()
            .map(|(path, bytes)| analyze_bytes(path, bytes, asset_id, config, signatures))
            .collect()
    } else {
        batch
            .iter()
            .map(|(path, bytes)| analyze_bytes(path, bytes, asset_id, config, signatures))
            .collect()
    };
    for mut file_output in analyzed {
        output.locations.append(&mut file_output.locations);
        output.findings.append(&mut file_output.findings);
    }
}
fn read_path_bounded(
    path: &Path,
    limit: u64,
    follow_symlinks: bool,
) -> Result<Option<Vec<u8>>, ScanError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !follow_symlinks {
        use std::os::unix::fs::OpenOptionsExt as _;
        const O_NOFOLLOW: i32 = 0x20_000;
        options.custom_flags(O_NOFOLLOW);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    if !follow_symlinks
        && fs::symlink_metadata(path)
            .map_err(|source| ScanError::Metadata {
                path: path.to_owned(),
                source,
            })?
            .file_type()
            .is_symlink()
    {
        return Ok(None);
    }

    let file = match options.open(path) {
        Ok(file) => file,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Err(source) if !follow_symlinks && source.raw_os_error() == Some(40) => return Ok(None),
        Err(source) => {
            return Err(ScanError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    read_file_bounded(file, path, limit)
}

fn read_file_bounded(file: File, path: &Path, limit: u64) -> Result<Option<Vec<u8>>, ScanError> {
    let metadata = file.metadata().map_err(|source| ScanError::Metadata {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Ok(None);
    }
    let capacity = usize::try_from(metadata.len().min(limit)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ScanError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Ok(None);
    }
    Ok(Some(bytes))
}

pub fn analyze_bytes(
    path: &str,
    bytes: &[u8],
    asset_id: &AssetId,
    config: &ScannerConfig,
    signatures: &MalwareSignatures,
) -> ScanOutput {
    let mut builder = FindingBuilder::new(path, asset_id);
    scan_malware(bytes, config, signatures, &mut builder);
    if let Some(text) = decode_text(bytes) {
        scan_secrets(text, config, &mut builder);
        scan_iac(path, text, &mut builder);
        scan_service_config(path, text, &mut builder);
        scan_sast(path, text, &mut builder);
    }
    builder.finish(bytes.len() as u64)
}

fn validate_config(config: &ScannerConfig) -> Result<(), ScanError> {
    for (name, value) in [
        ("max_file_bytes", config.max_file_bytes),
        ("max_total_bytes", config.max_total_bytes),
        ("max_files", config.max_files as u64),
        ("max_depth", config.max_depth as u64),
        ("max_archive_entries", config.max_archive_entries as u64),
        (
            "max_archive_uncompressed_bytes",
            config.max_archive_uncompressed_bytes,
        ),
    ] {
        if value == 0 {
            return Err(ScanError::InvalidBound(name));
        }
    }
    Ok(())
}

struct FindingSpec<'a> {
    kind: FindingKind,
    rule: &'a str,
    line: u32,
    column: u32,
    summary: &'a str,
    details: &'a str,
    severity: Severity,
    confidence: Confidence,
    description: String,
    references: &'a [&'a str],
    properties: BTreeMap<String, String>,
    redacted: bool,
    remediation: &'a str,
    cwe: Option<&'a str>,
}

struct FindingBuilder<'a> {
    path: &'a str,
    asset_id: &'a AssetId,
    locations: BTreeSet<Location>,
    findings: Vec<Finding>,
}

impl<'a> FindingBuilder<'a> {
    fn new(path: &'a str, asset_id: &'a AssetId) -> Self {
        Self {
            path,
            asset_id,
            locations: BTreeSet::new(),
            findings: Vec::new(),
        }
    }

    fn add(&mut self, spec: FindingSpec<'_>) {
        let FindingSpec {
            kind,
            rule,
            line,
            column,
            summary,
            details,
            severity,
            confidence,
            description,
            references,
            properties,
            redacted,
            remediation,
            cwe,
        } = spec;
        let start = Position { line, column };
        let location_id = stable_location_id(self.asset_id, self.path, Some(start))
            .expect("scanner paths are non-empty");
        self.locations.insert(Location {
            id: location_id.clone(),
            asset_id: self.asset_id.clone(),
            path: self.path.to_owned(),
            start: Some(start),
            end: None,
        });
        let rule_id = RuleId::new(rule).expect("rule IDs are constants");
        let mut evidence_references = references
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        if let Some(cwe) = cwe {
            evidence_references.insert(format!(
                "https://cwe.mitre.org/data/definitions/{}.html",
                cwe.trim_start_matches("CWE-")
            ));
        }
        let evidence = Evidence {
            description,
            locations: BTreeSet::from([location_id.clone()]),
            references: evidence_references,
            properties,
            redacted,
        };
        let risk_score = match severity {
            Severity::Critical => 9_500,
            Severity::High => 8_000,
            Severity::Medium => 5_500,
            Severity::Low => 2_500,
            Severity::Unknown => 0,
        };
        self.findings.push(Finding {
            id: stable_finding_id(kind, &rule_id, None, Some(&location_id)),
            kind,
            rule_id,
            advisory_id: None,
            component_id: None,
            location_id: Some(location_id),
            aliases: cwe.into_iter().map(str::to_owned).collect(),
            summary: Some(summary.to_owned()),
            details: Some(details.to_owned()),
            severity,
            confidence,
            evidence: BTreeSet::from([evidence]),
            applicability: Some(Applicability {
                status: ApplicabilityStatus::Affected,
                rationale: Some(
                    "Concrete local source or file evidence matched this rule.".to_owned(),
                ),
            }),
            remediation: Some(Remediation {
                description: remediation.to_owned(),
                fixed_versions: BTreeSet::new(),
                references: BTreeSet::new(),
            }),
            risk: Some(Risk::new(risk_score).expect("constant risk score is bounded")),
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        });
    }

    fn finish(mut self, bytes: u64) -> ScanOutput {
        self.findings.sort_by(|left, right| left.id.cmp(&right.id));
        ScanOutput {
            locations: self.locations,
            findings: self.findings,
            scanned_files: 1,
            scanned_bytes: bytes,
            skipped_files: 0,
        }
    }
}

fn decode_text(bytes: &[u8]) -> Option<&str> {
    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

struct SecretRule {
    rule: &'static str,
    regex: Regex,
    label: &'static str,
    severity: Severity,
}

static SECRET_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    [
        (
            "secret.aws-access-key",
            r"\bAKIA[0-9A-Z]{16}\b",
            "AWS access key ID",
            Severity::High,
        ),
        (
            "secret.github-token",
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            "GitHub token",
            Severity::Critical,
        ),
        (
            "secret.gitlab-token",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
            "GitLab personal access token",
            Severity::Critical,
        ),
        (
            "secret.slack-token",
            r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
            "Slack token",
            Severity::Critical,
        ),
        (
            "secret.private-key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            "private key",
            Severity::Critical,
        ),
        (
            "secret.jwt",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "JSON Web Token",
            Severity::High,
        ),
    ]
    .into_iter()
    .map(|(rule, expression, label, severity)| SecretRule {
        rule,
        regex: Regex::new(expression).expect("constant secret regex"),
        label,
        severity,
    })
    .collect()
});

static SECRET_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*["']([^"']{12,256})["']"#)
        .expect("constant assignment regex")
});

fn scan_secrets(text: &str, config: &ScannerConfig, builder: &mut FindingBuilder<'_>) {
    for (line_index, line) in text.lines().enumerate() {
        if line.len() > MAX_TEXT_LINE_BYTES || allowlisted(line) {
            continue;
        }
        for secret_rule in SECRET_RULES.iter() {
            for matched in secret_rule.regex.find_iter(line) {
                add_secret(
                    builder,
                    secret_rule.rule,
                    secret_rule.label,
                    secret_rule.severity,
                    line_index,
                    matched.start(),
                    matched.as_str(),
                );
            }
        }
        for captures in SECRET_ASSIGNMENT_REGEX.captures_iter(line) {
            let value = captures.get(2).expect("capture exists");
            if looks_placeholder(value.as_str())
                || shannon_entropy(value.as_str()) * 1000.0
                    < f64::from(config.secret_entropy_threshold_milli)
            {
                continue;
            }
            add_secret(
                builder,
                "secret.high-entropy-assignment",
                "high-entropy credential assignment",
                Severity::High,
                line_index,
                value.start(),
                value.as_str(),
            );
        }
    }
}

fn add_secret(
    builder: &mut FindingBuilder<'_>,
    rule: &str,
    label: &str,
    severity: Severity,
    line: usize,
    column: usize,
    value: &str,
) {
    let entropy_milli = (shannon_entropy(value) * 1000.0).round() as u64;
    let mut properties = BTreeMap::new();
    properties.insert(
        "fingerprint_sha256".to_owned(),
        hex_sha256(value.as_bytes()),
    );
    properties.insert("pattern".to_owned(), rule.to_owned());
    properties.insert("length_bytes".to_owned(), value.len().to_string());
    properties.insert("entropy_milli".to_owned(), entropy_milli.to_string());
    builder.add(FindingSpec {
        kind: FindingKind::Secret,
        rule,
        line: line as u32 + 1,
        column: column as u32 + 1,
        summary: &format!("Potential {label} exposed"),
        details: "A credential-shaped value was found. The value is never retained; evidence contains only non-reversible correlation and classification metadata.",
        severity,
        confidence: Confidence::High,
        description: format!("Redacted {label}; safe metadata recorded for correlation and triage."),
        references: &["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        properties,
        redacted: true,
        remediation: "Revoke and rotate the credential, remove it from source and history, and load its replacement from an approved secret manager.",
        cwe: Some("CWE-798"),
    });
}

fn allowlisted(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    SECRET_ALLOWLIST_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn looks_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "example",
        "sample",
        "placeholder",
        "changeme",
        "replace_me",
        "dummy",
        "not-a-real",
        "your_",
        "<",
        "${",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || value.chars().collect::<BTreeSet<_>>().len() < 5
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0_u32; 256];
    for byte in value.bytes() {
        counts[byte as usize] += 1;
    }
    let length = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .fold(0.0, |entropy, count| {
            let probability = f64::from(count) / length;
            entropy - probability * probability.log2()
        })
}

fn scan_iac(path: &str, text: &str, builder: &mut FindingBuilder<'_>) {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if extension == "tf" {
        scan_terraform(text, builder);
    }
    if name == "dockerfile" || name.starts_with("dockerfile.") {
        scan_dockerfile(text, builder);
    }
    if matches!(extension.as_str(), "yaml" | "yml" | "json") {
        scan_structured_iac(text, &extension, builder);
    }
}

static TERRAFORM_PUBLIC_CIDR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^\s*(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*["'](?:0\.0\.0\.0/0|::/0)["']"#,
    )
    .expect("constant Terraform public CIDR regex")
});

static TERRAFORM_UNENCRYPTED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(encrypted|storage_encrypted)\s*=\s*false\b")
        .expect("constant Terraform encryption regex")
});

fn scan_terraform(text: &str, builder: &mut FindingBuilder<'_>) {
    for matched in TERRAFORM_PUBLIC_CIDR_REGEX.find_iter(text) {
        let (line, column) = line_column(text, matched.start());
        builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.terraform.public-ingress", line, column, summary: "Unrestricted Terraform network CIDR", details: "A Terraform network rule explicitly permits the entire IPv4 or IPv6 Internet.", severity: Severity::High, confidence: Confidence::High, description: "Concrete cidr_blocks assignment contains 0.0.0.0/0 or ::/0.".to_owned(), references: &["https://developer.hashicorp.com/terraform/language"], properties: BTreeMap::new(), redacted: false, remediation: "Restrict ingress to the smallest required CIDR ranges and ports.", cwe: Some("CWE-284") });
    }
    for matched in TERRAFORM_UNENCRYPTED_REGEX.find_iter(text) {
        let (line, column) = line_column(text, matched.start());
        builder.add(FindingSpec {
            kind: FindingKind::Iac,
            rule: "iac.terraform.encryption-disabled",
            line,
            column,
            summary: "Terraform storage encryption disabled",
            details: "A concrete Terraform encryption property is set to false.",
            severity: Severity::High,
            confidence: Confidence::High,
            description: matched.as_str().trim().to_owned(),
            references: &["https://developer.hashicorp.com/terraform/language"],
            properties: BTreeMap::new(),
            redacted: false,
            remediation: "Enable provider-managed or customer-managed encryption for data at rest.",
            cwe: Some("CWE-311"),
        });
    }
}

static DOCKER_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z_][a-z0-9_-]*)\s*=\s*(\"[^\"]+\"|'[^']+'|[^\s]+)"#)
        .expect("constant Docker assignment regex")
});

fn docker_declares_secret(instruction: &str, upper: &str) -> bool {
    let Some(arguments) = instruction
        .split_once(char::is_whitespace)
        .map(|(_, value)| value.trim())
    else {
        return false;
    };
    if DOCKER_ASSIGNMENT_REGEX
        .captures_iter(arguments)
        .any(|captures| {
            captures
                .get(1)
                .is_some_and(|name| secret_variable_name(name.as_str()))
        })
    {
        return true;
    }
    if upper.starts_with("ENV ") {
        let mut fields = arguments.splitn(2, char::is_whitespace);
        return fields.next().is_some_and(secret_variable_name)
            && fields.next().is_some_and(|value| !value.trim().is_empty());
    }
    false
}

fn secret_variable_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "password" | "passwd" | "token" | "secret" | "apikey" | "api_key"
    ) || normalized.ends_with("_password")
        || normalized.ends_with("_passwd")
        || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_secret_key")
        || normalized.ends_with("_api_key")
        || normalized.ends_with("_access_key")
}

fn scan_dockerfile(text: &str, builder: &mut FindingBuilder<'_>) {
    let mut final_stage_line = 1;
    let mut final_user: Option<(u32, String)> = None;
    for (index, line) in docker_logical_lines(text) {
        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("FROM ") {
            final_stage_line = index;
            final_user = None;
        } else if upper.starts_with("USER ") {
            final_user = Some((index, trimmed[5..].trim().to_owned()));
        }
        if upper.starts_with("ADD ")
            && (trimmed.contains("http://") || trimmed.contains("https://"))
        {
            builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.dockerfile.remote-add", line: index, column: 1, summary: "Dockerfile ADD fetches a remote URL", details: "Remote ADD makes provenance and cache behavior harder to control.", severity: Severity::Medium, confidence: Confidence::High, description: trimmed.to_owned(), references: &["https://docs.docker.com/reference/dockerfile/#add"], properties: BTreeMap::new(), redacted: false, remediation: "Fetch with a pinned, checksum-verified build step, then COPY the verified artifact.", cwe: Some("CWE-494") });
        }
        if (upper.starts_with("ENV ") || upper.starts_with("ARG "))
            && docker_declares_secret(trimmed, &upper)
        {
            builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.dockerfile.secret-in-build-arg", line: index, column: 1, summary: "Docker build instruction declares a secret", details: "ENV and ARG values can persist in image configuration or build history.", severity: Severity::High, confidence: Confidence::High, description: "Secret-like variable name in ENV/ARG; value omitted.".to_owned(), references: &["https://docs.docker.com/build/building/secrets/"], properties: BTreeMap::new(), redacted: true, remediation: "Use BuildKit secret mounts and ensure credentials never enter image layers or metadata.", cwe: Some("CWE-522") });
        }
    }
    let final_user_is_root = final_user
        .as_ref()
        .is_none_or(|(_, user)| docker_user_is_root(user));
    if final_user_is_root {
        let line = final_user
            .as_ref()
            .map_or(final_stage_line, |(line, _)| *line);
        builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.dockerfile.root-user", line, column: 1, summary: "Container final stage runs as root", details: "The final Dockerfile stage does not select a concrete non-root user.", severity: Severity::Medium, confidence: Confidence::Medium, description: "Final stage has no non-root USER instruction.".to_owned(), references: &["https://docs.docker.com/reference/dockerfile/#user"], properties: BTreeMap::new(), redacted: false, remediation: "Create an unprivileged account and set USER to its numeric UID in the final stage.", cwe: Some("CWE-250") });
    }
}

fn docker_user_is_root(user: &str) -> bool {
    let user = user.split(':').next().unwrap_or(user).trim();
    user.eq_ignore_ascii_case("root") || user == "0"
}

fn docker_logical_lines(text: &str) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut start = 1;
    for (index, line) in text.lines().enumerate() {
        if current.is_empty() {
            start = index as u32 + 1;
        }
        current.push_str(line.trim_end_matches('\\'));
        if line.trim_end().ends_with('\\') {
            current.push(' ');
        } else {
            result.push((start, std::mem::take(&mut current)));
        }
    }
    if !current.is_empty() {
        result.push((start, current));
    }
    result
}

fn scan_structured_iac(text: &str, extension: &str, builder: &mut FindingBuilder<'_>) {
    let documents: Vec<serde_json::Value> = if extension == "json" {
        serde_json::from_str(text).into_iter().collect()
    } else {
        serde_yaml::Deserializer::from_str(text)
            .filter_map(|document| serde_yaml::Value::deserialize(document).ok())
            .filter_map(|value| serde_json::to_value(value).ok())
            .collect()
    };
    for document in documents {
        if document.get("apiVersion").is_some() && document.get("kind").is_some() {
            scan_kubernetes_value(&document, text, builder);
        }
        if document.get("AWSTemplateFormatVersion").is_some() || document.get("Resources").is_some()
        {
            scan_cloudformation_value(&document, text, builder);
        }
    }
}

struct StructuredIacRule<'a> {
    anchor: &'a str,
    needle: &'a str,
    rule: &'a str,
    summary: &'a str,
    severity: Severity,
    remediation: &'a str,
    cwe: &'a str,
}

fn scan_kubernetes_value(value: &serde_json::Value, text: &str, builder: &mut FindingBuilder<'_>) {
    let workload = value
        .pointer("/metadata/name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    for spec in pod_specs(value) {
        if spec
            .pointer("/hostNetwork")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            add_structured_iac(
                builder,
                text,
                StructuredIacRule {
                    anchor: workload,
                    needle: "hostNetwork",
                    rule: "iac.kubernetes.host-network",
                    summary: "Kubernetes workload uses the host network",
                    severity: Severity::High,
                    remediation: "Disable hostNetwork unless the workload has a documented, unavoidable requirement.",
                    cwe: "CWE-250",
                },
            );
        }
        for container in spec
            .get("containers")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = container
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(workload);
            let security = container
                .get("securityContext")
                .unwrap_or(&serde_json::Value::Null);
            if security
                .get("privileged")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                add_structured_iac(
                    builder,
                    text,
                    StructuredIacRule {
                        anchor: name,
                        needle: "privileged",
                        rule: "iac.kubernetes.privileged-container",
                        summary: "Kubernetes container is privileged",
                        severity: Severity::Critical,
                        remediation: "Remove privileged mode and grant only narrowly required capabilities.",
                        cwe: "CWE-250",
                    },
                );
            }
            if security
                .get("allowPrivilegeEscalation")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
            {
                add_structured_iac(
                    builder,
                    text,
                    StructuredIacRule {
                        anchor: name,
                        needle: "allowPrivilegeEscalation",
                        rule: "iac.kubernetes.privilege-escalation",
                        summary: "Kubernetes container permits privilege escalation",
                        severity: Severity::High,
                        remediation: "Set securityContext.allowPrivilegeEscalation to false.",
                        cwe: "CWE-269",
                    },
                );
            }
        }
    }
}

fn pod_specs(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let pointer = match kind {
        "Pod" => "/spec",
        "CronJob" => "/spec/jobTemplate/spec/template/spec",
        _ => "/spec/template/spec",
    };
    value.pointer(pointer).into_iter().collect()
}

fn scan_cloudformation_value(
    value: &serde_json::Value,
    text: &str,
    builder: &mut FindingBuilder<'_>,
) {
    let Some(resources) = value
        .get("Resources")
        .and_then(serde_json::Value::as_object)
    else {
        return;
    };
    for (logical_id, resource) in resources {
        let resource_type = resource
            .get("Type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let properties = resource
            .get("Properties")
            .unwrap_or(&serde_json::Value::Null);
        if resource_type == "AWS::S3::Bucket"
            && properties.get("PublicAccessBlockConfiguration").is_none()
        {
            add_structured_iac(
                builder,
                text,
                StructuredIacRule {
                    anchor: logical_id,
                    needle: "AWS::S3::Bucket",
                    rule: "iac.cloudformation.s3-public-access-block",
                    summary: "CloudFormation S3 bucket lacks public access blocking",
                    severity: Severity::High,
                    remediation: "Configure all four PublicAccessBlockConfiguration controls as true.",
                    cwe: "CWE-284",
                },
            );
        }
        if resource_type == "AWS::RDS::DBInstance"
            && properties
                .get("StorageEncrypted")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            add_structured_iac(
                builder,
                text,
                StructuredIacRule {
                    anchor: logical_id,
                    needle: "StorageEncrypted",
                    rule: "iac.cloudformation.rds-encryption",
                    summary: "CloudFormation RDS storage encryption is not enabled",
                    severity: Severity::High,
                    remediation: "Set StorageEncrypted to true and select an approved KMS key where required.",
                    cwe: "CWE-311",
                },
            );
        }
    }
}

fn add_structured_iac(builder: &mut FindingBuilder<'_>, text: &str, rule: StructuredIacRule<'_>) {
    let anchor = find_structured_scalar(text, rule.anchor).unwrap_or(0);
    let offset = text[anchor..]
        .find(rule.needle)
        .map_or(anchor, |relative| anchor + relative);
    let (line, column) = line_column(text, offset);
    let mut properties = BTreeMap::new();
    if !rule.anchor.is_empty() {
        properties.insert("object".to_owned(), rule.anchor.to_owned());
    }
    builder.add(FindingSpec { kind: FindingKind::Iac, rule: rule.rule, line, column, summary: rule.summary, details: "A parsed IaC document contains the concrete insecure configuration described by this rule.", severity: rule.severity, confidence: Confidence::High, description: format!("Parsed configuration key: {}", rule.needle), references: &["https://kubernetes.io/docs/concepts/security/", "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/"], properties, redacted: false, remediation: rule.remediation, cwe: Some(rule.cwe) });
}

fn find_structured_scalar(text: &str, value: &str) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    let quoted_double = format!("\"{value}\"");
    let quoted_single = format!("'{value}'");
    text.find(&quoted_double)
        .or_else(|| text.find(&quoted_single))
        .or_else(|| {
            text.lines()
                .scan(0usize, |offset, line| {
                    let start = *offset;
                    *offset += line.len() + 1;
                    Some((start, line))
                })
                .find_map(|(offset, line)| line.find(value).map(|column| offset + column))
        })
}

const WEAK_TLS_PROTOCOL_TOKENS: &[&str] = &["sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"];

struct ServiceConfigRule<'a> {
    rule: &'a str,
    summary: &'a str,
    details: &'a str,
    remediation: &'a str,
    severity: Severity,
    cwe: &'a str,
    references: &'a [&'a str],
}

fn add_service_finding(
    builder: &mut FindingBuilder<'_>,
    rule: &ServiceConfigRule<'_>,
    description: String,
    line: u32,
    column: u32,
) {
    builder.add(FindingSpec {
        kind: FindingKind::Iac,
        rule: rule.rule,
        line,
        column,
        summary: rule.summary,
        details: rule.details,
        severity: rule.severity,
        confidence: Confidence::High,
        description,
        references: rule.references,
        properties: BTreeMap::new(),
        redacted: false,
        remediation: rule.remediation,
        cwe: Some(rule.cwe),
    });
}

fn scan_service_config(path: &str, text: &str, builder: &mut FindingBuilder<'_>) {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let nginx_conf =
        name == "nginx.conf" || (name.starts_with("nginx.") && name.ends_with(".conf"));
    if nginx_conf {
        scan_nginx_config(text, builder);
    }
    if name.ends_with(".conf")
        && !nginx_conf
        && !matches!(
            name.as_str(),
            "pg_hba.conf" | "postgresql.conf" | "redis.conf"
        )
    {
        scan_apache_config(text, builder);
    }
    match name.as_str() {
        "pg_hba.conf" => scan_pg_hba_config(text, builder),
        "postgresql.conf" => scan_postgresql_config(text, builder),
        "redis.conf" => scan_redis_config(text, builder),
        "sshd_config" => scan_sshd_config(text, builder),
        _ => {}
    }
}

fn config_lines(text: &str) -> impl Iterator<Item = (u32, usize, &str)> {
    let mut offset = 0_usize;
    text.lines().enumerate().map(move |(index, line)| {
        let start = offset;
        offset += line.len() + 1;
        (index as u32 + 1, start, line)
    })
}

fn effective_config_line(line: &str) -> &str {
    line.split_once('#').map_or(line, |(code, _)| code).trim()
}

fn split_config_directive(line: &str) -> Option<(&str, &str)> {
    line.split_once(char::is_whitespace)
}

fn directive_column(line: &str) -> u32 {
    u32::try_from(line.len() - line.trim_start().len())
        .unwrap_or(u32::MAX)
        .saturating_add(1)
}

fn argument_tokens(arguments: &str) -> impl Iterator<Item = &str> {
    arguments
        .split(|character: char| character.is_whitespace() || character == ',' || character == ';')
        .filter(|token| !token.is_empty())
}

fn is_weak_protocol_token(token: &str) -> bool {
    let normalized = token.trim_matches(['+', '-']);
    WEAK_TLS_PROTOCOL_TOKENS
        .iter()
        .any(|weak| normalized.eq_ignore_ascii_case(weak))
}

fn enables_weak_protocol(token: &str) -> bool {
    !token.starts_with('-') && is_weak_protocol_token(token)
}

fn config_assignment(line: &str) -> Option<(&str, &str)> {
    let content = effective_config_line(line);
    if content.is_empty() {
        return None;
    }
    let (key, value) = content
        .split_once('=')
        .or_else(|| content.split_once(char::is_whitespace))?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, unquote_config_value(value)))
}

fn unquote_config_value(value: &str) -> &str {
    let trimmed = value.trim();
    let Some(first) = trimmed.chars().next() else {
        return "";
    };
    if (first == '"' || first == '\'')
        && trimmed.len() >= 2 * first.len_utf8()
        && trimmed.ends_with(first)
    {
        return &trimmed[first.len_utf8()..trimmed.len() - first.len_utf8()];
    }
    trimmed
}

const NGINX_WEAK_TLS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.nginx.weak-tls-protocol",
    summary: "Nginx enables deprecated TLS protocols",
    details: "The ssl_protocols directive explicitly lists SSLv2, SSLv3, TLSv1, or TLSv1.1.",
    remediation: "Restrict ssl_protocols to TLSv1.2 and TLSv1.3.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols"],
};

const NGINX_SERVER_TOKENS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.nginx.server-tokens",
    summary: "Nginx broadcasts its server version",
    details: "The server_tokens directive is set to on, exposing the exact version in headers and error pages.",
    remediation: "Set server_tokens off to reduce fingerprinting.",
    severity: Severity::Low,
    cwe: "CWE-200",
    references: &["https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"],
};

const APACHE_WEAK_TLS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.apache.weak-tls-protocol",
    summary: "Apache enables deprecated SSL/TLS protocols",
    details: "The SSLProtocol directive enables SSLv2, SSLv3, TLSv1, or TLSv1.1.",
    remediation: "Enable only TLSv1.2 and TLSv1.3 in SSLProtocol.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslprotocol"],
};

const APACHE_SERVER_TOKENS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.apache.server-tokens",
    summary: "Apache discloses detailed server information",
    details: "The ServerTokens directive is Full or OS, sending product, version, and OS details in response headers.",
    remediation: "Set ServerTokens Prod to minimize version disclosure.",
    severity: Severity::Low,
    cwe: "CWE-200",
    references: &["https://httpd.apache.org/docs/current/mod/core.html#servertokens"],
};

const PG_HBA_TRUST_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.pg-hba.trust-authentication",
    summary: "PostgreSQL pg_hba entry trusts connections without authentication",
    details: "A pg_hba.conf record uses the trust auth method, granting access without any credential check.",
    remediation: "Replace trust with scram-sha-256 or certificate authentication.",
    severity: Severity::Critical,
    cwe: "CWE-306",
    references: &["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
};

const POSTGRES_SSL_OFF_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.postgres.ssl-disabled",
    summary: "PostgreSQL accepts unencrypted connections",
    details: "The ssl setting is off, so client traffic is not encrypted.",
    remediation: "Enable ssl and require encrypted connections for remote clients.",
    severity: Severity::High,
    cwe: "CWE-319",
    references: &["https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-SSL"],
};

const POSTGRES_WEAK_PASSWORD_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.postgres.weak-password-encryption",
    summary: "PostgreSQL stores passwords with a weak scheme",
    details: "password_encryption is md5 or plain instead of a modern password-based scheme.",
    remediation: "Set password_encryption to scram-sha-256 and re-set roles to upgrade stored verifiers.",
    severity: Severity::Medium,
    cwe: "CWE-916",
    references: &[
        "https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-PASSWORD-ENCRYPTION",
    ],
};

const REDIS_PROTECTED_MODE_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.redis.protected-mode-disabled",
    summary: "Redis protected mode disabled",
    details: "protected-mode no lets Redis serve external clients even when no authentication is configured.",
    remediation: "Keep protected-mode yes or configure ACLs and bind addresses before exposing Redis.",
    severity: Severity::High,
    cwe: "CWE-306",
    references: &["https://redis.io/docs/latest/operate/oss_and_mgmt/admin/"],
};

const REDIS_EMPTY_PASSWORD_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.redis.empty-password",
    summary: "Redis requirepass configured with an empty password",
    details: "The requirepass directive is set to an empty quoted string, disabling authentication.",
    remediation: "Configure a strong requirepass value or ACL users instead of an empty password.",
    severity: Severity::High,
    cwe: "CWE-521",
    references: &["https://redis.io/docs/latest/operate/oss_and_mgmt/admin/"],
};

const SSHD_ROOT_LOGIN_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.root-login-permitted",
    summary: "SSH permits direct root login",
    details: "PermitRootLogin yes allows logins straight into the root account.",
    remediation: "Use PermitRootLogin no (or prohibit-password) and escalate via sudo.",
    severity: Severity::High,
    cwe: "CWE-250",
    references: &["https://man.openbsd.org/sshd_config#PermitRootLogin"],
};

const SSHD_PASSWORD_AUTH_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.password-authentication",
    summary: "SSH permits password authentication",
    details: "PasswordAuthentication yes allows brute-forceable password logins.",
    remediation: "Require public key authentication.",
    severity: Severity::Medium,
    cwe: "CWE-521",
    references: &["https://man.openbsd.org/sshd_config#PasswordAuthentication"],
};

const SSHD_PROTOCOL_ONE_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.protocol-version-1",
    summary: "SSH protocol version 1 enabled",
    details: "Protocol 1 enables the deprecated SSHv1 protocol with weak integrity guarantees.",
    remediation: "Support SSH protocol version 2 only.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://man.openbsd.org/sshd_config#Protocol"],
};

const SSHD_EMPTY_PASSWORDS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.empty-passwords-permitted",
    summary: "SSH permits empty passwords",
    details: "PermitEmptyPasswords yes lets accounts without passwords authenticate.",
    remediation: "Reject empty passwords with PermitEmptyPasswords no.",
    severity: Severity::High,
    cwe: "CWE-521",
    references: &["https://man.openbsd.org/sshd_config#PermitEmptyPasswords"],
};

fn scan_nginx_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let content = effective_config_line(line);
        let Some((directive, arguments)) = split_config_directive(content) else {
            continue;
        };
        if directive.eq_ignore_ascii_case("ssl_protocols")
            && argument_tokens(arguments).any(is_weak_protocol_token)
        {
            add_service_finding(
                builder,
                &NGINX_WEAK_TLS_RULE,
                content.to_owned(),
                number,
                directive_column(line),
            );
        } else if directive.eq_ignore_ascii_case("server_tokens")
            && argument_tokens(arguments)
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case("on"))
        {
            add_service_finding(
                builder,
                &NGINX_SERVER_TOKENS_RULE,
                content.to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

fn scan_apache_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let content = effective_config_line(line);
        let Some((directive, arguments)) = split_config_directive(content) else {
            continue;
        };
        if directive.eq_ignore_ascii_case("SSLProtocol")
            && argument_tokens(arguments).any(enables_weak_protocol)
        {
            add_service_finding(
                builder,
                &APACHE_WEAK_TLS_RULE,
                content.to_owned(),
                number,
                directive_column(line),
            );
        } else if directive.eq_ignore_ascii_case("ServerTokens")
            && argument_tokens(arguments).next().is_some_and(|value| {
                value.eq_ignore_ascii_case("full") || value.eq_ignore_ascii_case("os")
            })
        {
            add_service_finding(
                builder,
                &APACHE_SERVER_TOKENS_RULE,
                content.to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

fn scan_pg_hba_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let entry = effective_config_line(line);
        let field_count = entry.split_whitespace().count();
        let trust_method = entry
            .split_whitespace()
            .last()
            .is_some_and(|method| method.eq_ignore_ascii_case("trust"));
        if field_count >= 4 && trust_method {
            add_service_finding(
                builder,
                &PG_HBA_TRUST_RULE,
                entry.to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

fn scan_postgresql_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let Some((key, value)) = config_assignment(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case("ssl") && value.eq_ignore_ascii_case("off") {
            add_service_finding(
                builder,
                &POSTGRES_SSL_OFF_RULE,
                effective_config_line(line).to_owned(),
                number,
                directive_column(line),
            );
        } else if key.eq_ignore_ascii_case("password_encryption")
            && (value.eq_ignore_ascii_case("md5") || value.eq_ignore_ascii_case("plain"))
        {
            add_service_finding(
                builder,
                &POSTGRES_WEAK_PASSWORD_RULE,
                effective_config_line(line).to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

fn scan_redis_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let Some((key, value)) = config_assignment(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case("protected-mode") && value.eq_ignore_ascii_case("no") {
            add_service_finding(
                builder,
                &REDIS_PROTECTED_MODE_RULE,
                effective_config_line(line).to_owned(),
                number,
                directive_column(line),
            );
        } else if key.eq_ignore_ascii_case("requirepass") && value.is_empty() {
            add_service_finding(
                builder,
                &REDIS_EMPTY_PASSWORD_RULE,
                effective_config_line(line).to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

fn scan_sshd_config(text: &str, builder: &mut FindingBuilder<'_>) {
    for (number, _, line) in config_lines(text) {
        let entry = effective_config_line(line);
        let Some((keyword, arguments)) = split_config_directive(entry) else {
            continue;
        };
        let Some(value) = argument_tokens(arguments).next() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("PermitRootLogin") && value.eq_ignore_ascii_case("yes") {
            add_service_finding(
                builder,
                &SSHD_ROOT_LOGIN_RULE,
                entry.to_owned(),
                number,
                directive_column(line),
            );
        } else if keyword.eq_ignore_ascii_case("PasswordAuthentication")
            && value.eq_ignore_ascii_case("yes")
        {
            add_service_finding(
                builder,
                &SSHD_PASSWORD_AUTH_RULE,
                entry.to_owned(),
                number,
                directive_column(line),
            );
        } else if keyword.eq_ignore_ascii_case("Protocol") && value == "1" {
            add_service_finding(
                builder,
                &SSHD_PROTOCOL_ONE_RULE,
                entry.to_owned(),
                number,
                directive_column(line),
            );
        } else if keyword.eq_ignore_ascii_case("PermitEmptyPasswords")
            && value.eq_ignore_ascii_case("yes")
        {
            add_service_finding(
                builder,
                &SSHD_EMPTY_PASSWORDS_RULE,
                entry.to_owned(),
                number,
                directive_column(line),
            );
        }
    }
}

struct SastRule {
    rule: &'static str,
    regex: Regex,
    summary: &'static str,
    cwe: &'static str,
    severity: Severity,
    remediation: &'static str,
}

static SAST_RULES: LazyLock<BTreeMap<&'static str, Vec<SastRule>>> = LazyLock::new(|| {
    let mut by_extension = BTreeMap::new();
    for (extensions, rules) in [
        (
            &["rs"][..],
            &[
                (
                    "sast.rust.command-shell",
                    r#"\bCommand\s*::\s*new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*\)\s*\.\s*arg\s*\(\s*["'](?:-c|/C|Command)["']\s*\)\s*\.\s*arg\s*\([^"']"#,
                    "Dynamic shell command execution",
                    "CWE-78",
                    Severity::High,
                    "Pass fixed arguments directly to the target executable and strictly map permitted operations.",
                ),
                (
                    "sast.rust.sql-format",
                    r#"(?s)\b(?:query|execute)\s*\(\s*&?format!\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b"#,
                    "Formatted SQL passed to a database API",
                    "CWE-89",
                    Severity::High,
                    "Use parameterized queries and bind every untrusted value.",
                ),
                (
                    "sast.rust.weak-hash-md5",
                    r"\bMd5\s*::\s*new\s*\(",
                    "MD5 hash construction",
                    "CWE-327",
                    Severity::Medium,
                    "Use SHA-256 or BLAKE3; MD5 is broken for security-sensitive digests.",
                ),
                (
                    "sast.rust.weak-hash-sha1",
                    r"\bSha1\s*::\s*new\s*\(",
                    "SHA-1 hash construction",
                    "CWE-327",
                    Severity::Medium,
                    "Use SHA-256 or BLAKE3; SHA-1 is broken for security-sensitive digests.",
                ),
            ][..],
        ),
        (
            &["js", "jsx", "ts", "tsx"][..],
            &[
                (
                    "sast.javascript.eval-dynamic",
                    r"\b(?:eval|Function)\s*\(\s*",
                    "Dynamic JavaScript evaluation",
                    "CWE-95",
                    Severity::High,
                    "Replace dynamic evaluation with explicit parsing and a fixed dispatch table.",
                ),
                (
                    "sast.javascript.exec-dynamic",
                    r#"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^"'`])"#,
                    "Dynamic command execution",
                    "CWE-78",
                    Severity::High,
                    "Use spawn/execFile with a fixed executable and validated argument array.",
                ),
                (
                    "sast.javascript.sql-template",
                    r"\b(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{",
                    "Interpolated SQL query",
                    "CWE-89",
                    Severity::High,
                    "Use driver placeholders and parameter binding.",
                ),
                (
                    "sast.javascript.weak-hash",
                    r#"\bcreateHash\s*\(\s*["'](md5|sha1)["']\s*\)"#,
                    "Weak hash algorithm selected",
                    "CWE-327",
                    Severity::Medium,
                    "Hash with createHash('sha256') or stronger algorithms.",
                ),
            ][..],
        ),
        (
            &["py"][..],
            &[
                (
                    "sast.python.eval-dynamic",
                    r"\b(?:eval|exec)\s*\(\s*",
                    "Dynamic Python evaluation",
                    "CWE-95",
                    Severity::High,
                    "Parse expected data formats and use explicit operations rather than eval or exec.",
                ),
                (
                    "sast.python.shell-true",
                    r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^\)]*\bshell\s*=\s*True",
                    "Python subprocess enables a command shell",
                    "CWE-78",
                    Severity::High,
                    "Set shell=False and pass a fixed executable plus a validated argument list.",
                ),
                (
                    "sast.python.sql-format",
                    r#"(?i)\.execute\s*\(\s*(?:f["']|["'][^"']*(?:select|insert|update|delete)[^"']*["']\s*(?:%|\.format\s*\())"#,
                    "Formatted SQL execution",
                    "CWE-89",
                    Severity::High,
                    "Use DB-API placeholders and a separate parameter sequence.",
                ),
                (
                    "sast.python.weak-hash-md5",
                    r"\bhashlib\.md5\s*\(",
                    "MD5 hash usage",
                    "CWE-327",
                    Severity::Medium,
                    "Prefer hashlib.sha256 or stronger for security-sensitive digests.",
                ),
                (
                    "sast.python.weak-hash-sha1",
                    r"\bhashlib\.sha1\s*\(",
                    "SHA-1 hash usage",
                    "CWE-327",
                    Severity::Medium,
                    "Prefer hashlib.sha256 or stronger for security-sensitive digests.",
                ),
                (
                    "sast.python.pickle-deserialization",
                    r"\bpickle\.loads?\s*\(",
                    "Pickle deserialization",
                    "CWE-502",
                    Severity::High,
                    "Exchange data in inert formats such as JSON instead of unpickling bytes.",
                ),
                (
                    "sast.python.yaml-unsafe-load",
                    r"\byaml\.load\s*\(",
                    "YAML load without a restricted Loader",
                    "CWE-502",
                    Severity::High,
                    "Use yaml.safe_load or pass an explicit Loader limited to safe types.",
                ),
            ][..],
        ),
        (
            &["go"][..],
            &[
                (
                    "sast.go.command-shell",
                    r#"\bexec\.Command\s*\(\s*["'](?:sh|bash)["']\s*,\s*["']-c["']\s*,\s*[^"']"#,
                    "Dynamic shell command execution",
                    "CWE-78",
                    Severity::High,
                    "Invoke the intended executable directly with a validated argument slice.",
                ),
                (
                    "sast.go.sql-format",
                    r#"\b(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b"#,
                    "Formatted SQL passed to database/sql",
                    "CWE-89",
                    Severity::High,
                    "Use database/sql placeholders and pass values as query arguments.",
                ),
                (
                    "sast.go.weak-hash-md5",
                    r"\bmd5\.New\s*\(",
                    "MD5 hash construction",
                    "CWE-327",
                    Severity::Medium,
                    "Use crypto/sha256 or stronger hashes for security-sensitive digests.",
                ),
                (
                    "sast.go.weak-hash-sha1",
                    r"\bsha1\.New\s*\(",
                    "SHA-1 hash construction",
                    "CWE-327",
                    Severity::Medium,
                    "Use crypto/sha256 or stronger hashes for security-sensitive digests.",
                ),
            ][..],
        ),
        (
            &["java"][..],
            &[
                (
                    "sast.java.runtime-exec",
                    r"\bRuntime\.getRuntime\(\)\.exec\s*\(\s*",
                    "Dynamic Runtime.exec command",
                    "CWE-78",
                    Severity::High,
                    "Use ProcessBuilder with a fixed executable and validated arguments.",
                ),
                (
                    "sast.java.sql-concat",
                    r#"\b(?:executeQuery|executeUpdate|execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+"#,
                    "Concatenated SQL execution",
                    "CWE-89",
                    Severity::High,
                    "Use PreparedStatement placeholders and typed setters.",
                ),
                (
                    "sast.java.weak-hash",
                    r#"\bMessageDigest\s*\.\s*getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']\s*\)"#,
                    "Weak MessageDigest algorithm requested",
                    "CWE-327",
                    Severity::Medium,
                    "Request SHA-256 or stronger digest algorithms.",
                ),
                (
                    "sast.java.unsafe-deserialization",
                    r"\bObjectInputStream\b[^;\n]*?\.readObject\s*\(",
                    "Native Java deserialization",
                    "CWE-502",
                    Severity::High,
                    "Parse untrusted bytes with schema-based formats instead of ObjectInputStream.readObject.",
                ),
            ][..],
        ),
        (
            &["cs"][..],
            &[
                (
                    "sast.csharp.process-shell",
                    r#"\bProcess\.Start\s*\(\s*["'](?:cmd\.exe|powershell(?:\.exe)?)["']\s*,\s*[^"']"#,
                    "Dynamic shell process execution",
                    "CWE-78",
                    Severity::High,
                    "Use ProcessStartInfo.ArgumentList with a fixed executable and validated arguments.",
                ),
                (
                    "sast.csharp.sql-concat",
                    r#"\b(?:SqlCommand|ExecuteSqlRaw)\s*\(\s*(?:\$["']|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)"#,
                    "Interpolated or concatenated SQL",
                    "CWE-89",
                    Severity::High,
                    "Use SQL parameters or ExecuteSqlInterpolated with trusted query structure.",
                ),
                (
                    "sast.csharp.weak-hash",
                    r"\b(?:MD5|SHA1)\.Create\s*\(\s*\)",
                    "Weak hash algorithm instance",
                    "CWE-327",
                    Severity::Medium,
                    "Create SHA256 or stronger hash instances for security-sensitive digests.",
                ),
                (
                    "sast.csharp.unsafe-deserialization",
                    r"\bBinaryFormatter\b[^;\n]*?\.Deserialize\s*\(",
                    "BinaryFormatter deserialization",
                    "CWE-502",
                    Severity::High,
                    "Replace BinaryFormatter with a safe serializer; never deserialize untrusted input.",
                ),
            ][..],
        ),
    ] {
        for extension in extensions {
            by_extension.insert(
                *extension,
                rules
                    .iter()
                    .map(
                        |(rule, expression, summary, cwe, severity, remediation)| SastRule {
                            rule,
                            regex: Regex::new(expression).expect("constant SAST regex"),
                            summary,
                            cwe,
                            severity: *severity,
                            remediation,
                        },
                    )
                    .collect(),
            );
        }
    }
    by_extension
});

fn scan_sast(path: &str, text: &str, builder: &mut FindingBuilder<'_>) {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(rules) = SAST_RULES.get(extension.as_str()) else {
        return;
    };
    let line_starts = line_starts(text);
    for rule in rules {
        for matched in rule.regex.find_iter(text) {
            if offset_in_comment_or_string_prefix(text, matched.start(), &extension) {
                continue;
            }
            if matches!(
                rule.rule,
                "sast.javascript.eval-dynamic"
                    | "sast.python.eval-dynamic"
                    | "sast.java.runtime-exec"
            ) && has_single_literal_argument(&text[matched.end()..])
            {
                continue;
            }
            if rule.rule == "sast.python.yaml-unsafe-load"
                && yaml_call_specifies_loader(&text[matched.end()..])
            {
                continue;
            }
            let (line, column) = indexed_line_column(&line_starts, matched.start());
            builder.add(FindingSpec { kind: FindingKind::Sast, rule: rule.rule, line, column, summary: rule.summary, details: "A language-specific call expression uses a dangerous sink with dynamic or explicitly unsafe syntax.", severity: rule.severity, confidence: Confidence::High, description: "Dangerous sink invocation detected; source expression omitted.".to_owned(), references: &["https://owasp.org/www-project-code-review-guide/"], properties: BTreeMap::new(), redacted: true, remediation: rule.remediation, cwe: Some(rule.cwe) });
        }
    }
}

fn has_single_literal_argument(after_open_paren: &str) -> bool {
    let source = after_open_paren.trim_start();
    let mut chars = source.char_indices();
    let Some((_, quote @ ('\'' | '"' | '`'))) = chars.next() else {
        return false;
    };
    let mut escaped = false;
    for (offset, character) in chars {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if quote == '`' && character == '$' && source[offset..].starts_with("${") {
            return false;
        }
        if character == quote {
            return source[offset + character.len_utf8()..]
                .trim_start()
                .starts_with(')');
        }
    }
    false
}

static YAML_LOADER_KWARG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bLoader\s*=").expect("constant YAML Loader kwarg regex"));

fn yaml_call_specifies_loader(after_open_paren: &str) -> bool {
    const MAX_CALL_ARGUMENT_SCAN_BYTES: usize = 16 * 1024;
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut end = after_open_paren.len().min(MAX_CALL_ARGUMENT_SCAN_BYTES);
    for (index, character) in after_open_paren.char_indices() {
        if index >= MAX_CALL_ARGUMENT_SCAN_BYTES {
            break;
        }
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' => {
                if depth == 0 {
                    end = index;
                    break;
                }
                depth -= 1;
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    YAML_LOADER_KWARG_REGEX.is_match(&after_open_paren[..end])
}

fn offset_in_comment_or_string_prefix(text: &str, offset: usize, extension: &str) -> bool {
    let line_start = text[..offset]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    let prefix = &text[line_start..offset];
    let trimmed = prefix.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return true;
    }
    if extension == "py" {
        return false;
    }
    let mut quote = None;
    let mut escaped = false;
    for character in prefix.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        }
    }
    quote.is_some()
}

fn scan_malware(
    bytes: &[u8],
    config: &ScannerConfig,
    signatures: &MalwareSignatures,
    builder: &mut FindingBuilder<'_>,
) {
    let digest = hex_sha256(bytes);
    if let Some(signature) = signatures.sha256.get(&digest) {
        let mut properties = BTreeMap::new();
        properties.insert("sha256".to_owned(), digest);
        properties.insert("signature".to_owned(), signature.clone());
        builder.add(FindingSpec { kind: FindingKind::Malware, rule: "malware.sha256-denylist", line: 1, column: 1, summary: "File matches malware signature denylist", details: "The complete file SHA-256 exactly matches a caller-supplied local signature database entry.", severity: Severity::Critical, confidence: Confidence::High, description: format!("Exact SHA-256 match for signature '{signature}'."), references: &["https://csrc.nist.gov/glossary/term/cryptographic_hash_function"], properties, redacted: false, remediation: "Quarantine the file, investigate its provenance, and remove it only after preserving forensic evidence.", cwe: None });
    }
    let formats = detected_formats(bytes);
    if formats.len() > 1 {
        let mut properties = BTreeMap::new();
        properties.insert("formats".to_owned(), formats.join(","));
        builder.add(FindingSpec { kind: FindingKind::Malware, rule: "malware.executable-script-polyglot", line: 1, column: 1, summary: "Executable/script polyglot indicator", details: "Multiple independently meaningful executable or script format signatures occur in the same file.", severity: Severity::Medium, confidence: Confidence::Low, description: "Heuristic polyglot indicator; manual validation is required.".to_owned(), references: &["https://attack.mitre.org/techniques/T1027/"], properties, redacted: false, remediation: "Quarantine for manual analysis and verify the artifact against its trusted publisher.", cwe: None });
    }
    if bytes.starts_with(b"PK\x03\x04") {
        scan_zip_bomb(bytes, config, builder);
    }
}

fn detected_formats(bytes: &[u8]) -> Vec<&'static str> {
    let mut formats = Vec::new();
    if bytes.starts_with(b"MZ") {
        formats.push("pe");
    }
    if bytes.starts_with(b"\x7fELF") {
        formats.push("elf");
    }
    if bytes.starts_with(b"#!") {
        formats.push("script");
    }
    if bytes.starts_with(b"PK\x03\x04") {
        formats.push("zip");
    }
    if bytes.starts_with(b"%PDF-") {
        formats.push("pdf");
    }
    if bytes
        .windows(2)
        .skip(2)
        .take(4096)
        .any(|window| window == b"MZ")
    {
        formats.push("embedded-pe");
    }
    if bytes
        .windows(4)
        .skip(4)
        .take(4096)
        .any(|window| window == b"\x7fELF")
    {
        formats.push("embedded-elf");
    }
    formats.sort_unstable();
    formats.dedup();
    formats
}

fn scan_zip_bomb(bytes: &[u8], config: &ScannerConfig, builder: &mut FindingBuilder<'_>) {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return;
    };
    let mut total_uncompressed = 0_u64;
    let mut total_compressed = 0_u64;
    let mut suspicious_entry = false;
    let inspected = archive
        .len()
        .min(config.max_archive_entries.saturating_add(1));
    for index in 0..inspected {
        let Ok(file) = archive.by_index(index) else {
            continue;
        };
        total_uncompressed = total_uncompressed.saturating_add(file.size());
        total_compressed = total_compressed.saturating_add(file.compressed_size());
        suspicious_entry |= file.size() > ARCHIVE_ENTRY_SIZE_LIMIT
            || (file.compressed_size() > 0
                && file.size() / file.compressed_size() > ARCHIVE_RATIO_LIMIT);
    }
    let too_many = archive.len() > config.max_archive_entries;
    let too_large = total_uncompressed > config.max_archive_uncompressed_bytes;
    let excessive_ratio =
        total_compressed > 0 && total_uncompressed / total_compressed > ARCHIVE_RATIO_LIMIT;
    if too_many || too_large || excessive_ratio || suspicious_entry {
        let mut properties = BTreeMap::new();
        properties.insert("entries".to_owned(), archive.len().to_string());
        properties.insert(
            "declared_uncompressed_bytes".to_owned(),
            total_uncompressed.to_string(),
        );
        properties.insert("compressed_bytes".to_owned(), total_compressed.to_string());
        builder.add(FindingSpec { kind: FindingKind::Malware, rule: "malware.archive-bomb-indicator", line: 1, column: 1, summary: "Archive bomb indicator", details: "ZIP central-directory metadata exceeds configured expansion, entry-count, entry-size, or compression-ratio bounds. No entry content was extracted.", severity: Severity::High, confidence: Confidence::Medium, description: "Metadata-only archive expansion heuristic; the archive was not decompressed.".to_owned(), references: &["https://owasp.org/www-community/attacks/Zip_bomb"], properties, redacted: false, remediation: "Reject or quarantine the archive and inspect it in an isolated bounded analysis environment.", cwe: None });
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(text.len() / 40 + 1);
    starts.push(0);
    starts.extend(
        text.bytes()
            .enumerate()
            .filter_map(|(offset, byte)| (byte == b'\n').then_some(offset + 1)),
    );
    starts
}

fn indexed_line_column(starts: &[usize], offset: usize) -> (u32, u32) {
    let line_index = starts
        .partition_point(|start| *start <= offset)
        .saturating_sub(1);
    (
        u32::try_from(line_index + 1).unwrap_or(u32::MAX),
        u32::try_from(offset.saturating_sub(starts[line_index]) + 1).unwrap_or(u32::MAX),
    )
}

fn line_column(text: &str, offset: usize) -> (u32, u32) {
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32 + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len(), |(_, tail)| tail.len()) as u32
        + 1;
    (line, column)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    fn asset() -> AssetId {
        AssetId::new("asset:test").unwrap()
    }
    fn analyze(path: &str, text: &str) -> ScanOutput {
        analyze_bytes(
            path,
            text.as_bytes(),
            &asset(),
            &ScannerConfig::default(),
            &MalwareSignatures::default(),
        )
    }
    fn has(output: &ScanOutput, rule: &str) -> bool {
        output
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_str() == rule)
    }

    #[test]
    fn secret_patterns_are_redacted_and_fingerprinted() {
        let secret = format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        let output = analyze("config.txt", &secret);
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "secret.github-token")
            .unwrap();
        let serialized = serde_json::to_string(finding).unwrap();
        assert!(!serialized.contains(&secret));
        let evidence = finding.evidence.iter().next().unwrap();
        assert!(evidence.redacted);
        assert_eq!(
            evidence.properties["fingerprint_sha256"],
            hex_sha256(secret.as_bytes())
        );
    }

    #[test]
    fn secret_evidence_contains_only_safe_metadata() {
        let secret = format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        let output = analyze("config.txt", &secret);
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "secret.github-token")
            .unwrap();
        let evidence = finding.evidence.iter().next().unwrap();

        assert_eq!(
            evidence
                .properties
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "entropy_milli",
                "fingerprint_sha256",
                "length_bytes",
                "pattern",
            ]
        );
        assert_eq!(evidence.properties["pattern"], "secret.github-token");
        assert_eq!(
            evidence.properties["length_bytes"],
            secret.len().to_string()
        );
        assert_eq!(
            evidence.properties["entropy_milli"],
            ((shannon_entropy(&secret) * 1000.0).round() as u64).to_string()
        );
        let serialized = serde_json::to_string(finding).unwrap();
        assert!(!serialized.contains(&secret));
        assert!(!serialized.contains("matched_bytes"));
    }

    #[test]
    fn secret_allowlist_and_placeholders_are_close_negatives() {
        let allowlisted = format!(
            "token = \"{}{}\" # gitleaks:allow",
            "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        );
        assert!(!has(&analyze("x", &allowlisted), "secret.github-token"));
        assert!(!has(
            &analyze("x", "password = \"replace_me_please\""),
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn high_entropy_assignment_requires_entropy_and_context() {
        assert!(has(
            &analyze("x", "api_key = \"B7kP9vQ2mX8cR4tN6zW3\""),
            "secret.high-entropy-assignment"
        ));
        assert!(!has(
            &analyze("x", "value = \"B7kP9vQ2mX8cR4tN6zW3\""),
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn terraform_rules_detect_concrete_assignments_only() {
        let output = analyze(
            "main.tf",
            "cidr_blocks = [\"0.0.0.0/0\"]\nencrypted = false\n",
        );
        assert!(has(&output, "iac.terraform.public-ingress"));
        assert!(has(&output, "iac.terraform.encryption-disabled"));
        assert!(!has(
            &analyze("main.tf", "description = \"0.0.0.0/0 encrypted = false\""),
            "iac.terraform.public-ingress"
        ));
    }

    #[test]
    fn kubernetes_rules_parse_documents() {
        let yaml = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: app\n      image: app@sha256:abc\n      securityContext:\n        privileged: true\n        allowPrivilegeEscalation: false\n";
        let output = analyze("pod.yaml", yaml);
        assert!(has(&output, "iac.kubernetes.host-network"));
        assert!(has(&output, "iac.kubernetes.privileged-container"));
        assert!(!has(&output, "iac.kubernetes.privilege-escalation"));
    }

    #[test]
    fn cloudformation_rules_parse_json() {
        let json = r#"{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"Db":{"Type":"AWS::RDS::DBInstance","Properties":{"StorageEncrypted":false}},"Bucket":{"Type":"AWS::S3::Bucket","Properties":{}}}}"#;
        let output = analyze("template.json", json);
        assert!(has(&output, "iac.cloudformation.rds-encryption"));
        assert!(has(&output, "iac.cloudformation.s3-public-access-block"));
    }

    #[test]
    fn structured_iac_repeated_objects_have_distinct_locations_and_ids() {
        let yaml = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: repeated\nspec:\n  containers:\n    - name: first\n      securityContext:\n        privileged: true\n        allowPrivilegeEscalation: false\n    - name: second\n      securityContext:\n        privileged: true\n        allowPrivilegeEscalation: false\n";
        let output = analyze("pod.yaml", yaml);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "iac.kubernetes.privileged-container")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 2);
        assert_ne!(findings[0].id, findings[1].id);
        assert_ne!(findings[0].location_id, findings[1].location_id);
        let lines = findings
            .iter()
            .map(|finding| {
                output
                    .locations
                    .iter()
                    .find(|location| Some(&location.id) == finding.location_id.as_ref())
                    .unwrap()
                    .start
                    .unwrap()
                    .line
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(lines, BTreeSet::from([9, 13]));
    }

    #[test]
    fn dockerfile_rules_and_close_negative() {
        let output = analyze(
            "Dockerfile",
            "FROM alpine\nADD https://bad.invalid/tool /tool\nARG API_TOKEN=x\n",
        );
        assert!(has(&output, "iac.dockerfile.remote-add"));
        assert!(has(&output, "iac.dockerfile.secret-in-build-arg"));
        assert!(has(&output, "iac.dockerfile.root-user"));
        assert!(!has(
            &analyze("Dockerfile", "FROM alpine\nCOPY tool /tool\nUSER 10001\n"),
            "iac.dockerfile.root-user"
        ));
        assert!(!has(
            &analyze(
                "Dockerfile",
                "FROM alpine\nARG API_TOKEN\nENV TOKEN_ENDPOINT=https://example.invalid\nUSER 10001\n",
            ),
            "iac.dockerfile.secret-in-build-arg"
        ));
        assert!(has(
            &analyze(
                "Dockerfile",
                "FROM alpine\nENV DB_PASSWORD hunter2 API_KEY=abc123\nUSER 10001\n",
            ),
            "iac.dockerfile.secret-in-build-arg"
        ));
    }

    #[test]
    fn dockerfile_root_user_is_determined_by_final_stage() {
        assert!(has(
            &analyze(
                "Dockerfile",
                "FROM alpine AS build\nUSER 10001\nFROM scratch\nCOPY --from=build /app /app\n"
            ),
            "iac.dockerfile.root-user"
        ));
        assert!(!has(
            &analyze(
                "Dockerfile",
                "FROM alpine AS build\nUSER root\nFROM scratch\nUSER 10001:10001\n"
            ),
            "iac.dockerfile.root-user"
        ));
        assert!(has(
            &analyze("Dockerfile", "FROM alpine\nUSER 10001\nUSER root\n"),
            "iac.dockerfile.root-user"
        ));
    }

    #[test]
    fn sast_rules_are_language_and_syntax_aware() {
        assert!(has(
            &analyze("x.py", "subprocess.run(user_input, shell=True)"),
            "sast.python.shell-true"
        ));
        assert!(has(
            &analyze("x.ts", "db.query(`SELECT * FROM users WHERE id=${id}`)"),
            "sast.javascript.sql-template"
        ));
        assert!(has(
            &analyze("x.go", "exec.Command(\"sh\", \"-c\", input)"),
            "sast.go.command-shell"
        ));
        assert!(has(
            &analyze("x.rs", "Command::new(\"sh\").arg(\"-c\").arg(input)"),
            "sast.rust.command-shell"
        ));
    }

    #[test]
    fn sast_ignores_other_languages_comments_and_fixed_calls() {
        assert!(!has(
            &analyze("x.txt", "eval(user_input)"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.js", "// eval(user_input)"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.py", "eval(\"1 + 1\")"),
            "sast.python.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.go", "exec.Command(\"git\", \"status\")"),
            "sast.go.command-shell"
        ));
    }

    #[test]
    fn sast_only_suppresses_a_single_constant_literal_argument() {
        assert!(has(
            &analyze("x.py", "eval(\"safe\" + user_input)"),
            "sast.python.eval-dynamic"
        ));
        assert!(has(
            &analyze("x.js", "eval(`safe ${userInput}`)"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.js", "eval(\"1 + 1\")"),
            "sast.javascript.eval-dynamic"
        ));
    }

    #[test]
    fn sast_evidence_is_redacted_and_omits_credentials() {
        let credential = "postgres://admin:hunter2@example.invalid/database";
        let source = format!("eval(credential + \"{credential}\")");
        let output = analyze("x.js", &source);
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "sast.javascript.eval-dynamic")
            .unwrap();
        let evidence = finding.evidence.iter().next().unwrap();
        assert!(evidence.redacted);
        let serialized = serde_json::to_string(finding).unwrap();
        assert!(!serialized.contains(credential));
        assert!(!serialized.contains("hunter2"));
    }

    #[test]
    fn exact_malware_digest_match_is_high_confidence() {
        let bytes = b"known malicious fixture";
        let digest = hex_sha256(bytes);
        let signatures = MalwareSignatures {
            sha256: BTreeMap::from([(digest.clone(), "fixture-family".to_owned())]),
        };
        let output = analyze_bytes(
            "sample.bin",
            bytes,
            &asset(),
            &ScannerConfig::default(),
            &signatures,
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "malware.sha256-denylist")
            .unwrap();
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(
            finding.evidence.iter().next().unwrap().properties["sha256"],
            digest
        );
    }

    #[test]
    fn polyglot_is_labeled_low_confidence() {
        let mut bytes = b"#!/bin/sh\n".to_vec();
        bytes.extend_from_slice(b"padding MZ payload");
        let output = analyze_bytes(
            "polyglot",
            &bytes,
            &asset(),
            &ScannerConfig::default(),
            &MalwareSignatures::default(),
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "malware.executable-script-polyglot")
            .unwrap();
        assert_eq!(finding.confidence, Confidence::Low);
    }

    #[test]
    fn archive_bomb_uses_metadata_without_extracting() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file(
                "large.txt",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![b'A'; 200_000]).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let config = ScannerConfig {
            max_archive_uncompressed_bytes: 100_000,
            ..ScannerConfig::default()
        };
        let output = analyze_bytes(
            "bomb.zip",
            &bytes,
            &asset(),
            &config,
            &MalwareSignatures::default(),
        );
        assert!(has(&output, "malware.archive-bomb-indicator"));
    }

    #[test]
    fn binary_files_skip_text_analyzers_but_keep_hash_scanning() {
        let bytes = b"\0ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
        let digest = hex_sha256(bytes);
        let signatures = MalwareSignatures {
            sha256: BTreeMap::from([(digest, "binary-fixture".to_owned())]),
        };
        let output = analyze_bytes(
            "binary",
            bytes,
            &asset(),
            &ScannerConfig::default(),
            &signatures,
        );
        assert!(has(&output, "malware.sha256-denylist"));
        assert!(!has(&output, "secret.github-token"));
    }

    #[test]
    fn nginx_rules_flag_weak_tls_protocols_and_version_disclosure() {
        let output = analyze(
            "etc/nginx/nginx.conf",
            "server {\n  ssl_protocols SSLv3 TLSv1.1;\n  server_tokens on;\n}\n",
        );
        assert!(has(&output, "iac.nginx.weak-tls-protocol"));
        assert!(has(&output, "iac.nginx.server-tokens"));
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "iac.nginx.server-tokens")
            .unwrap();
        let location = output
            .locations
            .iter()
            .find(|location| Some(&location.id) == finding.location_id.as_ref())
            .unwrap();
        assert_eq!(location.start.unwrap().line, 3);
        let hardened = analyze(
            "etc/nginx/nginx.conf",
            "server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n  server_tokens off;\n}\n",
        );
        assert!(!has(&hardened, "iac.nginx.weak-tls-protocol"));
        assert!(!has(&hardened, "iac.nginx.server-tokens"));
    }

    #[test]
    fn apache_rules_flag_enabled_weak_protocols_and_verbose_server_tokens() {
        let output = analyze(
            "conf/httpd.conf",
            "SSLProtocol -ALL +SSLv3\nServerTokens OS\n",
        );
        assert!(has(&output, "iac.apache.weak-tls-protocol"));
        assert!(has(&output, "iac.apache.server-tokens"));
        assert!(has(
            &analyze("httpd.conf", "SSLProtocol +TLSv1\n"),
            "iac.apache.weak-tls-protocol"
        ));
        assert!(!has(
            &analyze("httpd.conf", "SSLProtocol -TLSv1\n"),
            "iac.apache.weak-tls-protocol"
        ));
        let hardened = analyze(
            "conf/httpd.conf",
            "SSLProtocol -ALL +TLSv1.2\nServerTokens Prod\n",
        );
        assert!(!has(&hardened, "iac.apache.weak-tls-protocol"));
        assert!(!has(&hardened, "iac.apache.server-tokens"));
    }

    #[test]
    fn pg_hba_trust_entries_are_flagged_as_critical_missing_authentication() {
        let output = analyze(
            "data/pg_hba.conf",
            "# TYPE DATABASE USER ADDRESS METHOD\nlocal all all trust\nhost app app 10.0.0.0/8 scram-sha-256\n",
        );
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "iac.pg-hba.trust-authentication")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].kind, FindingKind::Iac);
    }

    #[test]
    fn postgresql_ssl_and_password_encryption_rules_flag_concrete_values() {
        let output = analyze(
            "postgresql.conf",
            "ssl = off\npassword_encryption = md5\npassword_encryption = plain\n",
        );
        assert!(has(&output, "iac.postgres.ssl-disabled"));
        assert!(has(&output, "iac.postgres.weak-password-encryption"));
        let hardened = analyze(
            "postgresql.conf",
            "ssl = on\npassword_encryption = scram-sha-256\n",
        );
        assert!(!has(&hardened, "iac.postgres.ssl-disabled"));
        assert!(!has(&hardened, "iac.postgres.weak-password-encryption"));
    }

    #[test]
    fn redis_protected_mode_and_empty_requirepass_rules_fire_together() {
        let output = analyze("redis.conf", "protected-mode no\nrequirepass \"\"\n");
        assert!(has(&output, "iac.redis.protected-mode-disabled"));
        assert!(has(&output, "iac.redis.empty-password"));
        let secured = analyze(
            "redis.conf",
            "protected-mode yes\nrequirepass S3cure-Passphrase\n",
        );
        assert!(!has(&secured, "iac.redis.protected-mode-disabled"));
        assert!(!has(&secured, "iac.redis.empty-password"));
    }

    #[test]
    fn sshd_rules_flag_each_weak_directive_and_ignore_hardened_values() {
        let weak = analyze(
            "etc/ssh/sshd_config",
            "PermitRootLogin yes\nPasswordAuthentication yes\nProtocol 1\nPermitEmptyPasswords yes\n",
        );
        assert!(has(&weak, "iac.sshd.root-login-permitted"));
        assert!(has(&weak, "iac.sshd.password-authentication"));
        assert!(has(&weak, "iac.sshd.protocol-version-1"));
        assert!(has(&weak, "iac.sshd.empty-passwords-permitted"));
        let hardened = analyze(
            "etc/ssh/sshd_config",
            "# PermitRootLogin yes\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nProtocol 2\nPermitEmptyPasswords no\n",
        );
        assert!(!has(&hardened, "iac.sshd.root-login-permitted"));
        assert!(!has(&hardened, "iac.sshd.password-authentication"));
        assert!(!has(&hardened, "iac.sshd.protocol-version-1"));
        assert!(!has(&hardened, "iac.sshd.empty-passwords-permitted"));
    }

    #[test]
    fn commented_service_config_directives_are_ignored() {
        let commented = analyze(
            "nginx.conf",
            "# ssl_protocols SSLv3;\n# server_tokens on;\n",
        );
        assert!(!has(&commented, "iac.nginx.weak-tls-protocol"));
        assert!(!has(&commented, "iac.nginx.server-tokens"));
        let pg = analyze("pg_hba.conf", "# local all all trust\n");
        assert!(!has(&pg, "iac.pg-hba.trust-authentication"));
    }

    #[test]
    fn service_config_routing_requires_known_filenames() {
        assert!(has(
            &analyze("myapp.conf", "ServerTokens Full\n"),
            "iac.apache.server-tokens"
        ));
        assert!(!has(
            &analyze("notes.txt", "ServerTokens Full\n"),
            "iac.apache.server-tokens"
        ));
        assert!(!has(
            &analyze("app.conf", "protected-mode no\n"),
            "iac.redis.protected-mode-disabled"
        ));
        assert!(has(
            &analyze("redis.conf", "protected-mode no\n"),
            "iac.redis.protected-mode-disabled"
        ));
    }

    #[test]
    fn service_config_files_in_nested_directories_are_scanned() {
        let directory = tempdir().unwrap();
        let nginx_dir = directory.path().join("etc").join("nginx");
        fs::create_dir_all(&nginx_dir).unwrap();
        fs::write(
            nginx_dir.join("nginx.default.conf"),
            "ssl_protocols TLSv1;\n",
        )
        .unwrap();
        let ssh_dir = directory.path().join("etc").join("ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("sshd_config"), "PasswordAuthentication yes\n").unwrap();
        let output = scan_path(
            directory.path(),
            &asset(),
            &ScannerConfig::default(),
            &MalwareSignatures::default(),
        )
        .unwrap();
        assert!(has(&output, "iac.nginx.weak-tls-protocol"));
        assert!(has(&output, "iac.sshd.password-authentication"));
    }

    #[test]
    fn python_weak_hash_calls_are_flagged_with_safe_negative() {
        let output = analyze(
            "x.py",
            "digest = hashlib.md5(payload)\nlegacy = hashlib.sha1(payload)\n",
        );
        assert!(has(&output, "sast.python.weak-hash-md5"));
        assert!(has(&output, "sast.python.weak-hash-sha1"));
        let modern = analyze("x.py", "modern = hashlib.sha256(payload)");
        assert!(!has(&modern, "sast.python.weak-hash-md5"));
        assert!(!has(&modern, "sast.python.weak-hash-sha1"));
    }

    #[test]
    fn javascript_createhash_flags_only_weak_algorithms() {
        let output = analyze(
            "x.js",
            "const a = createHash('md5');\nconst b = createHash(\"sha1\");\n",
        );
        let count = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.weak-hash")
            .count();
        assert_eq!(count, 2);
        assert!(!has(
            &analyze("x.ts", "const h = createHash('sha256');"),
            "sast.javascript.weak-hash"
        ));
    }

    #[test]
    fn go_weak_hash_constructors_are_flagged() {
        let output = analyze("x.go", "h := md5.New()\ns := sha1.New()\n");
        assert!(has(&output, "sast.go.weak-hash-md5"));
        assert!(has(&output, "sast.go.weak-hash-sha1"));
        let modern = analyze("x.go", "h := sha256.New()");
        assert!(!has(&modern, "sast.go.weak-hash-md5"));
        assert!(!has(&modern, "sast.go.weak-hash-sha1"));
    }

    #[test]
    fn java_message_digest_flags_weak_instances_only() {
        let output = analyze(
            "X.java",
            "MessageDigest a = MessageDigest.getInstance(\"MD5\");\nMessageDigest b = MessageDigest.getInstance(\"SHA-1\");\n",
        );
        assert!(has(&output, "sast.java.weak-hash"));
        assert!(!has(
            &analyze(
                "X.java",
                "MessageDigest d = MessageDigest.getInstance(\"SHA-256\");"
            ),
            "sast.java.weak-hash"
        ));
    }

    #[test]
    fn csharp_weak_hash_factories_are_flagged() {
        let output = analyze("X.cs", "var a = MD5.Create();\nvar b = SHA1.Create();\n");
        let count = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.csharp.weak-hash")
            .count();
        assert_eq!(count, 2);
        assert!(!has(
            &analyze("X.cs", "var h = SHA256.Create();"),
            "sast.csharp.weak-hash"
        ));
    }

    #[test]
    fn rust_weak_hash_constructors_are_flagged() {
        let output = analyze(
            "x.rs",
            "let mut h = Md5::new();\nlet mut s = Sha1::new();\n",
        );
        assert!(has(&output, "sast.rust.weak-hash-md5"));
        assert!(has(&output, "sast.rust.weak-hash-sha1"));
        let modern = analyze("x.rs", "let mut h = Sha256::new();");
        assert!(!has(&modern, "sast.rust.weak-hash-md5"));
        assert!(!has(&modern, "sast.rust.weak-hash-sha1"));
    }

    #[test]
    fn python_pickle_deserialization_is_flagged() {
        assert!(has(
            &analyze("x.py", "obj = pickle.loads(blob)"),
            "sast.python.pickle-deserialization"
        ));
        assert!(!has(
            &analyze("x.py", "text = json.loads(blob)"),
            "sast.python.pickle-deserialization"
        ));
    }

    #[test]
    fn python_yaml_load_requires_restricted_loader() {
        assert!(has(
            &analyze("x.py", "cfg = yaml.load(doc)"),
            "sast.python.yaml-unsafe-load"
        ));
        assert!(!has(
            &analyze("x.py", "cfg = yaml.load(doc, Loader=yaml.SafeLoader)"),
            "sast.python.yaml-unsafe-load"
        ));
        assert!(!has(
            &analyze(
                "x.py",
                "cfg = yaml.load(read(path), Loader=yaml.SafeLoader)"
            ),
            "sast.python.yaml-unsafe-load"
        ));
        assert!(!has(
            &analyze("x.py", "safe = yaml.safe_load(doc)"),
            "sast.python.yaml-unsafe-load"
        ));
    }

    #[test]
    fn java_objectinputstream_readobject_chain_is_flagged() {
        assert!(has(
            &analyze(
                "X.java",
                "Object o = new ObjectInputStream(in).readObject();"
            ),
            "sast.java.unsafe-deserialization"
        ));
        assert!(!has(
            &analyze(
                "X.java",
                "ObjectInputStream stream = new ObjectInputStream(in);"
            ),
            "sast.java.unsafe-deserialization"
        ));
    }

    #[test]
    fn csharp_binaryformatter_deserialize_chain_is_flagged() {
        assert!(has(
            &analyze(
                "X.cs",
                "var graph = ((BinaryFormatter)new BinaryFormatter()).Deserialize(stream);"
            ),
            "sast.csharp.unsafe-deserialization"
        ));
        assert!(!has(
            &analyze("X.cs", "var model = serializer.Deserialize(stream);"),
            "sast.csharp.unsafe-deserialization"
        ));
    }

    #[test]
    fn sast_weak_hash_evidence_is_redacted_and_commented_code_ignored() {
        let output = analyze(
            "x.js",
            "const h = createHash('md5').update(secret).digest('hex');",
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "sast.javascript.weak-hash")
            .unwrap();
        assert!(finding.evidence.iter().next().unwrap().redacted);
        assert!(!has(
            &analyze("x.js", "// const h = createHash('md5');"),
            "sast.javascript.weak-hash"
        ));
        assert!(!has(
            &analyze("x.py", "# digest = hashlib.md5(x)"),
            "sast.python.weak-hash-md5"
        ));
    }

    #[test]
    fn recursive_scan_honors_size_file_and_symlink_bounds() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("a.py"), "eval(user_input)").unwrap();
        fs::write(directory.path().join("b.py"), vec![b'x'; 64]).unwrap();
        let config = ScannerConfig {
            max_file_bytes: 32,
            max_files: 1,
            ..ScannerConfig::default()
        };
        let output = scan_path(
            directory.path(),
            &asset(),
            &config,
            &MalwareSignatures::default(),
        )
        .unwrap();
        assert_eq!(output.scanned_files, 1);
        assert!(output.skipped_files >= 1);
        assert!(output.scanned_bytes <= 32);
    }

    #[test]
    fn parallel_file_analysis_preserves_deterministic_bounds_and_output() {
        let directory = tempdir().unwrap();
        for index in 0..40 {
            fs::write(
                directory.path().join(format!("source-{index:02}.py")),
                format!("eval(user_input)\npassword = \"replace_me_please\"\n# {index}\n"),
            )
            .unwrap();
        }
        let config = ScannerConfig {
            max_file_bytes: 1_024,
            max_total_bytes: 100_000,
            max_files: 32,
            ..ScannerConfig::default()
        };
        let first = scan_path(
            directory.path(),
            &asset(),
            &config,
            &MalwareSignatures::default(),
        )
        .unwrap();
        let second = scan_path(
            directory.path(),
            &asset(),
            &config,
            &MalwareSignatures::default(),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.scanned_files, 32);
        assert_eq!(first.skipped_files, 1);
        assert!(
            first
                .findings
                .windows(2)
                .all(|pair| pair[0].id <= pair[1].id)
        );
    }

    #[test]
    fn handle_bound_reader_rejects_growth_past_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("growing");
        fs::write(&path, vec![b'x'; 33]).unwrap();
        let file = File::open(&path).unwrap();
        assert!(read_file_bounded(file, &path, 32).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_reader_rejects_symlink_handle_open() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, b"contents").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_path_bounded(&link, 32, false).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_root_is_skipped_by_default() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.py");
        let link = directory.path().join("link.py");
        fs::write(&target, "eval(user_input)").unwrap();
        symlink(&target, &link).unwrap();
        let output = scan_path(
            &link,
            &asset(),
            &ScannerConfig::default(),
            &MalwareSignatures::default(),
        )
        .unwrap();
        assert_eq!(output.scanned_files, 0);
        assert_eq!(output.skipped_files, 1);
    }

    #[test]
    fn findings_have_stable_ids_locations_cwe_and_references() {
        let first = analyze("x.py", "eval(user_input)");
        let second = analyze("x.py", "eval(user_input)");
        assert_eq!(first.findings, second.findings);
        let finding = &first.findings[0];
        assert!(finding.location_id.is_some());
        assert!(finding.aliases.contains("CWE-95"));
        assert!(
            !finding
                .evidence
                .iter()
                .next()
                .unwrap()
                .references
                .is_empty()
        );
    }

    #[test]
    fn signature_database_rejects_noncanonical_input() {
        let signatures = MalwareSignatures {
            sha256: BTreeMap::from([("ABC".to_owned(), "bad".to_owned())]),
        };
        assert!(matches!(
            signatures.validate(),
            Err(ScanError::InvalidSignatureDigest(_))
        ));
    }
}
