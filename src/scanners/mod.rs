use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zip::ZipArchive;

use crate::filesystem::repository_walk;
use crate::model::{
    Applicability, ApplicabilityStatus, AssetId, Confidence, Evidence, Finding, FindingKind,
    FindingStatus, Location, Position, Remediation, Risk, RuleId, Severity, stable_finding_id,
    stable_location_id,
};
use crate::util::{jsonc_to_json, sha256_hex};

mod sast;
mod service_config;
mod spans;

use sast::scan_sast;
#[cfg(test)]
use sast::yaml_call_specifies_loader;
use service_config::scan_service_config;

const ARCHIVE_RATIO_LIMIT: u64 = 100;
const ARCHIVE_ENTRY_SIZE_LIMIT: u64 = 512 * 1024 * 1024;
const PARALLEL_MIN_FILES: usize = 32;
const PARALLEL_MIN_BYTES: u64 = 16 * 1024 * 1024;

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
    /// Files rejected during admission; a LOWER BOUND once the walk's max_files cap trips (surplus entries are never enumerated).
    pub skipped_files: usize,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("cannot inspect '{path}'")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read '{path}'")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem traversal failed at '{path}'")]
    Walk {
        path: PathBuf,
        #[source]
        source: ignore::Error,
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
    let ctx = ScanContext {
        asset_id,
        config,
        signatures,
    };
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
    let mut walk_skipped = 0_usize;
    if metadata.is_file() || (metadata.file_type().is_symlink() && config.follow_symlinks) {
        paths.push(root.to_owned());
    } else if metadata.is_dir() {
        for entry in repository_walk(root, config.follow_symlinks, Some(config.max_depth)) {
            // A single unreadable directory entry must not abort the scan:
            // it degrades to a skipped file like an unreadable regular file.
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    walk_skipped += 1;
                    continue;
                }
            };
            if entry.file_type().is_some_and(|kind| kind.is_file()) {
                paths.push(entry.into_path());
                if paths.len() > config.max_files {
                    // Sentinel early-exit stops enumeration at the cap; skipped_files is therefore only a lower bound past this point.
                    break;
                }
            }
        }
    } else {
        return Err(ScanError::UnsupportedRoot(root.to_owned()));
    }
    paths.sort();

    let mut output = ScanOutput {
        skipped_files: walk_skipped,
        ..ScanOutput::default()
    };
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
        // Oversized, vanished, or unreadable files count as skipped rather
        // than failing the whole scan.
        let bytes = match read_path_bounded(&path, limit, config.follow_symlinks) {
            Ok(Some(bytes)) => bytes,
            Ok(None) | Err(_) => {
                output.skipped_files += 1;
                continue;
            }
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
        if admitted.len() >= PARALLEL_MIN_FILES || admitted_bytes >= PARALLEL_MIN_BYTES {
            analyze_admitted(&mut admitted, admitted_bytes, &mut output, &ctx);
            admitted_bytes = 0;
        }
    }
    analyze_admitted(&mut admitted, admitted_bytes, &mut output, &ctx);
    output
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(output)
}

fn analyze_admitted(
    admitted: &mut Vec<(String, Vec<u8>)>,
    admitted_bytes: u64,
    output: &mut ScanOutput,
    ctx: &ScanContext<'_>,
) {
    if admitted.is_empty() {
        return;
    }
    let batch = std::mem::take(admitted);
    let analyzed: Vec<_> =
        if batch.len() >= PARALLEL_MIN_FILES || admitted_bytes >= PARALLEL_MIN_BYTES {
            batch
                .par_iter()
                .map(|(path, bytes)| analyze_file(path, bytes, ctx))
                .collect()
        } else {
            batch
                .iter()
                .map(|(path, bytes)| analyze_file(path, bytes, ctx))
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
    analyze_file(
        path,
        bytes,
        &ScanContext {
            asset_id,
            config,
            signatures,
        },
    )
}

fn analyze_file(path: &str, bytes: &[u8], ctx: &ScanContext<'_>) -> ScanOutput {
    let mut builder = FindingBuilder::new(path, ctx);
    scan_malware(bytes, &mut builder);
    if let Some(text) = decode_text(bytes) {
        scan_secrets(text, &mut builder);
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

/// Per-scan context threaded through the scanner pipeline; built once per
/// file (and once per scan run for batches) instead of passing the
/// asset/config/signature trio as loose positional parameters everywhere.
struct ScanContext<'a> {
    asset_id: &'a AssetId,
    config: &'a ScannerConfig,
    signatures: &'a MalwareSignatures,
}

struct FindingBuilder<'a> {
    path: &'a str,
    ctx: &'a ScanContext<'a>,
    locations: BTreeSet<Location>,
    findings: Vec<Finding>,
}

impl<'a> FindingBuilder<'a> {
    fn new(path: &'a str, ctx: &'a ScanContext<'a>) -> Self {
        Self {
            path,
            ctx,
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
        // An empty path (only reachable through the `analyze_bytes` library
        // entry point) cannot form a location id; the finding still reports
        // without a location instead of panicking.
        let location_id = stable_location_id(self.ctx.asset_id, self.path, Some(start)).ok();
        if let Some(location_id) = &location_id {
            self.locations.insert(Location {
                id: location_id.clone(),
                asset_id: self.ctx.asset_id.clone(),
                path: self.path.to_owned(),
                start: Some(start),
                end: None,
            });
        }
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
            locations: location_id.iter().cloned().collect(),
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
            id: stable_finding_id(kind, &rule_id, None, location_id.as_ref()),
            kind,
            rule_id,
            advisory_id: None,
            component_id: None,
            location_id,
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
    // A NUL anywhere marks binary content; scanning the whole buffer is a
    // single linear pass and keeps the gate consistent for files whose
    // binary payload starts past any prefix window.
    if bytes.contains(&0) {
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
            r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            "AWS access key ID",
            Severity::High,
        ),
        (
            "secret.github-token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            "GitHub token",
            Severity::Critical,
        ),
        (
            "secret.gitlab-token",
            r"\b(?:glpat|glrt|gldt|glft|glagent|glcbt|glptt|glsoat|glff|gloas)-[A-Za-z0-9_-]{20,}\b",
            "GitLab token",
            Severity::Critical,
        ),
        (
            "secret.slack-token",
            r"\b(?:xox[baprs]|xapp|xoxe(?:\.xoxp)?|xoxc|xoxd)-[A-Za-z0-9-]{20,}\b",
            "Slack token",
            Severity::Critical,
        ),
        (
            "secret.private-key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
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
    // The optional `["']?` accepts JSON quoted keys ("password": "..."), and
    // the separator-delimited prefix/suffix segments accept compound names
    // (SECRET_KEY, DB_PASSWORD, API_SECRET) without lookarounds, which the
    // regex crate does not support. Unseparated words like "tokenize" or
    // "tokens" still do not match; concatenated names like "secretkey" do.
    // Values may be double-quoted, single-quoted, or unquoted (`.env` and
    // shell exports); each quoted alternative permits the other quote kind
    // inside the value.
    Regex::new(
        r#"(?i)\b((?:[a-z0-9]+[_-])?(?:api[_-]?key|secret[_-]?key|client[_-]?secret|secret|token|password|passwd)(?:[_-][a-z0-9]+)*)\b\s*["']?\s*[:=]\s*(?:"([^"]{12,256})"|'([^']{12,256})'|([^\s"']{12,256}))"#,
    )
    .expect("constant assignment regex")
});

fn scan_secrets(text: &str, builder: &mut FindingBuilder<'_>) {
    let package_script_values: BTreeSet<String> = if Path::new(builder.path)
        .file_name()
        .is_some_and(|name| name == "package.json")
    {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|document| {
                document
                    .get("scripts")
                    .and_then(|scripts| scripts.as_object())
                    .cloned()
            })
            .into_iter()
            .flatten()
            .filter_map(|(_, value)| value.as_str().map(str::to_owned))
            .collect()
    } else {
        BTreeSet::new()
    };
    let line_starts = line_starts(text);
    // PEM END markers are indexed once per file so a marker-heavy file stays
    // linear: each BEGIN match binary-searches this table instead of scanning
    // to EOF for a terminator that may not exist.
    let mut pem_end_offsets: Option<Vec<usize>> = None;
    for (line_index, line) in text.lines().enumerate() {
        // Long lines (minified bundles, single-line dumps) are scanned like
        // any other: every rule is a linear-time regex with bounded captures,
        // so skipping them would silently hide leaked credentials.
        if allowlisted(line) {
            continue;
        }
        let line_offset = line_starts[line_index];
        for secret_rule in SECRET_RULES.iter() {
            for matched in secret_rule.regex.find_iter(line) {
                // The private-key rule matches only the BEGIN marker line;
                // evidence must cover the whole PEM block so fingerprints
                // discriminate between distinct keys, and blocks without a
                // plausible base64 body (placeholders, redactions, truncated
                // markers) are not secrets at all.
                let value = if secret_rule.rule == "secret.private-key" {
                    let end_offsets = pem_end_offsets.get_or_insert_with(|| {
                        text.match_indices("-----END ")
                            .map(|(offset, _)| offset)
                            .collect()
                    });
                    let Some(block) = pem_block(text, line_offset + matched.start(), end_offsets)
                    else {
                        continue;
                    };
                    block
                } else {
                    Cow::Borrowed(matched.as_str())
                };
                let value = value.as_ref();
                let entropy = shannon_entropy(value) * 1000.0;
                if looks_placeholder(value)
                    || entropy < f64::from(builder.ctx.config.secret_entropy_threshold_milli)
                {
                    continue;
                }
                let site = SecretSite {
                    label: secret_rule.label,
                    severity: secret_rule.severity,
                    line: line_index,
                    column: matched.start(),
                    value,
                    entropy_milli: entropy.round() as u64,
                };
                add_secret(builder, secret_rule.rule, site);
            }
        }
        for captures in SECRET_ASSIGNMENT_REGEX.captures_iter(line) {
            let assignment = captures.get(0).expect("capture exists");
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .or_else(|| captures.get(4))
                .expect("value capture exists");
            if assignment.start() > 0
                && line.as_bytes()[assignment.start() - 1] == b':'
                && package_script_values.contains(value.as_str())
            {
                continue;
            }
            let name = captures
                .get(1)
                .expect("capture exists")
                .as_str()
                .to_ascii_lowercase();
            if name.ends_with("_hash") || name.ends_with("-hash") {
                continue;
            }
            let entropy = shannon_entropy(value.as_str()) * 1000.0;
            if looks_self_referential(&name, value.as_str())
                || looks_placeholder(value.as_str())
                || looks_like_noncredential_assignment(value.as_str())
                || (name_suggests_reference(&name)
                    && looks_like_namespaced_reference(value.as_str()))
                || entropy < f64::from(builder.ctx.config.secret_entropy_threshold_milli)
            {
                continue;
            }
            let site = SecretSite {
                label: "high-entropy credential assignment",
                severity: Severity::High,
                line: line_index,
                column: value.start(),
                value: value.as_str(),
                entropy_milli: entropy.round() as u64,
            };
            add_secret(builder, "secret.high-entropy-assignment", site);
        }
    }
}

/// Returns the complete `-----BEGIN …-----` … `-----END …-----` PEM block
/// starting at `begin_offset`, but only when the body between the markers is
/// plausible base64 key material. Placeholder bodies (`<REDACTED…>`, `…`,
/// `XXXX`, empty) and marker-only fragments return `None` so they never
/// produce a finding. `end_offsets` is the pre-indexed table of every
/// `-----END ` occurrence in `text`; the first entry at or after the body
/// start is the only candidate terminator, so malformed marker runs cannot
/// force a scan to EOF.
fn pem_block<'a>(
    text: &'a str,
    begin_offset: usize,
    end_offsets: &[usize],
) -> Option<Cow<'a, str>> {
    const PEM_LABEL_MAX_BYTES: usize = 128;
    let block = text.get(begin_offset..)?;
    let label_start = "-----BEGIN ".len();
    let label_end = label_start
        + block
            .get(label_start..label_start + PEM_LABEL_MAX_BYTES)?
            .find("-----")?;
    let body_start = label_end + 5;
    let end_start = *end_offsets.get(end_offsets.partition_point(|offset| *offset < body_start))?;
    if end_start < body_start {
        return None;
    }
    let end_label_start = end_start.checked_sub(begin_offset)? + "-----END ".len();
    let end_label_end = end_label_start
        + block
            .get(end_label_start..end_label_start + PEM_LABEL_MAX_BYTES)?
            .find("-----")?;
    if block[label_start..label_end] != block[end_label_start..end_label_end] {
        return None;
    }
    let block = &block[..end_label_end + 5];
    // Only PEM newline escapes are decoded, not arbitrary host-language escapes.
    // Ordinary raw PEMs remain borrowed, preserving their existing fingerprints.
    let normalized = if block.as_bytes().contains(&b'\\') {
        let mut normalized = String::with_capacity(block.len());
        let mut chars = block.chars();
        while let Some(ch) = chars.next() {
            normalized.push(if ch == '\\' {
                match chars.next()? {
                    'n' => '\n',
                    'r' => '\r',
                    _ => return None,
                }
            } else {
                ch
            });
        }
        Cow::Owned(normalized)
    } else {
        Cow::Borrowed(block)
    };
    let body_end = normalized.len() - (block.len() - (end_start - begin_offset));
    let body = &normalized[body_start..body_end];
    if !(body.starts_with('\n') || body.starts_with("\r\n")) {
        return None;
    }
    plausible_pem_body(body).then_some(normalized)
}

/// A PEM body is plausible key material when it is a run of base64 characters
/// (whitespace between wrapped lines allowed) long and diverse enough to be a
/// real key rather than a placeholder like `XXXX…` or `AAAA…`. Legacy
/// encrypted PEMs prepend `Proc-Type:`/`DEK-Info:` header lines before the
/// base64 body (RFC 1421); a leading run of `Name: value` header lines is
/// stripped before the base64 check so real encrypted keys are not rejected.
fn plausible_pem_body(body: &str) -> bool {
    let mut rest = body;
    loop {
        let line = rest.split('\n').next().unwrap_or("");
        let trimmed = line.trim_end_matches(['\r', ' ', '\t']);
        if trimmed.is_empty() {
            rest = &rest[line.len()..];
            rest = rest.strip_prefix('\n').unwrap_or(rest);
            continue;
        }
        let is_header = trimmed.split_once(':').is_some_and(|(name, _)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
        if !is_header {
            break;
        }
        rest = &rest[line.len()..];
        rest = rest.strip_prefix('\n').unwrap_or(rest);
    }
    let mut length = 0;
    let mut alphabet = [false; 128];
    let mut distinct = 0;
    for byte in rest.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')) {
            return false;
        }
        length += 1;
        if !alphabet[usize::from(byte)] {
            alphabet[usize::from(byte)] = true;
            distinct += 1;
        }
    }
    length >= 16 && distinct >= 5
}

struct SecretSite<'a> {
    label: &'a str,
    severity: Severity,
    line: usize,
    column: usize,
    value: &'a str,
    entropy_milli: u64,
}
fn add_secret(builder: &mut FindingBuilder<'_>, rule: &str, site: SecretSite<'_>) {
    let SecretSite {
        label,
        severity,
        line,
        column,
        value,
        entropy_milli,
    } = site;
    let mut properties = BTreeMap::new();
    properties.insert(
        "fingerprint_sha256".to_owned(),
        sha256_hex(value.as_bytes()),
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
        references: &["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        properties,
        redacted: true,
        remediation: "Revoke and rotate the credential, remove it from source and history, and load its replacement from an approved secret manager.",
        cwe: Some("CWE-798"),
    });
}

static SECRET_ALLOWLIST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // `nosec` must appear as a standalone marker (word boundary on both
    // sides, digits allowed for rule ids like `nosec B602`); a credential
    // value that merely contains the substring must not suppress itself.
    Regex::new(
        r"(?i)(?:hooray:allow-secret|pragma: allowlist secret|gitleaks:allow|(?:^|[^A-Za-z0-9_])nosec(?:[^A-Za-z]|$))",
    )
    .expect("constant secret allowlist regex")
});

fn allowlisted(line: &str) -> bool {
    SECRET_ALLOWLIST_REGEX.is_match(line)
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
        "redacted",
        "your_",
        "<",
        "${",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || value.chars().collect::<BTreeSet<_>>().len() < 5
        || looks_sequential_or_repeated(value)
        || looks_like_pattern(value)
}

/// These shapes belong only to the generic entropy heuristic. Specific token
/// signatures still run even when an assignment's value resembles vocabulary.
fn looks_like_noncredential_assignment(value: &str) -> bool {
    let bytes = value.as_bytes();
    let uuid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    let query_key = value
        .strip_prefix(['&', '?'])
        .and_then(|fragment| fragment.strip_suffix('='))
        .is_some_and(|key| {
            !key.is_empty()
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
    let protocol_prefix = value.strip_suffix('.').is_some_and(|prefix| {
        let mut words = prefix.split('.');
        matches!(words.next(), Some("base64" | "base64url"))
            && words.next() == Some("bearer")
            && words.all(|word| {
                !word.is_empty() && word.len() <= 16 && word.bytes().all(|b| b.is_ascii_lowercase())
            })
    });
    let mut words = value.split_ascii_whitespace();
    let placeholder_phrase = matches!(words.next(), Some("new" | "old" | "current" | "test"))
        && matches!(words.next(), Some("valid" | "invalid" | "test"))
        && matches!(words.next(), Some("password" | "token" | "secret"))
        && words.next().is_none();
    uuid || query_key || protocol_prefix || placeholder_phrase
}

/// Detects sequential (`0123456789abcdef`, `abcdef`, `zyxwv`) and repeated
/// (`abababab`, `abcabc`) dummy values: real credentials are never sorted or
/// periodic, so these shapes are documentation/test constants.
fn looks_sequential_or_repeated(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_sorted() || bytes.is_sorted_by(|left, right| left >= right) {
        return true;
    }
    (1..=bytes.len() / 2)
        .filter(|period| bytes.len().is_multiple_of(*period))
        .any(|period| bytes.chunks(period).all(|chunk| chunk == &bytes[..period]))
}

/// Detects Kubernetes `namespace/name` object references such as
/// `default/other-demo-secret`: two RFC 1123-style labels joined by a single
/// slash. These are pointers to a secret object, not secret material. The
/// shape alone is ambiguous (`admin/panel123` is a real credential), so it
/// only suppresses when `name_suggests_reference` marks the assignment key
/// as a reference-style field.
fn looks_like_namespaced_reference(value: &str) -> bool {
    let mut parts = value.split('/');
    let (Some(namespace), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [namespace, name].iter().all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            })
            && part
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && part
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
    })
}

/// Whether an assignment key names a reference rather than the credential
/// itself (`secret_name`, `token_ref`, `password_name`): only then may a
/// `namespace/name` value be treated as an object pointer.
fn name_suggests_reference(name: &str) -> bool {
    let normalized = name.replace('-', "_");
    normalized.ends_with("_name") || normalized.ends_with("_ref")
}

/// Detects values that merely restate the assignment key as vocabulary, such
/// as the Android autofill hint `'password': 'current-password'` or
/// `token = "api_token"`. An exact restatement always suppresses; a longer
/// value suppresses only when every word belongs to credential vocabulary —
/// `token_value` or `secret-key` carry real (if weak) credential material
/// and must flag.
fn looks_self_referential(name: &str, value: &str) -> bool {
    const CREDENTIAL_VOCABULARY: &[&str] = &[
        "api", "auth", "current", "new", "old", "pass", "passwd", "password", "secret", "token",
        "user",
    ];
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    let normalized_name = name.replace(['-', '_'], "");
    let normalized_value = value.replace(['-', '_'], "");
    if normalized_name.is_empty() {
        return false;
    }
    if normalized_value == normalized_name {
        return true;
    }
    normalized_value.len() > normalized_name.len()
        && normalized_value.contains(&normalized_name)
        && value
            .split(['-', '_'])
            .all(|word| CREDENTIAL_VOCABULARY.contains(&word))
}

/// Detects values that are pattern definitions rather than credential text:
/// regex literals such as `/ghp_[A-Za-z0-9]{36}/` or
/// `{^([a-f0-9]{12,}|gh[a-z]_[a-zA-Z0-9_.-]+)$}` describe a token format and
/// are not secrets themselves. A single strong metacharacter signal (a
/// ranged/negated character class, a counted quantifier, or a parenthesized
/// alternation) marks a pattern; weaker signals (regex escapes like `\d`,
/// `/…/` delimiter wrapping, `^`/`$` anchors) must appear in pairs so plain
/// secrets containing one stray metacharacter still flag.
fn looks_like_pattern(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut strong = false;
    let mut weak = 0_u8;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if bytes
                    .get(i + 1)
                    .is_some_and(|b| b"dDwWsSbBzZAZG".contains(b))
                {
                    weak = weak.saturating_add(1);
                }
                i += 2;
                continue;
            }
            b'[' => {
                let mut j = i + 1;
                if bytes.get(j) == Some(&b'^') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j] != b']' {
                    j += 1;
                }
                if j < bytes.len() && j > i + 1 {
                    // A class whose body carries a range or negation is
                    // pattern syntax; a bare "[ab]" is too common in literal
                    // text to count on its own.
                    if bytes[i + 1] == b'^' || bytes[i + 1..j].contains(&b'-') {
                        strong = true;
                    }
                }
                i = j + 1;
                continue;
            }
            b'{' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'}' {
                    j += 1;
                }
                if j < bytes.len()
                    && bytes[i + 1..j]
                        .iter()
                        .all(|b| b.is_ascii_digit() || *b == b',')
                    && bytes[i + 1..j].iter().any(|b| b.is_ascii_digit())
                {
                    strong = true;
                }
                i = j + 1;
                continue;
            }
            b'(' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b')' {
                    j += 1;
                }
                if j < bytes.len() && bytes[i + 1..j].contains(&b'|') {
                    strong = true;
                }
                i = j + 1;
                continue;
            }
            _ => i += 1,
        }
    }
    if value.len() >= 3 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && matches!(first, b'/' | b'#' | b'~') {
            weak = weak.saturating_add(1);
        }
        if (bytes[0] == b'^' || bytes[0] == b'$') || (last == b'^' || last == b'$') {
            weak = weak.saturating_add(1);
        }
    }
    strong || weak >= 2
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
    // Terraform JSON (`.tf.json`) is HCL's JSON dialect: it needs the
    // Terraform checks, not the Kubernetes/CloudFormation structured scan.
    if name.ends_with(".tf.json") {
        scan_terraform_json(text, builder);
    }
    // `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, and Podman's
    // `Containerfile*` all carry Dockerfile syntax.
    if name == "dockerfile"
        || name.starts_with("dockerfile.")
        || name.ends_with(".dockerfile")
        || name == "containerfile"
        || name.starts_with("containerfile.")
    {
        scan_dockerfile(text, builder);
    }
    if matches!(extension.as_str(), "yaml" | "yml" | "json") && !name.ends_with(".tf.json") {
        scan_structured_iac(text, &extension, builder);
    }
}

static TERRAFORM_PUBLIC_CIDR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Singular and plural CIDR attributes (aws_route's
    // destination_cidr_block, security-group cidr_blocks/ipv6_cidr_blocks),
    // quoted or bare scalars, and list elements. `[^\]=]*` keeps the match
    // inside one attribute value across wrapped lists.
    Regex::new(
        r#"(?m)^[ \t]*(?:destination_)?(?:ipv6_)?cidr_blocks?\s*=\s*(?:[^\]=]*["'\s,\[]|\s*)(?:0\.0\.0\.0/0|::/0)\b"#,
    )
    .expect("constant Terraform public CIDR regex")
});

static TERRAFORM_UNENCRYPTED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(encrypted|storage_encrypted)\s*=\s*false\b")
        .expect("constant Terraform encryption regex")
});

/// Sorted `(byte offset, suppressed)` breakpoints marking where Terraform
/// text enters or leaves an `egress { … }` block, a `resource` block carrying
/// `type = "egress"`, or a heredoc body. A match is suppressed when the last
/// breakpoint at or before its start reports `true`, so single-line blocks
/// are handled at byte precision rather than by line.
fn terraform_suppression_breaks(text: &str) -> Vec<(usize, bool)> {
    enum Frame {
        /// A block whose label is not egress-related.
        Other,
        /// An `egress { … }` block (including `dynamic "egress"`).
        Egress,
        /// A `resource "…" "…"` block; suppressed once `type = "egress"`
        /// appears at its top level.
        Resource { egress: bool },
    }
    fn suppressed(stack: &[Frame]) -> bool {
        stack.iter().any(|frame| match frame {
            Frame::Egress => true,
            Frame::Resource { egress } => *egress,
            Frame::Other => false,
        })
    }
    let mut breaks = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut heredoc_terminator: Option<String> = None;
    let starts = line_starts(text);
    for (index, line) in text.lines().enumerate() {
        let offset = starts[index];
        if let Some(terminator) = &heredoc_terminator {
            breaks.push((offset, true));
            if line.trim() == terminator.as_str() {
                heredoc_terminator = None;
            }
            continue;
        }
        // Truncate at the first comment opener outside quotes so commented
        // braces and attributes cannot corrupt block tracking or match.
        let mut code_end = line.len();
        let mut quote = false;
        for (at, byte) in line.bytes().enumerate() {
            if byte == b'"' {
                quote = !quote;
            } else if !quote
                && (byte == b'#' || (byte == b'/' && line.as_bytes().get(at + 1) == Some(&b'/')))
            {
                code_end = at;
                break;
            }
        }
        let code = &line[..code_end];
        if let Some(marker) = code.find("<<").and_then(|at| {
            let rest = code[at + 2..].trim_start_matches('-').trim_start();
            let end = rest
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(rest.len());
            (end > 0).then(|| rest[..end].to_owned())
        }) {
            heredoc_terminator = Some(marker);
        }
        // Walk the line in byte order: block opens/closes (outside string
        // literals) update the frame stack, and a `type = "egress"`
        // attribute flips the innermost resource frame. The block label is
        // the first identifier of the statement segment ending at the
        // brace, so `resource "aws_security_group" "x" {` reads `resource`.
        let mut quoted_ranges: Vec<(usize, usize)> = Vec::new();
        let mut quote_start = 0_usize;
        let mut quote = false;
        let mut escaped = false;
        for (at, byte) in code.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' if quote => escaped = true,
                b'"' => {
                    if quote {
                        quoted_ranges.push((quote_start, at + 1));
                    } else {
                        quote_start = at;
                    }
                    quote = !quote;
                }
                _ => {}
            }
        }
        let in_string = |at: usize| {
            quoted_ranges
                .iter()
                .any(|(start, end)| *start <= at && at < *end)
        };
        let mut events: Vec<(usize, u8)> = TERRAFORM_EGRESS_TYPE_REGEX
            .find_iter(code)
            .filter(|matched| !in_string(matched.start()))
            .map(|matched| (matched.start(), b't'))
            .collect();
        let mut segment_start = 0_usize;
        let mut quote = false;
        let mut escaped = false;
        for (at, byte) in code.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' if quote => escaped = true,
                b'"' => quote = !quote,
                b'{' | b'}' if !quote => events.push((at, byte)),
                _ => {}
            }
        }
        events.sort_by_key(|(at, _)| *at);
        for (at, byte) in events {
            match byte {
                b'{' => {
                    let segment = &code[segment_start..at];
                    let label = segment
                        .split(|character: char| {
                            !(character.is_ascii_alphanumeric() || character == '_')
                        })
                        .find(|word| !word.is_empty())
                        .unwrap_or("");
                    stack.push(match label {
                        "egress" => Frame::Egress,
                        "resource" => Frame::Resource { egress: false },
                        "dynamic" if segment.contains("\"egress\"") => Frame::Egress,
                        _ => Frame::Other,
                    });
                    breaks.push((offset + at + 1, suppressed(&stack)));
                }
                b'}' => {
                    stack.pop();
                    segment_start = at + 1;
                    breaks.push((offset + at + 1, suppressed(&stack)));
                }
                // A top-level `type = "egress"` attribute marks its
                // enclosing resource (aws_security_group_rule) as an
                // outbound rule.
                _ => {
                    if matches!(stack.last(), Some(Frame::Resource { egress: false })) {
                        if let Some(Frame::Resource { egress }) = stack.last_mut() {
                            *egress = true;
                        }
                        breaks.push((offset + at, true));
                    }
                }
            }
        }
        breaks.push((offset + line.len() + 1, suppressed(&stack)));
    }
    breaks
}

static TERRAFORM_EGRESS_TYPE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\btype\s*=\s*["']?egress["']?\b"#).expect("constant Terraform egress type regex")
});

fn terraform_position_suppressed(breaks: &[(usize, bool)], position: usize) -> bool {
    let index = breaks.partition_point(|(offset, _)| *offset <= position);
    index > 0 && breaks[index - 1].1
}

fn scan_terraform(text: &str, builder: &mut FindingBuilder<'_>) {
    let line_starts = line_starts(text);
    let breaks = terraform_suppression_breaks(text);
    for matched in TERRAFORM_PUBLIC_CIDR_REGEX.find_iter(text) {
        if terraform_position_suppressed(&breaks, matched.start()) {
            continue;
        }
        let (line, column) = indexed_line_column(&line_starts, matched.start());
        builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.terraform.public-ingress", line, column, summary: "Unrestricted Terraform network CIDR", details: "A Terraform network rule explicitly permits the entire IPv4 or IPv6 Internet.", severity: Severity::High, confidence: Confidence::High, description: "Concrete cidr_blocks assignment contains 0.0.0.0/0 or ::/0.".to_owned(), references: &["https://developer.hashicorp.com/terraform/language"], properties: BTreeMap::new(), redacted: false, remediation: "Restrict ingress to the smallest required CIDR ranges and ports.", cwe: Some("CWE-284") });
    }
    for matched in TERRAFORM_UNENCRYPTED_REGEX.find_iter(text) {
        let (line, column) = indexed_line_column(&line_starts, matched.start());
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

/// Terraform JSON dialect (`.tf.json`): the same two checks evaluated on the
/// parsed document so JSON quoting cannot hide open CIDRs or disabled
/// encryption. `egress` objects and `type = "egress"` resources are skipped
/// like their HCL counterparts.
fn scan_terraform_json(text: &str, builder: &mut FindingBuilder<'_>) {
    let parse_text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(document) = serde_json::from_str::<serde_json::Value>(parse_text) else {
        return;
    };
    let line_starts = line_starts(text);
    let index = yaml_path_index(parse_text);
    let location = DocumentLocation {
        text,
        document_offset: text.len() - parse_text.len(),
        index: index.as_ref(),
        line_starts: &line_starts,
    };
    scan_terraform_json_value(&document, "", false, &location, builder);
}

fn scan_terraform_json_value(
    value: &serde_json::Value,
    path: &str,
    in_egress: bool,
    location: &DocumentLocation<'_>,
    builder: &mut FindingBuilder<'_>,
) {
    let object = match value {
        serde_json::Value::Object(object) => object,
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_terraform_json_value(
                    item,
                    &format!("{path}/{index}"),
                    in_egress,
                    location,
                    builder,
                );
            }
            return;
        }
        _ => return,
    };
    let egress_here = in_egress
        || object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("egress"));
    for (key, field) in object {
        let field_path = format!("{path}/{}", pointer_escape(key));
        let key_lower = key.to_ascii_lowercase();
        if matches!(key_lower.as_str(), "egress" | "dynamic") {
            scan_terraform_json_value(field, &field_path, true, location, builder);
            continue;
        }
        let is_cidr_attribute =
            key_lower.ends_with("cidr_block") || key_lower.ends_with("cidr_blocks");
        if is_cidr_attribute && !egress_here && terraform_json_has_open_cidr(field) {
            add_structured_iac(
                builder,
                location,
                StructuredIacRule {
                    path: &field_path,
                    anchor: "",
                    needle: "0.0.0.0/0",
                    rule: "iac.terraform.public-ingress",
                    summary: "Unrestricted Terraform network CIDR",
                    severity: Severity::High,
                    remediation: "Restrict ingress to the smallest required CIDR ranges and ports.",
                    cwe: "CWE-284",
                },
            );
        }
        if matches!(key_lower.as_str(), "encrypted" | "storage_encrypted")
            && field.as_bool() == Some(false)
        {
            add_structured_iac(
                builder,
                location,
                StructuredIacRule {
                    path: &field_path,
                    anchor: "",
                    needle: "false",
                    rule: "iac.terraform.encryption-disabled",
                    summary: "Terraform storage encryption disabled",
                    severity: Severity::High,
                    remediation: "Enable provider-managed or customer-managed encryption for data at rest.",
                    cwe: "CWE-311",
                },
            );
        }
        scan_terraform_json_value(field, &field_path, egress_here, location, builder);
    }
}

fn terraform_json_has_open_cidr(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            matches!(text.trim(), "0.0.0.0/0" | "::/0")
        }
        serde_json::Value::Array(items) => items.iter().any(terraform_json_has_open_cidr),
        _ => false,
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
        "password" | "passwd" | "pass" | "pwd" | "token" | "secret" | "apikey" | "api_key"
    ) || normalized.ends_with("_password")
        || normalized.ends_with("_passwd")
        || normalized.ends_with("_pass")
        || normalized.ends_with("_pwd")
        || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_secret_key")
        || normalized.ends_with("_api_key")
        || normalized.ends_with("_apikey")
        || normalized.ends_with("_access_key")
        || normalized.starts_with("credential")
}

/// Redacts credentials from URLs in a line before it is rendered as IaC
/// evidence: userinfo (`scheme://user:password@host`) and every non-empty
/// query-string value (`?token=…`, `&sig=…`). Scheme, host, path, and query
/// keys stay intact for triage. Only this finding embeds arbitrary remote
/// URLs, so the scrub is scoped here rather than applied to every rendered
/// directive line.
fn redact_url_credentials(line: &str) -> String {
    let mut redacted = String::with_capacity(line.len());
    let mut searched_up_to = 0;
    while let Some(separator) = line[searched_up_to..].find("://") {
        let scheme_end = searched_up_to + separator + 3;
        redacted.push_str(&line[searched_up_to..scheme_end]);
        let url_end = line[scheme_end..]
            .find(char::is_whitespace)
            .map_or(line.len(), |position| scheme_end + position);
        let url = &line[scheme_end..url_end];
        let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let authority = &url[..authority_end];
        match authority.rsplit_once('@') {
            Some((_, host)) => {
                redacted.push_str("[REDACTED]@");
                redacted.push_str(host);
            }
            None => redacted.push_str(authority),
        }
        let rest = &url[authority_end..];
        let fragment_at = rest.find('#').unwrap_or(rest.len());
        let (before_fragment, fragment) = rest.split_at(fragment_at);
        let (path, query) = match before_fragment.find('?') {
            Some(at) => (&before_fragment[..at], &before_fragment[at + 1..]),
            None => (before_fragment, ""),
        };
        redacted.push_str(path);
        if before_fragment.contains('?') {
            redacted.push('?');
            for (index, pair) in query.split('&').enumerate() {
                if index > 0 {
                    redacted.push('&');
                }
                match pair.split_once('=') {
                    Some((key, value)) if !value.is_empty() => {
                        redacted.push_str(key);
                        redacted.push_str("=[REDACTED]");
                    }
                    _ => redacted.push_str(pair),
                }
            }
        }
        redacted.push_str(fragment);
        searched_up_to = url_end;
    }
    redacted.push_str(&line[searched_up_to..]);
    redacted
}

fn scan_dockerfile(text: &str, builder: &mut FindingBuilder<'_>) {
    let mut seen_from = false;
    let mut final_stage_line = 1;
    let mut final_user: Option<(u32, String)> = None;
    for (index, line) in docker_logical_lines(text) {
        let trimmed = line.trim();
        // `ONBUILD <instruction>` wraps another directive; strip the trigger
        // prefix so ENV/ARG/ADD/USER dispatch sees the wrapped instruction.
        let upper = trimmed.to_ascii_uppercase();
        let (trimmed, upper) = match upper.strip_prefix("ONBUILD ") {
            Some(rest) => {
                let skip = upper.len() - rest.len();
                (&trimmed[skip..], rest)
            }
            None => (trimmed, upper.as_str()),
        };
        if upper.starts_with("FROM ") {
            seen_from = true;
            final_stage_line = index;
            final_user = None;
        } else if upper.starts_with("USER ") {
            final_user = Some((index, trimmed[5..].trim().to_owned()));
        }
        if upper.starts_with("ADD ")
            && (trimmed.contains("http://") || trimmed.contains("https://"))
        {
            builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.dockerfile.remote-add", line: index, column: 1, summary: "Dockerfile ADD fetches a remote URL", details: "Remote ADD makes provenance and cache behavior harder to control.", severity: Severity::Medium, confidence: Confidence::High, description: redact_url_credentials(trimmed), references: &["https://docs.docker.com/reference/dockerfile/#add"], properties: BTreeMap::new(), redacted: false, remediation: "Fetch with a pinned, checksum-verified build step, then COPY the verified artifact.", cwe: Some("CWE-494") });
        }
        if (upper.starts_with("ENV ") || upper.starts_with("ARG "))
            && docker_declares_secret(trimmed, upper)
        {
            builder.add(FindingSpec { kind: FindingKind::Iac, rule: "iac.dockerfile.secret-in-build-arg", line: index, column: 1, summary: "Docker build instruction declares a secret", details: "ENV and ARG values can persist in image configuration or build history.", severity: Severity::High, confidence: Confidence::High, description: "Secret-like variable name in ENV/ARG; value omitted.".to_owned(), references: &["https://docs.docker.com/build/building/secrets/"], properties: BTreeMap::new(), redacted: true, remediation: "Use BuildKit secret mounts and ensure credentials never enter image layers or metadata.", cwe: Some("CWE-522") });
        }
    }
    // A file without any FROM is a fragment, not a stage: no root-user verdict.
    let final_user_is_root = seen_from
        && final_user
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
    let line_starts = line_starts(text);
    // A UTF-8 BOM is legal on the wire (RFC 8259 §8.1 receivers MAY ignore
    // it) but rejected by serde_json; strip it for parsing only and shift
    // document offsets by the BOM length so reported offsets still map to
    // the original text.
    let parse_text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let bom_len = text.len() - parse_text.len();
    if extension == "json" {
        // .json files are JSONC by convention in several ecosystems
        // (tsconfig, devcontainer, launch.json): retry strict-parse failures
        // through the shared comment/trailing-comma sanitizer so those files
        // are scanned instead of reported unparseable. Genuinely malformed
        // JSON still fails both parses and is surfaced.
        //
        // IaC-shape gate: only JSON-shaped content (a leading `{`/`[`) can be
        // a malformed IaC document. Other .json content is parsed as YAML —
        // YAML manifests in .json files still scan, while plain-text bodies
        // (error pages, prose) parse as inert scalars and are skipped rather
        // than misreported as unparseable IaC.
        let json_shaped = matches!(parse_text.trim_start().bytes().next(), Some(b'{' | b'['));
        if json_shaped {
            match serde_json::from_str::<serde_json::Value>(parse_text) {
                Ok(document) => {
                    let index = yaml_path_index(parse_text);
                    let location = DocumentLocation {
                        text,
                        document_offset: bom_len,
                        index: index.as_ref(),
                        line_starts: &line_starts,
                    };
                    scan_structured_document(&document, &location, builder);
                }
                Err(_) => {
                    match serde_json::from_str::<serde_json::Value>(&jsonc_to_json(parse_text)) {
                        Ok(document) => {
                            // Sanitized text offsets do not map back to the
                            // original file; fall back to document-scoped
                            // text anchoring for JSONC documents.
                            let location = DocumentLocation {
                                text,
                                document_offset: bom_len,
                                index: None,
                                line_starts: &line_starts,
                            };
                            scan_structured_document(&document, &location, builder);
                        }
                        Err(_) => add_unparseable_iac_document(builder),
                    }
                }
            }
            return;
        }
        // Non-JSON-shaped .json: scan as YAML below; unparseable YAML is not
        // surfaced because the file was never IaC-shaped input.
    }
    let mut dropped_documents = 0_usize;
    for (document_text, document_offset) in split_yaml_documents(parse_text) {
        let parsed = serde_yaml::from_str::<serde_yaml::Value>(&document_text)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok());
        match parsed {
            Some(document) => {
                let index = yaml_path_index(&document_text);
                let location = DocumentLocation {
                    text,
                    document_offset: document_offset + bom_len,
                    index: index.as_ref(),
                    line_starts: &line_starts,
                };
                scan_structured_document(&document, &location, builder);
            }
            None => dropped_documents += 1,
        }
    }
    if dropped_documents > 0 && extension != "json" {
        add_unparseable_iac_document(builder);
    }
}

/// Splits a YAML stream into per-document chunks on `---` separators,
/// returning each chunk's text and its byte offset in the original file so
/// findings anchor into the correct document. Parsing each chunk with a
/// single-document parse avoids libyaml's stream iterator, which can spin
/// forever on malformed trailing documents; behavior on well-formed streams
/// is identical.
fn split_yaml_documents(text: &str) -> Vec<(String, usize)> {
    let mut documents = Vec::new();
    let mut current = String::new();
    let mut current_offset = 0_usize;
    let mut offset = 0_usize;
    for line in text.split_inclusive('\n') {
        // A document marker is `---` or `...` followed by end-of-line or
        // whitespace (which covers `--- # comment`); `---foo` is content.
        // Content after `---` on the same line belongs to the new document.
        let marker = line
            .strip_prefix("---")
            .or_else(|| line.strip_prefix("..."));
        if let Some(rest) = marker
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            if !current.trim().is_empty() {
                documents.push((std::mem::take(&mut current), current_offset));
            }
            let content = if line.starts_with("---") { rest } else { "" };
            if content.trim().is_empty() {
                offset += line.len();
            } else {
                current_offset = offset + (line.len() - rest.len());
                current.push_str(rest);
                offset += line.len();
            }
            continue;
        }
        if current.is_empty() {
            current_offset = offset;
        }
        current.push_str(line);
        offset += line.len();
    }
    if !current.trim().is_empty() {
        documents.push((current, current_offset));
    }
    documents
}
/// Per-document source context for IaC anchoring: the full file text, the
/// document's byte offset within it, and a path→offset index built from the
/// YAML event stream so findings land on the offending field's line rather
/// than the first textual occurrence of an object name.
struct DocumentLocation<'a> {
    text: &'a str,
    /// Byte offset of this document's text within `text`.
    document_offset: usize,
    index: Option<&'a BTreeMap<String, usize>>,
    line_starts: &'a [usize],
}

/// Scans one parsed YAML/JSON document for Kubernetes and CloudFormation
/// findings.
fn scan_structured_document(
    document: &serde_json::Value,
    location: &DocumentLocation<'_>,
    builder: &mut FindingBuilder<'_>,
) {
    if document.get("apiVersion").is_some() && document.get("kind").is_some() {
        scan_kubernetes_value(document, "", location, builder);
    }
    if document.get("AWSTemplateFormatVersion").is_some() || document.get("Resources").is_some() {
        scan_cloudformation_value(document, "", location, builder);
    }
}

/// Builds a JSON-pointer path → byte-offset index for one YAML document by
/// walking the libyaml event stream — the same parser serde_yaml uses, so
/// positions always agree with the parsed value tree. Mapping entries record
/// the key's offset (the field's line); sequence items and the document root
/// record the node's own offset. Returns `None` when the event parse fails.
fn yaml_path_index(text: &str) -> Option<BTreeMap<String, usize>> {
    let mut parser = MaybeUninit::<unsafe_libyaml::yaml_parser_t>::uninit();
    let mut index = BTreeMap::new();
    // The event walk mirrors libyaml's document structure: a stack of open
    // collections plus the JSON-pointer path of the value currently being
    // descended into.
    enum Frame {
        Mapping {
            expecting_key: bool,
            pending_key: Option<String>,
        },
        Sequence {
            next_index: usize,
        },
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    /// Registers `offset` for the value that begins here: the current path
    /// after consuming a pending map key or the next sequence index. Scalar
    /// values pop the segment immediately; containers keep it until their
    /// end event. A container arriving where a mapping key is expected is a
    /// complex key (`? [...]`): it is indexed under a `?` segment and the
    /// mapping then expects its value.
    fn begin_value(
        stack: &mut [Frame],
        path: &mut Vec<String>,
        index: &mut BTreeMap<String, usize>,
        offset: usize,
    ) {
        match stack.last_mut() {
            Some(Frame::Mapping {
                expecting_key,
                pending_key,
            }) => {
                let key = if *expecting_key {
                    *expecting_key = false;
                    "?".to_owned()
                } else {
                    *expecting_key = true;
                    pending_key.take().unwrap_or_else(|| "?".to_owned())
                };
                path.push(key);
            }
            Some(Frame::Sequence { next_index }) => {
                path.push(next_index.to_string());
                *next_index += 1;
            }
            None => path.clear(),
        }
        index.entry(pointer_join(path)).or_insert(offset);
    }
    // SAFETY: `parser` is initialized before use, `text` outlives the parser
    // (libyaml reads the input in place), each event is deleted after its
    // data is copied out, and the parser is deleted on every exit path.
    unsafe {
        if unsafe_libyaml::yaml_parser_initialize(parser.as_mut_ptr()).fail {
            return None;
        }
        let parser = parser.as_mut_ptr();
        unsafe_libyaml::yaml_parser_set_encoding(parser, unsafe_libyaml::YAML_UTF8_ENCODING);
        unsafe_libyaml::yaml_parser_set_input_string(parser, text.as_ptr(), text.len() as u64);
        let mut event = MaybeUninit::<unsafe_libyaml::yaml_event_t>::uninit();
        loop {
            if unsafe_libyaml::yaml_parser_parse(parser, event.as_mut_ptr()).fail {
                unsafe_libyaml::yaml_parser_delete(parser);
                return None;
            }
            let mut parsed_event = event.assume_init();
            let offset = parsed_event.start_mark.index as usize;
            match parsed_event.type_ {
                unsafe_libyaml::YAML_STREAM_END_EVENT => {
                    unsafe_libyaml::yaml_event_delete(&mut parsed_event);
                    break;
                }
                unsafe_libyaml::YAML_DOCUMENT_START_EVENT => {
                    stack.clear();
                    path.clear();
                }
                unsafe_libyaml::YAML_MAPPING_START_EVENT => {
                    begin_value(&mut stack, &mut path, &mut index, offset);
                    stack.push(Frame::Mapping {
                        expecting_key: true,
                        pending_key: None,
                    });
                }
                unsafe_libyaml::YAML_SEQUENCE_START_EVENT => {
                    begin_value(&mut stack, &mut path, &mut index, offset);
                    stack.push(Frame::Sequence { next_index: 0 });
                }
                unsafe_libyaml::YAML_MAPPING_END_EVENT
                | unsafe_libyaml::YAML_SEQUENCE_END_EVENT => {
                    stack.pop();
                    path.pop();
                }
                unsafe_libyaml::YAML_SCALAR_EVENT => {
                    let scalar = parsed_event.data.scalar;
                    let value = std::str::from_utf8(std::slice::from_raw_parts(
                        scalar.value,
                        scalar.length as usize,
                    ))
                    .unwrap_or("")
                    .to_owned();
                    match stack.last_mut() {
                        Some(Frame::Mapping {
                            expecting_key: expecting @ true,
                            pending_key,
                        }) => {
                            *expecting = false;
                            *pending_key = Some(pointer_escape(&value));
                            index
                                .entry(pointer_join_with(&path, pending_key.as_deref().unwrap()))
                                .or_insert(offset);
                        }
                        _ => {
                            begin_value(&mut stack, &mut path, &mut index, offset);
                            path.pop();
                        }
                    }
                }
                unsafe_libyaml::YAML_ALIAS_EVENT => {
                    begin_value(&mut stack, &mut path, &mut index, offset);
                    path.pop();
                }
                _ => {}
            }
            unsafe_libyaml::yaml_event_delete(&mut parsed_event);
        }
        unsafe_libyaml::yaml_parser_delete(parser);
    }
    Some(index)
}

/// Escapes one path segment per RFC 6901 so keys containing `~` or `/` still
/// resolve unambiguously.
fn pointer_escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn pointer_join(path: &[String]) -> String {
    let mut pointer = String::new();
    for segment in path {
        pointer.push('/');
        pointer.push_str(segment);
    }
    pointer
}

fn pointer_join_with(path: &[String], segment: &str) -> String {
    let mut pointer = pointer_join(path);
    pointer.push('/');
    pointer.push_str(segment);
    pointer
}

/// Resolves a JSON-pointer path to a byte offset in the document, walking up
/// to the nearest indexed ancestor when the exact node was not recorded
/// (absent fields anchor to their parent object).
fn resolve_path_offset(index: &BTreeMap<String, usize>, path: &str) -> Option<usize> {
    let mut current = path;
    loop {
        if let Some(offset) = index.get(current) {
            return Some(*offset);
        }
        current = current.rsplit_once('/')?.0;
    }
}

/// Surfaces documents that failed to parse so operators can distinguish
/// "no IaC issues" from "could not parse" instead of silently scanning a
/// subset of the file; mirrors input.rs's malformed-lockfile diagnostics.
fn add_unparseable_iac_document(builder: &mut FindingBuilder<'_>) {
    builder.add(FindingSpec {
        kind: FindingKind::Iac,
        rule: "iac.unparseable-document",
        line: 1,
        column: 1,
        summary: "Structured IaC file contains unparseable documents",
        details: "At least one YAML or JSON document in this file failed to parse and was excluded from IaC analysis; a clean result does not mean the whole file was checked.",
        severity: Severity::Low,
        confidence: Confidence::High,
        description: "Documents that failed to parse were skipped; the remaining documents were still scanned.".to_owned(),
        references: &[],
        properties: BTreeMap::new(),
        redacted: false,
        remediation: "Fix the YAML or JSON syntax errors so every document in the file is parsed and scanned.",
        cwe: None,
    });
}

struct StructuredIacRule<'a> {
    /// JSON-pointer path of the offending field within the document; used
    /// for position-indexed anchoring.
    path: &'a str,
    /// Object name recorded in the finding's `object` property.
    anchor: &'a str,
    /// Fallback text needle when no position index is available.
    needle: &'a str,
    rule: &'a str,
    summary: &'a str,
    severity: Severity,
    remediation: &'a str,
    cwe: &'a str,
}

/// Boolean-field predicates supported by the table-driven Kubernetes checks.
#[derive(Clone, Copy)]
enum KubernetesIacPredicate {
    /// Fires only when the field is present and set to true.
    IsTrue,
    /// Fires unless the field is explicitly set to false.
    IsNotFalse,
}

/// One table row: the boolean field to inspect, when the check fires, and
/// the finding to emit.
struct KubernetesIacCheck {
    field: &'static str,
    predicate: KubernetesIacPredicate,
    rule: StructuredIacRule<'static>,
}

const KUBERNETES_POD_SPEC_CHECKS: &[KubernetesIacCheck] = &[KubernetesIacCheck {
    field: "hostNetwork",
    predicate: KubernetesIacPredicate::IsTrue,
    rule: StructuredIacRule {
        path: "",
        anchor: "",
        needle: "hostNetwork",
        rule: "iac.kubernetes.host-network",
        summary: "Kubernetes workload uses the host network",
        severity: Severity::High,
        remediation: "Disable hostNetwork unless the workload has a documented, unavoidable requirement.",
        cwe: "CWE-250",
    },
}];

const KUBERNETES_SECURITY_CONTEXT_CHECKS: &[KubernetesIacCheck] = &[
    KubernetesIacCheck {
        field: "privileged",
        predicate: KubernetesIacPredicate::IsTrue,
        rule: StructuredIacRule {
            path: "",
            anchor: "",
            needle: "privileged",
            rule: "iac.kubernetes.privileged-container",
            summary: "Kubernetes container is privileged",
            severity: Severity::Critical,
            remediation: "Remove privileged mode and grant only narrowly required capabilities.",
            cwe: "CWE-250",
        },
    },
    KubernetesIacCheck {
        field: "allowPrivilegeEscalation",
        predicate: KubernetesIacPredicate::IsNotFalse,
        rule: StructuredIacRule {
            path: "",
            anchor: "",
            needle: "allowPrivilegeEscalation",
            rule: "iac.kubernetes.privilege-escalation",
            summary: "Kubernetes container permits privilege escalation",
            severity: Severity::High,
            remediation: "Set securityContext.allowPrivilegeEscalation to false.",
            cwe: "CWE-269",
        },
    },
];

/// Container list fields that carry a securityContext and ports, matching
/// the Kubernetes PodSpec schema (trivy scans the same three groups).
const KUBERNETES_CONTAINER_FIELDS: &[&str] =
    &["containers", "initContainers", "ephemeralContainers"];

fn scan_kubernetes_value(
    value: &serde_json::Value,
    path: &str,
    location: &DocumentLocation<'_>,
    builder: &mut FindingBuilder<'_>,
) {
    // `kind: List` and typed lists (`DeploymentList`, `PodList` — emitted by
    // API clients and GitOps exports) wrap whole objects in `items`; recurse
    // so each item is scanned with its own path prefix instead of being
    // invisible.
    if value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind.ends_with("List"))
    {
        if let Some(items) = value.get("items").and_then(serde_json::Value::as_array) {
            for (index, item) in items.iter().enumerate() {
                scan_kubernetes_value(item, &format!("{path}/items/{index}"), location, builder);
            }
        }
        return;
    }
    let workload = value
        .pointer("/metadata/name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    for (spec, spec_path) in pod_specs(value, path) {
        run_kubernetes_iac_checks(
            KUBERNETES_POD_SPEC_CHECKS,
            spec,
            &spec_path,
            workload,
            location,
            builder,
        );
        for container_field in KUBERNETES_CONTAINER_FIELDS {
            let Some(containers) = spec
                .get(*container_field)
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for (index, container) in containers.iter().enumerate() {
                let container_path = format!("{spec_path}/{container_field}/{index}");
                let name = container
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(workload);
                let security = container
                    .get("securityContext")
                    .unwrap_or(&serde_json::Value::Null);
                run_kubernetes_iac_checks(
                    KUBERNETES_SECURITY_CONTEXT_CHECKS,
                    security,
                    &format!("{container_path}/securityContext"),
                    name,
                    location,
                    builder,
                );
                // hostPort binds a container port onto the node interface
                // (trivy KSV-0024); Kubernetes treats hostPort: 0 as unset,
                // so only a nonzero value is flagged.
                if let Some(ports) = container.get("ports").and_then(serde_json::Value::as_array) {
                    for (port_index, port) in ports.iter().enumerate() {
                        if port
                            .get("hostPort")
                            .is_some_and(|value| value.as_i64() != Some(0))
                        {
                            add_structured_iac(
                                builder,
                                location,
                                StructuredIacRule {
                                    path: &format!("{container_path}/ports/{port_index}/hostPort"),
                                    anchor: name,
                                    needle: "hostPort",
                                    rule: "iac.kubernetes.host-port",
                                    summary: "Kubernetes container binds a host port",
                                    severity: Severity::Medium,
                                    remediation: "Remove hostPort and expose the workload through a Service instead of the node interface.",
                                    cwe: "CWE-668",
                                },
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Applies every check from `checks` against `fields`, emitting each rule
/// whose predicate holds. `fields_path` is the JSON-pointer path of `fields`
/// within the document; a firing check anchors at `fields_path/field` (or the
/// nearest indexed ancestor when the field is absent).
fn run_kubernetes_iac_checks(
    checks: &[KubernetesIacCheck],
    fields: &serde_json::Value,
    fields_path: &str,
    anchor: &str,
    location: &DocumentLocation<'_>,
    builder: &mut FindingBuilder<'_>,
) {
    for check in checks {
        let observed = fields.get(check.field).and_then(serde_json::Value::as_bool);
        let fires = match check.predicate {
            KubernetesIacPredicate::IsTrue => observed == Some(true),
            KubernetesIacPredicate::IsNotFalse => observed != Some(false),
        };
        if fires {
            add_structured_iac(
                builder,
                location,
                StructuredIacRule {
                    path: &format!("{fields_path}/{}", check.field),
                    anchor,
                    ..check.rule
                },
            );
        }
    }
}

fn pod_specs<'a>(value: &'a serde_json::Value, path: &str) -> Vec<(&'a serde_json::Value, String)> {
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let suffix = match kind {
        "Pod" => "/spec",
        "CronJob" => "/spec/jobTemplate/spec/template/spec",
        _ => "/spec/template/spec",
    };
    value
        .pointer(suffix)
        .into_iter()
        .map(|spec| (spec, format!("{path}{suffix}")))
        .collect()
}

fn scan_cloudformation_value(
    value: &serde_json::Value,
    path: &str,
    location: &DocumentLocation<'_>,
    builder: &mut FindingBuilder<'_>,
) {
    let Some(resources) = value
        .get("Resources")
        .and_then(serde_json::Value::as_object)
    else {
        return;
    };
    for (logical_id, resource) in resources {
        let resource_path = format!("{path}/Resources/{}", pointer_escape(logical_id));
        let resource_type = resource
            .get("Type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let properties = resource
            .get("Properties")
            .unwrap_or(&serde_json::Value::Null);
        if resource_type == "AWS::S3::Bucket" {
            // Flag when the block is absent, and when it is present but any
            // of the four controls is concretely false. Intrinsic values
            // ({Ref: …}, !If[…]) are unknown, not permissive.
            let permissive = match properties.get("PublicAccessBlockConfiguration") {
                None => true,
                Some(block) => [
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                ]
                .iter()
                .any(|field| block.get(*field).and_then(serde_json::Value::as_bool) == Some(false)),
            };
            if permissive {
                add_structured_iac(
                    builder,
                    location,
                    StructuredIacRule {
                        path: &format!("{resource_path}/Type"),
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
        }
        if resource_type == "AWS::RDS::DBInstance" {
            // Only a concrete boolean decides: absent or false is flagged,
            // intrinsic values ({Ref: …}, !If[…]) are unknown and skipped.
            let unencrypted = match properties.get("StorageEncrypted") {
                None => true,
                Some(value) => value.as_bool() == Some(false),
            };
            if unencrypted {
                add_structured_iac(
                    builder,
                    location,
                    StructuredIacRule {
                        path: &format!("{resource_path}/Properties/StorageEncrypted"),
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
}

fn add_structured_iac(
    builder: &mut FindingBuilder<'_>,
    location: &DocumentLocation<'_>,
    rule: StructuredIacRule<'_>,
) {
    // Prefer the parse-time position index: it anchors the finding to the
    // offending field inside the correct document. The document-scoped text
    // search remains only for inputs without a position index (JSONC).
    let offset = location
        .index
        .and_then(|index| resolve_path_offset(index, rule.path))
        .map(|offset| location.document_offset + offset)
        .unwrap_or_else(|| {
            let anchor =
                find_structured_scalar(location.text, location.document_offset, rule.anchor)
                    .unwrap_or(location.document_offset);
            location.text[anchor..]
                .find(rule.needle)
                .map_or(anchor, |relative| anchor + relative)
        });
    let (line, column) = indexed_line_column(location.line_starts, offset);
    let mut properties = BTreeMap::new();
    if !rule.anchor.is_empty() {
        properties.insert("object".to_owned(), rule.anchor.to_owned());
    }
    builder.add(FindingSpec { kind: FindingKind::Iac, rule: rule.rule, line, column, summary: rule.summary, details: "A parsed IaC document contains the concrete insecure configuration described by this rule.", severity: rule.severity, confidence: Confidence::High, description: format!("Parsed configuration key: {}", rule.needle), references: &["https://kubernetes.io/docs/concepts/security/", "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/"], properties, redacted: false, remediation: rule.remediation, cwe: Some(rule.cwe) });
}

/// Fallback anchor search used only when no parse-time position index is
/// available: finds `value` at or after `from` — quoted first, then bare —
/// so anchoring stays inside the current document.
fn find_structured_scalar(text: &str, from: usize, value: &str) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    let quoted_double = format!("\"{value}\"");
    let quoted_single = format!("'{value}'");
    text[from..]
        .find(&quoted_double)
        .or_else(|| text[from..].find(&quoted_single))
        .or_else(|| text[from..].find(value))
        .map(|relative| from + relative)
}

fn scan_malware(bytes: &[u8], builder: &mut FindingBuilder<'_>) {
    let digest = sha256_hex(bytes);
    if let Some(signature) = builder.ctx.signatures.sha256.get(&digest) {
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
        scan_zip_bomb(bytes, builder);
    }
}

/// Magic-byte format table: `(magic, format name, optional embedded-scan
/// name)`. Formats with an embedded name are additionally scanned for a
/// second magic occurrence beyond the file header (polyglot indicator).
const MAGIC_FORMATS: &[(&[u8], &str, Option<&str>)] = &[
    (b"MZ", "pe", Some("embedded-pe")),
    (b"\x7fELF", "elf", Some("embedded-elf")),
    (b"#!", "script", None),
    (b"PK\x03\x04", "zip", None),
    (b"%PDF-", "pdf", None),
];

fn detected_formats(bytes: &[u8]) -> Vec<&'static str> {
    let mut formats: Vec<&'static str> = Vec::new();
    for (magic, format, embedded) in MAGIC_FORMATS {
        if bytes.starts_with(magic) && executable_structure(bytes, magic) {
            formats.push(format);
        }
        // An embedded signature identical to the container's own format is
        // the same format twice, not an independently meaningful second
        // signature; counting it would flag ordinary single-format
        // executables as polyglots.
        if let Some(embedded_format) = embedded {
            let embedded_found = bytes
                .windows(magic.len())
                .enumerate()
                .skip(magic.len())
                .take(4096)
                .any(|(offset, window)| {
                    window == *magic && executable_structure(&bytes[offset..], magic)
                });
            if embedded_found && !formats.contains(format) {
                formats.push(embedded_format);
            }
        }
    }
    formats.sort_unstable();
    formats.dedup();
    formats
}

/// Inspect bounded headers/tables, not container type or surrounding bytes.
/// Coincidental magic (including encoded runs) cannot establish an executable.
fn executable_structure(bytes: &[u8], magic: &[u8]) -> bool {
    match magic {
        b"MZ" => plausible_pe_or_dos(bytes).unwrap_or(false),
        b"\x7fELF" => plausible_elf(bytes).unwrap_or(false),
        _ => true,
    }
}

fn header_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    })
}

fn header_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn header_u64(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let value = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

fn plausible_pe_or_dos(bytes: &[u8]) -> Option<bool> {
    let pe = usize::try_from(header_u32(bytes, 0x3c, true)?).ok()?;
    if pe >= 64 && bytes.get(pe..pe.checked_add(4)?) == Some(b"PE\0\0") {
        let coff = bytes.get(pe.checked_add(4)?..)?;
        let sections = usize::from(header_u16(coff, 2, true)?);
        let optional_size = usize::from(header_u16(coff, 16, true)?);
        let optional = coff.get(20..20_usize.checked_add(optional_size)?)?;
        let minimum = match header_u16(optional, 0, true)? {
            0x10b => 96,
            0x20b => 112,
            _ => return Some(false),
        };
        if header_u16(coff, 0, true)? == 0
            || header_u16(coff, 18, true)? & 2 == 0
            || !(1..=96).contains(&sections)
            || optional_size < minimum
        {
            return Some(false);
        }
        let table = coff.get(20 + optional_size..20 + optional_size + sections * 40)?;
        return Some(table.chunks_exact(40).all(|section| {
            let size = header_u32(section, 16, true).unwrap_or(0);
            let offset = header_u32(section, 20, true).unwrap_or(0);
            size == 0 || (offset > 0 && u64::from(offset) + u64::from(size) <= bytes.len() as u64)
        }));
    }
    // DOS-only executables have no PE signature. Retain the meaningful stub
    // case only with a coherent DOS image header and its in-image stub text.
    let last_page = usize::from(header_u16(bytes, 2, true)?);
    let pages = usize::from(header_u16(bytes, 4, true)?);
    let header_size = usize::from(header_u16(bytes, 8, true)?) * 16;
    if pages == 0 || last_page >= 512 || header_size < 28 {
        return Some(false);
    }
    let image_size = (pages - 1) * 512 + if last_page == 0 { 512 } else { last_page };
    let entry = header_size
        + usize::from(header_u16(bytes, 22, true)?) * 16
        + usize::from(header_u16(bytes, 20, true)?);
    if header_size >= image_size || image_size > bytes.len() || entry >= image_size {
        return Some(false);
    }
    let stub = &bytes[header_size..image_size.min(header_size + 4096)];
    Some(
        stub.windows(b"This program cannot be run in DOS mode".len())
            .any(|window| window == b"This program cannot be run in DOS mode"),
    )
}

fn plausible_elf(bytes: &[u8]) -> Option<bool> {
    let class = *bytes.get(4)?;
    let little = match bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return Some(false),
    };
    if bytes.get(6) != Some(&1)
        || !(1..=3).contains(&header_u16(bytes, 16, little)?)
        || header_u16(bytes, 18, little)? == 0
        || header_u32(bytes, 20, little)? != 1
    {
        return Some(false);
    }
    let (header_size, ph_offset, sh_offset, sizes, ph_size, sh_size) = match class {
        1 => (
            52,
            u64::from(header_u32(bytes, 28, little)?),
            u64::from(header_u32(bytes, 32, little)?),
            40,
            32,
            40,
        ),
        2 => (
            64,
            header_u64(bytes, 32, little)?,
            header_u64(bytes, 40, little)?,
            52,
            56,
            64,
        ),
        _ => return Some(false),
    };
    let ph_count = u64::from(header_u16(bytes, sizes + 4, little)?);
    let sh_count = u64::from(header_u16(bytes, sizes + 8, little)?);
    let table_fits = |offset: u64, count: u64, size: u16, expected: u16| {
        count == 0
            || (size == expected
                && offset >= u64::from(header_size)
                && offset
                    .checked_add(count * u64::from(size))
                    .is_some_and(|end| end <= bytes.len() as u64))
    };
    Some(
        header_u16(bytes, sizes, little)? == header_size
            && ph_count + sh_count > 0
            && table_fits(
                ph_offset,
                ph_count,
                header_u16(bytes, sizes + 2, little)?,
                ph_size,
            )
            && table_fits(
                sh_offset,
                sh_count,
                header_u16(bytes, sizes + 6, little)?,
                sh_size,
            ),
    )
}

fn scan_zip_bomb(bytes: &[u8], builder: &mut FindingBuilder<'_>) {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return;
    };
    let mut total_uncompressed = 0_u64;
    let mut total_compressed = 0_u64;
    let mut suspicious_entry = false;
    let inspected = archive
        .len()
        .min(builder.ctx.config.max_archive_entries.saturating_add(1));
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
    let too_many = archive.len() > builder.ctx.config.max_archive_entries;
    let too_large = total_uncompressed > builder.ctx.config.max_archive_uncompressed_bytes;
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

    // Minimal inert header fixtures: no executable instructions or external files.
    fn pe_fixture() -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[70..72].copy_from_slice(&1_u16.to_le_bytes());
        bytes[84..86].copy_from_slice(&240_u16.to_le_bytes());
        bytes[86..88].copy_from_slice(&2_u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[328..333].copy_from_slice(b".text");
        bytes[344..348].copy_from_slice(&16_u32.to_le_bytes());
        bytes[348..352].copy_from_slice(&496_u32.to_le_bytes());
        bytes
    }

    fn elf_fixture(class: u8, little: bool) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', class, if little { 1 } else { 2 }, 1]);
        let put16 = |bytes: &mut [u8], offset, value: u16| {
            bytes[offset..offset + 2].copy_from_slice(&if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            });
        };
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        bytes[if little { 20 } else { 23 }] = 1;
        let (header, sizes, ph_size) = if class == 1 {
            (52, 40, 32)
        } else {
            (64, 52, 56)
        };
        bytes[match (class, little) {
            (1, true) => 28,
            (1, false) => 31,
            (_, true) => 32,
            _ => 39,
        }] = header;
        put16(&mut bytes, sizes, u16::from(header));
        put16(&mut bytes, sizes + 2, ph_size);
        put16(&mut bytes, sizes + 4, 1);
        bytes
    }

    #[test]
    fn polyglot_requires_structure_inside_binary_containers() {
        let mut dos = vec![0; 128];
        dos[..2].copy_from_slice(b"MZ");
        dos[2..4].copy_from_slice(&128_u16.to_le_bytes());
        dos[4..6].copy_from_slice(&1_u16.to_le_bytes());
        dos[8..10].copy_from_slice(&4_u16.to_le_bytes());
        let message = b"This program cannot be run in DOS mode";
        dos[64..64 + message.len()].copy_from_slice(message);
        let mut cases = vec![(pe_fixture(), true), (dos, true)];
        for class in [1, 2] {
            for little in [false, true] {
                cases.push((elf_fixture(class, little), true));
            }
        }
        let mut bad_pe = pe_fixture();
        bad_pe[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push((bad_pe, false));
        let mut bad_section = pe_fixture();
        bad_section[348..352].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push((bad_section, false));
        let mut bad_elf = elf_fixture(2, true);
        bad_elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push((bad_elf, false));
        cases.push((b"\x80MZ\xff\0\x7fELF\x89\x01\x02".to_vec(), false));
        cases.push((pe_fixture()[..80].to_vec(), false));
        for (payload, expected) in cases {
            let mut pdf = b"%PDF-1.5\n<< /Filter /FlateDecode >>\nstream\n\x80\xff".to_vec();
            pdf.extend_from_slice(&payload);
            pdf.extend_from_slice(b"\nendstream\n%%EOF");
            let output = analyze_bytes(
                "embedded.pdf",
                &pdf,
                &asset(),
                &ScannerConfig::default(),
                &MalwareSignatures::default(),
            );
            assert_eq!(has(&output, "malware.executable-script-polyglot"), expected);
        }
    }

    #[test]
    fn private_key_escaped_forms_preserve_normalized_metadata() {
        // Generate inert, diverse base64 text locally; never copy secret material.
        // Real ephemeral OpenSSL key coverage belongs to the CLI smoke recipe.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let body: String = (0..192)
            .map(|index| char::from(alphabet[(index * 37 + index / 64) % 64]))
            .collect();
        let raw = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n{}\n{}\n-----END PRIVATE KEY-----",
            &body[..64],
            &body[64..128],
            &body[128..]
        );
        let metadata = |source: &str| {
            let output = analyze("fixture.txt", source);
            let keys: Vec<_> = output
                .findings
                .iter()
                .filter(|finding| finding.rule_id.as_str() == "secret.private-key")
                .collect();
            assert_eq!(keys.len(), 1);
            let serialized = serde_json::to_string(&output.findings).unwrap();
            assert!(!serialized.contains(&body[..64]));
            keys[0].evidence.iter().next().unwrap().properties.clone()
        };
        let expected = metadata(&raw);
        assert_eq!(expected["fingerprint_sha256"], sha256_hex(raw.as_bytes()));
        assert_eq!(expected["length_bytes"], raw.len().to_string());
        let quoted = serde_json::to_string(&raw).unwrap();
        for escaped in [
            format!("{{\"key\": {quoted}}}"),
            format!("package fixture\nvar key = {quoted}"),
            format!("key = {quoted}"),
        ] {
            assert_eq!(metadata(&escaped), expected);
        }
        let crlf = raw.replace('\n', "\r\n");
        assert_eq!(
            metadata(&serde_json::to_string(&crlf).unwrap()),
            metadata(&crlf)
        );
        let mismatched = raw.replace("END PRIVATE KEY", "END RSA PRIVATE KEY");
        let bad_escape = raw.replace('\n', "\\t");
        for invalid in [mismatched, bad_escape] {
            assert!(!has(
                &analyze("fixture.txt", &invalid),
                "secret.private-key"
            ));
        }
    }

    #[test]
    fn generic_secret_assignment_excludes_only_narrow_noncredential_shapes() {
        let rule = "secret.high-entropy-assignment";
        for value in [
            "base64url.bearer.phx.",
            "&_csrf_token=",
            "new valid password",
            "7488a646-e31f-11e4-aace-600308960662",
        ] {
            // No extension or directory-context exemption: these are value shapes.
            for path in ["src/config.ex", "test/config.exs", "guides/config.md"] {
                assert!(!has(&analyze(path, &format!("token = \"{value}\"")), rule));
            }
        }
        for value in [
            "base64url.bearer.B7kP9vQ2mX8cR4tN6zW3.",
            "&_csrf_token=B7kP9vQ2mX8cR4tN6zW3",
            "new valid B7kP9vQ2mX8cR4tN6zW3 password",
            "B7kP9vQ2 mX8cR4tN6 zW3",
            "7488a646-e31f-11e4-aace-60030896066Z",
        ] {
            assert!(has(
                &analyze("guides/config.md", &format!("token = \"{value}\"")),
                rule
            ));
        }
        let token = format!(
            "{}{}",
            "ghp_",
            (0..36)
                .map(|index| char::from(b"aB7kP9vQ2mX8cR4tN6zW3"[(index * 8) % 21]))
                .collect::<String>()
        );
        assert!(has(
            &analyze("guides/config.md", &format!("token = \"{token}\"")),
            "secret.github-token"
        ));
        let uuid_token = format!("{}{}", "glpat-", "7488a646-e31f-11e4-aace-600308960662");
        assert!(has(
            &analyze("guides/config.md", &uuid_token),
            "secret.gitlab-token"
        ));
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
            sha256_hex(secret.as_bytes())
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
        assert!(!has(
            &analyze("x", "token = \"[github_token_redacted]\""),
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn high_entropy_assignment_requires_entropy_and_context() {
        assert!(has(
            &analyze("x", "api_key = \"B7kP9vQ2mX8cR4tN6zW3\""), // hooray:allow-secret
            "secret.high-entropy-assignment"
        ));
        assert!(!has(
            &analyze("x", "value = \"B7kP9vQ2mX8cR4tN6zW3\""), // hooray:allow-secret
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn high_entropy_assignment_matches_json_quoted_keys_and_compound_names() {
        for line in [
            r#"{"password": "B7kP9vQ2mX8cR4tN6zW3"}"#, // hooray:allow-secret
            r#"{"api_key": "B7kP9vQ2mX8cR4tN6zW3"}"#,  // hooray:allow-secret
            r#""client_secret": "B7kP9vQ2mX8cR4tN6zW3""#, // hooray:allow-secret
            r#"SECRET_KEY = "B7kP9vQ2mX8cR4tN6zW3""#,  // hooray:allow-secret
            r#"DB_PASSWORD: "B7kP9vQ2mX8cR4tN6zW3""#,  // hooray:allow-secret
            r#"AUTH_TOKEN = "B7kP9vQ2mX8cR4tN6zW3""#,  // hooray:allow-secret
        ] {
            assert!(
                has(
                    &analyze("settings.json", line),
                    "secret.high-entropy-assignment"
                ),
                "missed credential assignment: {line}"
            );
        }
    }

    #[test]
    fn high_entropy_assignment_still_ignores_keyword_prefixed_identifiers() {
        assert!(!has(
            &analyze("x.js", "tokenize = \"B7kP9vQ2mX8cR4tN6zW3\""),
            "secret.high-entropy-assignment"
        ));
        assert!(!has(
            &analyze("x", "tokens = \"B7kP9vQ2mX8cR4tN6zW3\""),
            "secret.high-entropy-assignment"
        ));
        assert!(!has(
            &analyze(
                "package.json",
                r#"{"scripts":{"e2e:password":"HOOCLOAK_LOGIN_MODE=password playwright test"}}"# // hooray:allow-secret
            ),
            "secret.high-entropy-assignment"
        ));
        assert!(has(
            &analyze("package.json", r#"{"foo:password":"B7kP9vQ2mX8cR4tN6zW3"}"#), // hooray:allow-secret
            "secret.high-entropy-assignment"
        ));
        assert!(!has(
            &analyze(
                "config.yaml",
                "password_hash: \"$2b$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW\""
            ),
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
    fn dockerfile_remote_add_evidence_never_carries_url_credentials() {
        let output = analyze(
            "Dockerfile",
            "FROM alpine\nADD https://alice:hunter2@example.invalid/pkg.tgz /pkg.tgz\nUSER 10001\n",
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "iac.dockerfile.remote-add")
            .unwrap();
        let serialized = serde_json::to_string(finding).unwrap();
        assert!(!serialized.contains("hunter2"));
        assert!(!serialized.contains("alice"));
        assert!(serialized.contains("example.invalid/pkg.tgz"));
        let plain = analyze(
            "Dockerfile",
            "FROM alpine\nADD https://example.invalid/tool /tool\nUSER 10001\n",
        );
        let finding = plain
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "iac.dockerfile.remote-add")
            .unwrap();
        assert_eq!(
            finding.evidence.iter().next().unwrap().description,
            "ADD https://example.invalid/tool /tool"
        );
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
        assert!(!has(
            &analyze(
                "x.rs",
                "Command::new(\"sh\").arg(\"-c\").arg(input) // hooray:allow-sast"
            ),
            "sast.rust.command-shell"
        ));
        assert!(has(
            &analyze("x.js", "exec(command)"),
            "sast.javascript.exec-dynamic"
        ));
        assert!(!has(
            &analyze("x.ts", "/^(?:rgba|hsla)\\(([^)]+)\\)$/.exec(computed)"),
            "sast.javascript.exec-dynamic"
        ));
    }

    #[test]
    fn javascript_exec_receiver_aliases_and_literals() {
        let source = r#"
const childProcess = require("child_process");
childProcess.exec(command);
childProcess.execSync(`git ${branch}`);
const cp = require("node:child_process");
cp.exec(input);
require("child_process").exec(direct);
import * as esm from "node:child_process";
esm.execSync(value);
import { exec as run, execSync as runSync } from "child_process";
run(value);
runSync(`git ${branch}`);
const { exec: destructured, execSync: destructuredSync } = require("child_process");
destructured(input);
destructuredSync(`git ${branch}`);
exec(command);

/^(?:rgba|hsla)\(([^)]+)\)$/.exec(computed);
RegExp.prototype.exec(computed);
foo.exec(user_input);
// cp.exec(commented);
const text = "cp.exec(string)";
childProcess.exec("fixed");
childProcess.execSync(`fixed`);
cp.exec(`fixed`);
"#;
        let output = analyze("x.ts", source);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 10,
            "all proven dynamic child_process sinks are reported once"
        );
    }

    #[test]
    fn javascript_exec_receiver_aliases_respect_lexical_shadowing() {
        assert!(has(
            &analyze(
                "x.js",
                r#"const cp = require("child_process");
cp.exec(input);"#,
            ),
            "sast.javascript.exec-dynamic"
        ));
        assert!(!has(
            &analyze(
                "x.js",
                r#"const cp = require("child_process");
function run(cp) {
    cp.exec(input);
}"#,
            ),
            "sast.javascript.exec-dynamic"
        ));
        assert!(!has(
            &analyze(
                "x.js",
                r#"function run(require) {
    require("child_process").exec(input);
}"#,
            ),
            "sast.javascript.exec-dynamic"
        ));
        assert!(!has(
            &analyze(
                "x.js",
                r#"const cp = require("child_process").spawn;
cp.exec(input);
const { exec: run } = require("child_process").exec;
run(input);"#,
            ),
            "sast.javascript.exec-dynamic"
        ));
    }

    #[test]
    fn javascript_exec_receiver_aliases_respect_catch_shadowing() {
        let source = r#"const cp = require("child_process");
try {} catch (cp) {
    cp.exec(input);
}
try {} catch ({ exec: cp }) {
    cp.exec(input);
}
cp.exec(input);"#;
        let findings = analyze("x.js", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 1,
            "catch parameters must shadow aliases for both identifier and destructured bindings"
        );
    }

    #[test]
    fn javascript_exec_aliases_honor_reassignment_invalidation() {
        let source = r#"let cp = require("child_process");
cp.exec(before);
cp = fallback;
cp.exec(after);
let { exec: run } = require("child_process");
run(before);
run = fallback;
run(after);"#;
        let findings = analyze("x.js", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 2,
            "calls before reassignment remain findings while later calls are invalidated"
        );
    }

    #[test]
    fn javascript_exec_aliases_keep_nested_reassignments_scoped() {
        let source = r#"let cp = require("child_process");
function reset() {
    cp.exec(before);
    cp = safe;
    cp.exec(after);
}
cp.exec(outside);"#;
        let findings = analyze("x.js", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 2,
            "nested reassignment invalidates only calls after it in that function"
        );
    }

    #[test]
    fn javascript_exec_aliases_ignore_empty_argument_lists() {
        let source = concat!(
            "const cp = require(\"child_process\");\n",
            "cp.exec();\n",
            "cp.exec( /* comment */ );\n",
            "cp.exec(// comment\n);\n",
            "cp.exec(// comment\r);\n",
            "cp.exec(// comment\u{2028});\n",
            "cp.exec(// comment\u{2029});\n",
            "require(\"child_process\").exec(// comment\r);\n",
            "const { exec: run } = require(\"child_process\");\n",
            "run(// comment\u{2028});\n",
            "cp.exec(/* comment */ input);",
        );
        let findings = analyze("x.js", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 1,
            "empty and comment-only command calls are not dynamic sinks"
        );
    }

    #[test]
    fn javascript_exec_aliases_cover_declarations_without_receiver_false_positives() {
        let source = r#"prepare(); const namespace = require("child_process"); namespace.exec(input);
let node_namespace = require("node:child_process"); node_namespace.execSync(input);
var { exec: run } = require("child_process"); run(input);
const unrelated = { exec: input => input }; unrelated.exec(input);
const filesystem = require("fs"); filesystem.exec(input);
const { exec: not_run } = require("fs"); not_run(input);
"#;
        let output = analyze("x.js", source);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 3,
            "only child_process aliases, including renamed destructuring, are reported"
        );
        assert!(!has(
            &analyze(
                "x.js",
                r#"function load(require) {
    const cp = require("child_process");
    cp.exec(input);
}"#,
            ),
            "sast.javascript.exec-dynamic"
        ));
    }

    #[test]
    fn javascript_exec_aliases_reject_member_properties_across_line_comments() {
        let source = r#"const { exec: run } = require("child_process");
const cp = require("child_process");
const other = { run, cp, require };
other . run(input);
other /* comment */ . run(input);
other .
// comment
run(input);
other .
// comment
cp.exec(input);
other .
// comment
require("child_process").exec(input);
run(input);
cp.exec(input);"#;
        let findings = analyze("x.js", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 2,
            "only the named alias and namespace receiver calls are executable sinks"
        );
    }

    #[test]
    fn javascript_exec_aliases_skip_typescript_parameter_modifiers() {
        let source = r#"const cp = require("child_process");
class Runner {
    constructor(public cp: unknown) {
        cp.exec(input);
    }
    method(private readonly cp: unknown) {
        cp.exec(input);
    }
}
cp.exec(input);"#;
        let findings = analyze("x.ts", source)
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 1,
            "TypeScript parameter modifiers must not hide the shadowing identifier"
        );
    }
    #[test]
    fn javascript_exec_receiver_aliases_handle_utf8_and_concise_arrows() {
        let source = r#"const cp = require("child_process");
const π = 1;
const shadowed = cp => cp.exec(input);
const async_shadowed = async cp => cp.exec(input);
const newline_shadowed = cp => cp.exec(input)
const assignment_shadowed = fn = cp => cp.exec(input);
const dynamic = value => cp.exec(input);
childProcess.exec(input);"#;
        let output = analyze("x.js", source);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
            .count();
        assert_eq!(
            findings, 1,
            "only the unshadowed declared child_process alias is reported"
        );
    }

    #[test]
    fn javascript_binding_model_handles_reviewed_edge_cases() {
        let rule = "sast.javascript.exec-dynamic";
        let initializer = analyze(
            "x.js",
            "const π = 1;\nconst cp = require(\"child_process\");\nconst fn = (value = (other, cp)) => cp.exec(input);\n",
        );
        assert_eq!(
            initializer
                .findings
                .iter()
                .filter(|finding| finding.rule_id.as_str() == rule)
                .count(),
            1,
            "parenthesized initializer commas must not bind cp"
        );
        let finding = initializer
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == rule)
            .unwrap();
        let location = initializer
            .locations
            .iter()
            .find(|location| Some(&location.id) == finding.location_id.as_ref())
            .and_then(|location| location.start.as_ref())
            .unwrap();
        assert_eq!((location.line, location.column), (3, 40));

        assert_eq!(
            analyze(
                "x.js",
                "const cp = require(\"child_process\");\nfunction run() { { var cp = local; } cp.exec(input); }\ncp.exec(input);\n",
            )
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == rule)
            .count(),
            1,
            "var must bind in the nearest function scope"
        );
        assert_eq!(
            analyze(
                "x.js",
                "const cp = require(\"child_process\");\nconst number = cp => 1;\nconst string = cp => \"safe\";\ncp.exec(input);\n",
            )
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == rule)
            .count(),
            1,
            "literal concise-arrow bodies must end before the next line"
        );
        assert!(!has(
            &analyze(
                "x.js",
                "const cp = require(\"child_process\");\nconst logical = cp => value\n  && cp.exec(input);\n",
            ),
            rule
        ));
        assert!(!has(
            &analyze(
                "x.ts",
                "const cp = require(\"child_process\");\nfunction typed(cp): void { cp.exec(input); }\nconst typedArrow = (cp): void => { cp.exec(input); }\n",
            ),
            rule
        ));
        assert_eq!(
            analyze(
                "x.js",
                "const cp = require(\"child_process\");\nconst fn = function cp() { cp.exec(input); };\nconst cls = class cp { static run() { cp.exec(input); } }\ncp.exec(input);\n",
            )
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == rule)
            .count(),
            1,
            "named expressions must scope their names to the expression"
        );
        assert_eq!(
            analyze(
                "x.js",
                "const cp = require(\"child_process\");\nconst shadowed = cp => cp.exec(input) /* comment */\ncp.exec(input);\n",
            )
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == rule)
            .count(),
            1,
            "comment openers must not become arrow-expression tokens"
        );
        assert_eq!(
            analyze(
                "x.js",
                "const cp = require(\"child_process\");\nfunction run(...cp) { cp.exec(input); }\ncp.exec(input);\n",
            )
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == rule)
            .count(),
            1,
            "top-level rest parameters must bind their identifier"
        );
        assert!(has(
            &analyze(
                "x.js",
                "const { exec: run = fallback } = require(\"child_process\");\nrun(input);\n",
            ),
            rule
        ));
    }

    #[test]
    fn javascript_concise_arrow_regex_literals_do_not_corrupt_scope() {
        let findings = analyze(
            "x.js",
            "const cp = require(\"child_process\");\nconst matcher = cp => /)/.test(cp);\ncp.exec(input);\n",
        )
        .findings
        .iter()
        .filter(|finding| finding.rule_id.as_str() == "sast.javascript.exec-dynamic")
        .count();
        assert_eq!(
            findings, 1,
            "regex delimiters must not underflow arrow-expression scope tracking"
        );
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
    fn yaml_load_positional_restricted_loaders_are_not_reported() {
        for source in [
            "cfg = yaml.load(doc, yaml.SafeLoader)",
            "cfg = yaml.load(doc, yaml.CSafeLoader)",
            "cfg = yaml.load(doc, yaml.BaseLoader)",
            "cfg = yaml.load(doc, SafeLoader)",
        ] {
            assert!(
                !has(&analyze("x.py", source), "sast.python.yaml-unsafe-load"),
                "flagged safe call: {source}"
            );
        }
        assert!(has(
            &analyze("x.py", "cfg = yaml.load(doc)"),
            "sast.python.yaml-unsafe-load"
        ));
        assert!(has(
            &analyze("x.py", "cfg = yaml.load(doc, custom_loader)"),
            "sast.python.yaml-unsafe-load"
        ));
    }

    #[test]
    fn yaml_loader_scan_tolerates_multibyte_arguments_past_the_byte_cap() {
        let wide = "\u{20ac}".repeat(20_000);
        assert!(!yaml_call_specifies_loader(&wide));
        assert!(!yaml_call_specifies_loader(&format!("{})", wide)));
        let output = analyze(
            "x.py",
            &format!("cfg = yaml.load(\"{}\")", "\u{20ac}".repeat(9_000)),
        );

        assert!(has(&output, "sast.python.yaml-unsafe-load"));
    }
    #[test]
    fn python_triple_quoted_docstring_survives_lone_apostrophes() {
        let source = "'''don't eval(user_input)'''\nvalue = eval(user_input)\n";
        let output = analyze("x.py", source);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "sast.python.eval-dynamic")
            .collect::<Vec<_>>();
        assert_eq!(
            findings.len(),
            1,
            "docstring eval suppressed, live eval kept"
        );
    }

    #[test]
    fn sast_suppression_extends_across_inline_block_and_multiline_contexts() {
        assert!(!has(
            &analyze("x.js", "foo(); // eval(user_input)\n"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.js", "/* eval(user_input) */\n"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.rs", "/* Md5::new() */\n"),
            "sast.rust.weak-hash-md5"
        ));
        assert!(!has(
            &analyze("x.js", "const t = `first\neval(user_input)\nafter`;\n"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(!has(
            &analyze("x.py", "\"\"\"\ndocstring eval(user_input)\n\"\"\"\n"),
            "sast.python.eval-dynamic"
        ));
        assert!(has(
            &analyze("x.js", "const y = eval(user_input);\n"),
            "sast.javascript.eval-dynamic"
        ));
        assert!(has(
            &analyze("x.py", "value = eval(user_input)\n"),
            "sast.python.eval-dynamic"
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
        let digest = sha256_hex(bytes);
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
        bytes.extend_from_slice(&pe_fixture());
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
    fn monomorphic_pe_is_not_flagged_as_polyglot() {
        let mut bytes = pe_fixture();
        bytes.extend_from_slice(&pe_fixture());
        bytes.resize(4096, 0);
        assert_eq!(detected_formats(&bytes), vec!["pe"]);
        assert!(!has(
            &analyze_bytes(
                "app.bin",
                &bytes,
                &asset(),
                &ScannerConfig::default(),
                &MalwareSignatures::default(),
            ),
            "malware.executable-script-polyglot"
        ));
        // A genuinely distinct second format still raises the indicator.
        let mut polyglot = b"#!/bin/sh\n".to_vec();
        polyglot.extend_from_slice(&pe_fixture());
        assert_eq!(detected_formats(&polyglot), vec!["embedded-pe", "script"]);
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
        let digest = sha256_hex(bytes);
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
    fn python_weak_hash_usedforsecurity_false_is_suppressed() {
        // Literal opt-out: the stdlib marks the digest as non-security use.
        let opted_out = analyze(
            "x.py",
            "a = hashlib.md5(x, usedforsecurity=False)\n\
             b = hashlib.sha1(x, usedforsecurity=False)\n\
             c = hashlib.md5(usedforsecurity=False, data=x)\n\
             d = hashlib.sha1(x, usedforsecurity = False)\n",
        );
        assert!(!has(&opted_out, "sast.python.weak-hash-md5"));
        assert!(!has(&opted_out, "sast.python.weak-hash-sha1"));
        // Bare calls and an explicit True still fire; non-literal values stay
        // flagged because their value cannot be resolved statically.
        let flagged = analyze(
            "x.py",
            "a = hashlib.md5(x)\n\
             b = hashlib.sha1(x, usedforsecurity=True)\n\
             c = hashlib.md5(x, usedforsecurity=flag)\n",
        );
        assert_eq!(
            flagged
                .findings
                .iter()
                .filter(|finding| matches!(
                    finding.rule_id.as_str(),
                    "sast.python.weak-hash-md5" | "sast.python.weak-hash-sha1"
                ))
                .count(),
            3
        );
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
    fn recursive_scan_honors_gitignore_and_hoorayignore() {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("ignored")).unwrap();
        fs::create_dir(directory.path().join("fixtures")).unwrap();
        fs::write(directory.path().join(".gitignore"), "ignored/\n").unwrap();
        fs::write(directory.path().join(".hoorayignore"), "fixtures/\n").unwrap();
        fs::write(directory.path().join("ignored/bad.py"), "eval(user_input)").unwrap();
        fs::write(directory.path().join("fixtures/bad.py"), "eval(user_input)").unwrap();
        fs::write(directory.path().join("safe.py"), "print('safe')").unwrap();

        let output = scan_path(
            directory.path(),
            &asset(),
            &ScannerConfig::default(),
            &MalwareSignatures::default(),
        )
        .unwrap();

        assert_eq!(output.scanned_files, 3);
        assert!(!has(&output, "sast.python.eval-dynamic"));
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

    #[test]
    fn unparseable_structured_iac_documents_are_surfaced() {
        let partial = "apiVersion: v1\nkind: Pod\n---\n[1, 2\n";
        let output = analyze("pod.yaml", partial);
        assert!(has(&output, "iac.unparseable-document"));
        assert!(has(
            &analyze("broken.yaml", "{{{"),
            "iac.unparseable-document"
        ));
        assert!(has(
            &analyze("template.json", "{not json"),
            "iac.unparseable-document"
        ));
        // Fully parseable files stay clean, including an empty document stream.
        assert!(!has(
            &analyze("ok.yaml", "apiVersion: v1\nkind: Pod\n"),
            "iac.unparseable-document"
        ));
        assert!(!has(&analyze("empty.yaml", ""), "iac.unparseable-document"));
    }

    #[test]
    fn bom_prefixed_json_parses_and_yields_real_findings() {
        // dapper xunit.runner.json regression: a UTF-8 BOM must not produce
        // unparseable-document nor suppress the document's real findings.
        let pod = "\u{feff}{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"spec\":{\"containers\":[{\"name\":\"app\",\"securityContext\":{\"privileged\":true}}]}}";
        let output = analyze("pod.json", pod);
        assert!(!has(&output, "iac.unparseable-document"));
        assert!(has(&output, "iac.kubernetes.privileged-container"));
        assert!(has(&output, "iac.kubernetes.privilege-escalation"));
    }

    #[test]
    fn jsonc_style_json_files_do_not_report_unparseable() {
        // tsconfig/devcontainer/launch.json conventionally carry comments and
        // trailing commas; they must parse tolerantly instead of flagging.
        let tsconfig =
            "{\n  // compiler options\n  \"compilerOptions\": {\n    \"strict\": true,\n  },\n}\n";
        assert!(!has(
            &analyze("tsconfig.json", tsconfig),
            "iac.unparseable-document"
        ));
        let devcontainer =
            "{\n  /* image */\n  \"image\": \"mcr.microsoft.com/devcontainers/base:1\",\n}\n";
        assert!(!has(
            &analyze("devcontainer.json", devcontainer),
            "iac.unparseable-document"
        ));
        // JSONC IaC content is still scanned after sanitization.
        let pod = "{\n  // workload\n  \"apiVersion\": \"v1\",\n  \"kind\": \"Pod\",\n  \"spec\": {\"containers\": [{\"name\": \"app\", \"securityContext\": {\"privileged\": true}}]},\n}\n";
        let output = analyze("pod.json", pod);
        assert!(!has(&output, "iac.unparseable-document"));
        assert!(has(&output, "iac.kubernetes.privileged-container"));
        // Genuinely malformed JSON still reports unparseable-document.
        assert!(has(
            &analyze("broken.json", "{\"a\": }"),
            "iac.unparseable-document"
        ));
        assert!(has(
            &analyze("broken.json", "{not json"),
            "iac.unparseable-document"
        ));
    }

    #[test]
    fn private_key_rule_covers_all_pem_labels() {
        for label in ["", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED "] {
            let pem = format!(
                "-----BEGIN {label}PRIVATE KEY-----\nMIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIf8r2\n-----END {label}PRIVATE KEY-----"
            );
            assert!(
                has(&analyze("key.pem", &pem), "secret.private-key"),
                "missed PEM label: {label:?}"
            );
        }
    }

    #[test]
    fn regex_literal_assignments_are_not_flagged_as_secrets() {
        // composer GitHub.php regression: a constant holding a token-format
        // regex is a pattern definition, not a credential.
        for line in [
            "const GITHUB_TOKEN_REGEX = '{^([a-f0-9]{12,}|gh[a-z]_[a-zA-Z0-9_.-]+|github_pat_[a-zA-Z0-9_]+)$}';",
            "const GITHUB_TOKEN_REGEX = '/ghp_[A-Za-z0-9]{36}/';",
            "token_pattern = \"\\d{4}-\\d{4}\"",
        ] {
            assert!(
                !has(&analyze("x.php", line), "secret.high-entropy-assignment"),
                "pattern definition flagged: {line}"
            );
        }
        // Negative control: a literal token assignment still flags.
        let real = format!(
            "token = \"{}{}\"",
            "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        );
        assert!(has(&analyze("x", &real), "secret.github-token"));
        assert!(has(
            &analyze("x", "api_key = \"B7kP9vQ2mX8cR4tN6zW3\""), // hooray:allow-secret
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn polyglot_ignores_mz_inside_encoded_payload() {
        // fastlane pilot.ai regression: `MZ` inside a base64 PDF stream is a
        // coincidental substring, not an embedded PE signature.
        let mut pdf = b"%PDF-1.5\r\n1 0 obj\r<< /Length 200 >>\rstream\r".to_vec();
        for _ in 0..800 {
            pdf.extend_from_slice(b"QUJD");
        }
        pdf.extend_from_slice(b"MZCV47mpBBqadT2zKOSN04wxGrReka");
        for _ in 0..200 {
            pdf.extend_from_slice(b"QUJD");
        }
        pdf.extend_from_slice(b"\rendstream\rendobj\r%%EOF\r");
        assert!(!has(
            &analyze_bytes(
                "doc.ai",
                &pdf,
                &asset(),
                &ScannerConfig::default(),
                &MalwareSignatures::default(),
            ),
            "malware.executable-script-polyglot"
        ));
        // Negative control: a real embedded PE (binary boundary) still fires.
        let mut polyglot = b"#!/bin/sh\n".to_vec();
        polyglot.extend_from_slice(&pe_fixture());
        assert!(has(
            &analyze_bytes(
                "polyglot",
                &polyglot,
                &asset(),
                &ScannerConfig::default(),
                &MalwareSignatures::default(),
            ),
            "malware.executable-script-polyglot"
        ));
    }

    #[test]
    fn high_entropy_assignment_ignores_vocabulary_and_dummy_constants() {
        // flutter autofill_hint.dart regression: protocol vocabulary and
        // sequential dummy constants are not credentials.
        let source = "const Map<String, String> autofillHints = <String, String>{\n  'password': 'current-password',\n  'newPassword': 'new-password',\n};\nconst token = '0123456789abcdef';\n";
        let output = analyze("autofill_hint.dart", source);
        assert!(!has(&output, "secret.high-entropy-assignment"));
        // Kubernetes namespace/name secret references are pointers, not keys.
        assert!(!has(
            &analyze("deploy.yaml", "password: \"default/other-demo-secret\""),
            "secret.high-entropy-assignment"
        ));
        // Negative control: a real token assignment still flags.
        assert!(has(
            &analyze("x", "api_key = \"B7kP9vQ2mX8cR4tN6zW3\""), // hooray:allow-secret
            "secret.high-entropy-assignment"
        ));
    }

    #[test]
    fn kubernetes_findings_anchor_to_offending_field_in_correct_document() {
        // ingress-nginx multi-tls regression: a Service named `web` in the
        // first document must not absorb the Deployment container finding
        // from the second document.
        let yaml = "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  ports:\n    - port: 80\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: app:latest\n";
        let output = analyze("multi.yaml", yaml);
        let findings = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "iac.kubernetes.privilege-escalation")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        let line = output
            .locations
            .iter()
            .find(|location| Some(&location.id) == findings[0].location_id.as_ref())
            .unwrap()
            .start
            .unwrap()
            .line;
        // The container `- name: web` sits at line 17 of the second document,
        // not line 4 (Service metadata.name) as the old text search reported.
        assert_eq!(line, 17);
    }

    #[test]
    fn kubernetes_list_items_and_init_containers_are_scanned() {
        let yaml = "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    metadata:\n      name: listed\n    spec:\n      hostNetwork: true\n      initContainers:\n        - name: init\n          securityContext:\n            privileged: true\n      ephemeralContainers:\n        - name: debug\n          securityContext:\n            privileged: true\n      containers:\n        - name: app\n          ports:\n            - containerPort: 80\n              hostPort: 8080\n";
        let output = analyze("list.yaml", yaml);
        assert!(has(&output, "iac.kubernetes.host-network"));
        assert!(has(&output, "iac.kubernetes.host-port"));
        let privileged = output
            .findings
            .iter()
            .filter(|finding| finding.rule_id.as_str() == "iac.kubernetes.privileged-container")
            .count();
        assert_eq!(privileged, 2, "initContainers and ephemeralContainers");
    }

    #[test]
    fn command_shell_rules_ignore_literal_command_strings() {
        // ingress-nginx waitshutdown regression: a literal argv string is a
        // static command, not dynamic shell execution.
        assert!(!has(
            &analyze(
                "main.go",
                "exec.Command(\"bash\", \"-c\", \"pkill -SIGTERM -f nginx-ingress-controller\")"
            ),
            "sast.go.command-shell"
        ));
        assert!(!has(
            &analyze("x.rs", "Command::new(\"sh\").arg(\"-c\").arg( \"ls -la\" )"),
            "sast.rust.command-shell"
        ));
        // Negative controls: dynamic command strings still fire.
        assert!(has(
            &analyze("main.go", "exec.Command(\"bash\", \"-c\", cmd)"),
            "sast.go.command-shell"
        ));
        assert!(has(
            &analyze("x.rs", "Command::new(\"sh\").arg(\"-c\").arg(input)"),
            "sast.rust.command-shell"
        ));
    }

    #[test]
    fn private_key_rule_requires_plausible_pem_body() {
        // ingress-nginx kubectl-plugin.md regression: marker-only and
        // placeholder PEM bodies are not secrets.
        for pem in [
            "-----BEGIN PRIVATE KEY-----\n<REDACTED! DO NOT SHARE THIS!>\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nXXXXXXXXXXXXXXXXXXXXXXXX\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nfewfawefawfe\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\ninvalid!base64bodyhere\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            assert!(
                !has(&analyze("key.pem", pem), "secret.private-key"),
                "placeholder PEM flagged: {pem:?}"
            );
            assert!(!has(
                &analyze("key.json", &serde_json::to_string(pem).unwrap()),
                "secret.private-key"
            ));
        }
        // Construct inert key-shaped text at runtime so dogfood does not
        // mistake the regression fixture itself for an escaped private key.
        let body = "MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIf8r2";
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----");
        assert!(has(&analyze("key.pem", &pem), "secret.private-key"));
    }

    #[test]
    fn private_key_fingerprint_covers_the_pem_block() {
        // gitleaks regression: same-label PEMs with different bodies must
        // produce different fingerprints so policy exceptions pin one key.
        let body_a = "MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIf8r2AAAA";
        let body_b = "BQ0wMzAbBgkqhkiG9w0BBQwwDgQIf8r2MIIBpjBABgkqhkiG9w0BBBB";
        let pem =
            |body: &str| format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----");
        let fingerprints = |pem: &str| {
            analyze("key.pem", pem)
                .findings
                .iter()
                .filter(|finding| finding.rule_id.as_str() == "secret.private-key")
                .map(|finding| {
                    finding.evidence.iter().next().unwrap().properties["fingerprint_sha256"].clone()
                })
                .collect::<Vec<_>>()
        };
        let a = fingerprints(&pem(body_a));
        let b = fingerprints(&pem(body_b));
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_ne!(a[0], b[0]);
    }

    #[test]
    fn secret_pattern_rules_apply_placeholder_filtering() {
        // gitleaks self-scan regression: documented non-secrets must not flag
        // through the pattern-rule path either.
        let source = "key = AKIAXXXXXXXXXXXXXXXX\naws_access_key: AKIAIOSFODNN7EXAMPLE\ntoken = \"xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx\"\n";
        let output = analyze("config.txt", source);
        assert!(!has(&output, "secret.aws-access-key"));
        assert!(!has(&output, "secret.slack-token"));
        // Negative control: a real-format AWS key still flags.
        assert!(has(
            &analyze("config.txt", "key = AKIAB7KP9VQ2MX8CR4T6"), // hooray:allow-secret
            "secret.aws-access-key"
        ));
    }

    #[test]
    fn non_iac_json_files_do_not_report_unparseable() {
        // ingress-nginx error-page regression: a .json file holding plain
        // text is not a malformed IaC document.
        assert!(!has(
            &analyze(
                "500.json",
                "Internal Server Error\nThe server encountered an error.\n"
            ),
            "iac.unparseable-document"
        ));
        // JSON-shaped malformed content still reports the finding.
        assert!(has(
            &analyze("broken.json", "{not json"),
            "iac.unparseable-document"
        ));
    }
}
