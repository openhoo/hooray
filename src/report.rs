use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as FmtWrite},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    ApplicabilityStatus, ComponentId, Finding, FindingId, Location, LocationId, PolicyDecision,
    PolicyOutcome, ScanReport, Severity,
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
    Junit,
    Html,
    CycloneDxVex,
    Spdx,
    GitLabCodeQuality,
    JsonLines,
}

impl ReportFormat {
    pub const ALL: [Self; 10] = [
        Self::Json,
        Self::Yaml,
        Self::Table,
        Self::Sarif,
        Self::Junit,
        Self::Html,
        Self::CycloneDxVex,
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
            Self::Junit => "junit",
            Self::Html => "html",
            Self::CycloneDxVex => "cyclonedx-vex",
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
            Self::Sarif => "sarif",
            Self::Junit => "xml",
            Self::Html => "html",
            Self::CycloneDxVex => "cdx.json",
            Self::JsonLines => "jsonl",
        }
    }

    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json | Self::Spdx | Self::GitLabCodeQuality => "application/json",
            Self::Yaml => "application/yaml",
            Self::Table => "text/plain; charset=utf-8",
            Self::Sarif => "application/sarif+json",
            Self::Junit => "application/xml",
            Self::Html => "text/html; charset=utf-8",
            Self::CycloneDxVex => "application/vnd.cyclonedx+json",
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
            "junit" | "junit-xml" => Ok(Self::Junit),
            "html" => Ok(Self::Html),
            "cyclonedx" | "cyclonedx-vex" | "cdx" | "cdx-vex" => Ok(Self::CycloneDxVex),
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
        ReportFormat::Table => render_table(&sanitized, limit),
        ReportFormat::Sarif => render_sarif(&sanitized, limit),
        ReportFormat::Junit => render_junit(&sanitized, limit),
        ReportFormat::Html => render_html(&sanitized, limit),
        ReportFormat::CycloneDxVex => render_cyclonedx_vex(&sanitized, limit),
        ReportFormat::Spdx => render_spdx(&sanitized, limit),
        ReportFormat::GitLabCodeQuality => render_gitlab(&sanitized, limit),
        ReportFormat::JsonLines => render_json_lines(&sanitized, limit),
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

fn render_table(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
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
        let paths = dependency_paths(report, finding);
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
            output.push_str(if evidence.redacted {
                " [redacted]"
            } else {
                " [not-redacted]"
            });
            for (key, value) in &evidence.properties {
                output.push_str(&format!("; {}={}", clean_cell(key), clean_cell(value)));
            }
            output.push('\n');
        }
        for decision in policies_for(report, &finding.id) {
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

struct ReportIndex<'a> {
    roots: BTreeSet<&'a ComponentId>,
    adjacency: BTreeMap<&'a ComponentId, Vec<&'a ComponentId>>,
    locations: BTreeMap<&'a LocationId, &'a Location>,
    policies: BTreeMap<&'a FindingId, Vec<&'a PolicyDecision>>,
}

impl<'a> ReportIndex<'a> {
    fn new(report: &'a ScanReport) -> Self {
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
            .components
            .values()
            .flat_map(|component| component.locations.iter())
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

fn render_sarif(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    let index = ReportIndex::new(report);
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
        let locations = sarif_locations(&index, finding);
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

fn render_junit(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
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
        output.push_str(&format!(
            "    <testcase classname=\"hooray.{}\" name=\"{}\">\n",
            finding.kind.as_str(),
            xml_attr(finding.id.as_str())
        ));
        let body = finding_detail_text(report, finding);
        if finding.status != crate::model::FindingStatus::Resolved {
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

fn render_html(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    let mut rows = BoundedText::new(limit);
    for finding in report.findings.values() {
        let details = finding_detail_text(report, finding);
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
fn render_cyclonedx_vex(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
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
        let properties = common_properties(report, finding);
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

fn render_spdx(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
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
            "componentId": finding.component_id.as_ref().map(|id| id.as_str()), "dependencyPaths": dependency_paths(report, finding),
            "summary": finding.summary, "details": finding.details, "applicability": finding.applicability,
            "remediation": finding.remediation, "evidence": finding.evidence, "policyOutcomes": policies_for(report, &finding.id)
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

fn render_gitlab(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    let findings: Vec<Value> = report.findings.values().map(|finding| {
        let location = finding_location(report, finding);
        let path = location.map(|item| item.path.as_str()).unwrap_or(".");
        let line = location.and_then(|item| item.start.map(|position| position.line)).unwrap_or(1).max(1);
        json!({
            "description": finding_detail_text(report, finding), "check_name": finding.rule_id.as_str(),
            "fingerprint": finding.id.as_str(), "severity": gitlab_severity(finding.severity),
            "location": {"path": path, "lines": {"begin": line}},
            "categories": [finding.kind.as_str()],
            "hooray": {"format_version": CANONICAL_REPORT_VERSION, "finding_id": finding.id.as_str(),
                "component_id": finding.component_id.as_ref().map(|id| id.as_str()), "dependency_paths": dependency_paths(report, finding),
                "remediation": finding.remediation, "policy_outcomes": policies_for(report, &finding.id), "evidence": finding.evidence}
        })
    }).collect();
    pretty_json(&findings, limit)
}

fn render_json_lines(report: &ScanReport, limit: usize) -> Result<Vec<u8>, ReportError> {
    let mut output = BoundedWriter::new(limit);
    for finding in report.findings.values() {
        let envelope = JsonLineEnvelope {
            format: "hooray-finding",
            format_version: CANONICAL_REPORT_VERSION,
            report_schema_version: &report.schema_version,
            run_id: report.run.id.as_str(),
            finding,
            dependency_paths: dependency_paths(report, finding),
            policy_outcomes: policies_for(report, &finding.id),
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

fn finding_location<'a>(report: &'a ScanReport, finding: &Finding) -> Option<&'a Location> {
    let location_id = finding.location_id.as_ref()?;
    report
        .inventory
        .components
        .values()
        .flat_map(|component| component.locations.iter())
        .find(|location| &location.id == location_id)
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

fn dependency_paths<'a>(report: &'a ScanReport, finding: &'a Finding) -> Vec<Vec<&'a str>> {
    let Some(target) = finding.component_id.as_ref() else {
        return Vec::new();
    };
    let mut roots: BTreeSet<_> = report.inventory.components.keys().collect();
    for edge in &report.inventory.dependencies {
        roots.remove(&edge.to);
    }
    if roots.is_empty() {
        roots.extend(report.inventory.components.keys());
    }
    let adjacency: BTreeMap<_, Vec<_>> = report
        .inventory
        .components
        .keys()
        .map(|id| {
            let children = report
                .inventory
                .dependencies
                .iter()
                .filter(|edge| &edge.from == id)
                .map(|edge| &edge.to)
                .collect();
            (id, children)
        })
        .collect();
    let mut paths = Vec::new();
    for root in roots {
        let mut stack = vec![(root, vec![root], BTreeSet::from([root]))];
        while let Some((node, path, visited)) = stack.pop() {
            if node == target {
                paths.push(path.into_iter().map(|id| id.as_str()).collect());
                if paths.len() >= 100 {
                    return paths;
                }
                continue;
            }
            if let Some(children) = adjacency.get(node) {
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

fn policies_for<'a>(report: &'a ScanReport, finding_id: &FindingId) -> Vec<&'a PolicyDecision> {
    report
        .policy_decisions
        .iter()
        .filter(|decision| decision.finding_id.as_ref() == Some(finding_id))
        .collect()
}

fn common_properties(report: &ScanReport, finding: &Finding) -> Vec<Value> {
    let mut properties = vec![
        json!({"name": "hooray:finding-id", "value": finding.id.as_str()}),
        json!({"name": "hooray:kind", "value": finding.kind.as_str()}),
        json!({"name": "hooray:dependency-paths", "value": serde_json::to_string(&dependency_paths(report, finding)).expect("dependency paths are serializable")}),
        json!({"name": "hooray:evidence", "value": serde_json::to_string(&finding.evidence).expect("evidence is serializable")}),
        json!({"name": "hooray:policy-outcomes", "value": serde_json::to_string(&policies_for(report, &finding.id)).expect("policy outcomes are serializable")}),
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

fn finding_detail_text(report: &ScanReport, finding: &Finding) -> String {
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
    for path in dependency_paths(report, finding) {
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
    for decision in policies_for(report, &finding.id) {
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
        Severity::Unknown | Severity::Low => "minor",
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
