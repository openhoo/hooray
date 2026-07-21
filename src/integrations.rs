use std::collections::{BTreeMap, BTreeSet};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    model::{Finding, FindingId, FindingKind, Location, PolicyOutcome, ScanReport, Severity},
    store::ReportDiff,
};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const WEBHOOK_SIGNATURE_VERSION: &str = "v1";
const REDACTED: &str = "[REDACTED]";
const MIN_WEBHOOK_SECRET_BYTES: usize = 16;
const MAX_WEBHOOK_SECRET_BYTES: usize = 4_096;
const MAX_URL_BYTES: usize = 2_048;
const MAX_EVENT_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrationLimits {
    pub max_annotations: usize,
    pub max_payload_bytes: usize,
    pub max_text_bytes: usize,
}

impl Default for IntegrationLimits {
    fn default() -> Self {
        Self {
            max_annotations: 500,
            max_payload_bytes: 1024 * 1024,
            max_text_bytes: 4_096,
        }
    }
}

impl IntegrationLimits {
    pub fn validate(self) -> Result<Self, IntegrationError> {
        if self.max_annotations == 0 || self.max_annotations > 10_000 {
            return Err(IntegrationError::InvalidLimit("max_annotations"));
        }
        if self.max_payload_bytes < 1_024 || self.max_payload_bytes > 16 * 1024 * 1024 {
            return Err(IntegrationError::InvalidLimit("max_payload_bytes"));
        }
        if self.max_text_bytes == 0 || self.max_text_bytes > 64 * 1024 {
            return Err(IntegrationError::InvalidLimit("max_text_bytes"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifact {
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub truncated: bool,
}

impl GeneratedArtifact {
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWebhook {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestGate {
    pub passed: bool,
    pub introduced_findings: usize,
    pub new_denied_decisions: Vec<DeniedDecision>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeniedDecision {
    pub policy_id: String,
    pub finding_id: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("invalid integration limit: {0}")]
    InvalidLimit(&'static str),
    #[error("invalid HTTPS URL: {0}")]
    InvalidUrl(&'static str),
    #[error(
        "webhook secret must contain between {MIN_WEBHOOK_SECRET_BYTES} and {MAX_WEBHOOK_SECRET_BYTES} bytes"
    )]
    InvalidWebhookSecret,
    #[error("invalid webhook event name")]
    InvalidWebhookEvent,
    #[error("generated payload exceeds {maximum} bytes")]
    PayloadTooLarge { maximum: usize },
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy)]
pub struct IntegrationGenerator {
    limits: IntegrationLimits,
}

impl IntegrationGenerator {
    pub fn new(limits: IntegrationLimits) -> Result<Self, IntegrationError> {
        Ok(Self {
            limits: limits.validate()?,
        })
    }

    pub fn limits(&self) -> IntegrationLimits {
        self.limits
    }

    pub fn github_sarif(&self, report: &ScanReport) -> Result<GeneratedArtifact, IntegrationError> {
        let selected = self.selected_findings(report);
        let rules: Vec<Value> = selected
            .items
            .iter()
            .map(|finding| {
                (
                    finding.rule_id.to_string(),
                    json!({
                        "id": finding.rule_id.as_str(),
                        "name": finding.kind.as_str(),
                        "shortDescription": { "text": self.finding_title(finding) },
                        "defaultConfiguration": { "level": sarif_level(finding.severity) }
                    }),
                )
            })
            .collect::<BTreeMap<String, Value>>()
            .into_values()
            .collect();
        let results: Vec<Value> = selected
            .items
            .iter()
            .map(|finding| {
                let mut result = json!({
                    "ruleId": finding.rule_id.as_str(),
                    "level": sarif_level(finding.severity),
                    "message": { "text": self.finding_message(finding) },
                    "partialFingerprints": { "hoorayFindingId": finding.id.as_str() },
                    "properties": { "kind": finding.kind.as_str(), "severity": finding.severity.as_str() }
                });
                if let Some(location) = report_location(report, finding) {
                    result["locations"] = json!([sarif_location(location)]);
                }
                result
            })
            .collect();
        let value = json!({
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "Hooray", "informationUri": "https://github.com/openhoo/hooray", "rules": rules } },
                "results": results,
                "properties": truncation_properties(selected.total, selected.items.len())
            }]
        });
        self.json_artifact(value, selected.truncated)
    }

    pub fn github_check_run(
        &self,
        report: &ScanReport,
        details_url: Option<&str>,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let details_url = details_url.map(validate_https_url).transpose()?;
        let selected = self.selected_findings(report);
        let annotations: Vec<Value> = selected
            .items
            .iter()
            .map(|finding| {
                let location = report_location(report, finding);
                json!({
                    "path": location.map_or(".", |value| value.path.as_str()),
                    "start_line": location.and_then(|value| value.start).map_or(1, |value| value.line.max(1)),
                    "end_line": location.and_then(|value| value.end.or(value.start)).map_or(1, |value| value.line.max(1)),
                    "annotation_level": github_annotation_level(finding.severity),
                    "title": self.finding_title(finding),
                    "message": self.finding_message(finding),
                    "raw_details": format!("finding_id={} rule_id={}", finding.id, finding.rule_id)
                })
            })
            .collect();
        let conclusion = if report.policy_summary.denied > 0 {
            "failure"
        } else {
            "success"
        };
        let mut value = json!({
            "name": "Hooray security policy",
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": format!("{} denied, {} warnings", report.policy_summary.denied, report.policy_summary.warned),
                "summary": bounded_summary(selected.total, selected.items.len()),
                "annotations": annotations
            }
        });
        if let Some(url) = details_url {
            value["details_url"] = Value::String(url);
        }
        self.json_artifact(value, selected.truncated)
    }

    pub fn gitlab_code_quality(
        &self,
        report: &ScanReport,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let selected = self.selected_findings(report);
        let value = Value::Array(
            selected
                .items
                .iter()
                .map(|finding| {
                    let location = report_location(report, finding);
                    json!({
                        "description": self.finding_message(finding),
                        "check_name": finding.rule_id.as_str(),
                        "fingerprint": finding.id.as_str(),
                        "severity": gitlab_quality_severity(finding.severity),
                        "location": {
                            "path": location.map_or(".", |value| value.path.as_str()),
                            "lines": { "begin": location.and_then(|value| value.start).map_or(1, |value| value.line.max(1)) }
                        },
                        "categories": ["Security"],
                        "hooray_truncated": selected.truncated
                    })
                })
                .collect(),
        );
        self.json_artifact(value, selected.truncated)
    }

    pub fn signed_webhook(
        &self,
        url: &str,
        secret: &[u8],
        event: &str,
        payload: &Value,
    ) -> Result<SignedWebhook, IntegrationError> {
        let url = validate_https_url(url)?;
        if !(MIN_WEBHOOK_SECRET_BYTES..=MAX_WEBHOOK_SECRET_BYTES).contains(&secret.len()) {
            return Err(IntegrationError::InvalidWebhookSecret);
        }
        if event.is_empty()
            || event.len() > MAX_EVENT_BYTES
            || !event
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(IntegrationError::InvalidWebhookEvent);
        }
        let body = serde_json::to_vec(payload)?;
        self.ensure_payload_size(body.len())?;
        let signature = webhook_signature(secret, event, &body);
        Ok(SignedWebhook {
            url,
            headers: BTreeMap::from([
                ("content-type".into(), "application/json".into()),
                ("x-hooray-event".into(), event.into()),
                (
                    "x-hooray-signature-256".into(),
                    format!("{WEBHOOK_SIGNATURE_VERSION}={signature}"),
                ),
            ]),
            body,
        })
    }

    pub fn verify_webhook_signature(
        &self,
        secret: &[u8],
        event: &str,
        body: &[u8],
        supplied: &str,
    ) -> bool {
        if !(MIN_WEBHOOK_SECRET_BYTES..=MAX_WEBHOOK_SECRET_BYTES).contains(&secret.len())
            || event.is_empty()
            || event.len() > MAX_EVENT_BYTES
            || body.len() > self.limits.max_payload_bytes
        {
            return false;
        }
        let expected = format!(
            "{WEBHOOK_SIGNATURE_VERSION}={}",
            webhook_signature(secret, event, body)
        );
        constant_time_eq(expected.as_bytes(), supplied.as_bytes())
    }

    pub fn slack_summary(
        &self,
        report: &ScanReport,
        dashboard_url: Option<&str>,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let dashboard_url = dashboard_url.map(validate_https_url).transpose()?;
        let selected = self.selected_findings(report);
        let top: Vec<Value> = selected
            .items
            .iter()
            .take(10)
            .map(|finding| {
                json!({
                    "type": "mrkdwn",
                    "text": format!("*{}* — {}", escape_slack(&self.finding_title(finding)), escape_slack(&self.finding_message(finding)))
                })
            })
            .collect();
        let status = if report.policy_summary.denied == 0 {
            "PASSED"
        } else {
            "DENIED"
        };
        let mut blocks = vec![
            json!({ "type": "header", "text": { "type": "plain_text", "text": format!("Hooray scan {status}") } }),
            json!({ "type": "section", "fields": [
                { "type": "mrkdwn", "text": format!("*Denied:* {}", report.policy_summary.denied) },
                { "type": "mrkdwn", "text": format!("*Warnings:* {}", report.policy_summary.warned) },
                { "type": "mrkdwn", "text": format!("*Findings:* {}", report.findings.len()) },
                { "type": "mrkdwn", "text": format!("*Run:* `{}`", escape_slack(report.run.id.as_str())) }
            ] }),
        ];
        if !top.is_empty() {
            blocks.push(json!({ "type": "section", "fields": top }));
        }
        if selected.truncated {
            blocks.push(json!({ "type": "context", "elements": [{ "type": "mrkdwn", "text": bounded_summary(selected.total, selected.items.len()) }] }));
        }
        if let Some(url) = dashboard_url {
            blocks.push(json!({ "type": "actions", "elements": [{ "type": "button", "text": { "type": "plain_text", "text": "View report" }, "url": url }] }));
        }
        self.json_artifact(
            json!({
                "text": format!("Hooray scan {status}: {} denied, {} warnings", report.policy_summary.denied, report.policy_summary.warned),
                "blocks": blocks
            }),
            selected.truncated,
        )
    }

    pub fn pre_commit_config(&self) -> Result<GeneratedArtifact, IntegrationError> {
        self.text_artifact(
            "text/yaml",
            "repos:\n  - repo: https://github.com/openhoo/hooray\n    rev: v0.2.1\n    hooks:\n      - id: hooray\n        name: Hooray security policy\n        entry: hooray scan project . --format json\n        language: rust\n        pass_filenames: false\n        stages: [pre-commit, pre-push]\n",
        )
    }

    pub fn github_actions_workflow(&self) -> Result<GeneratedArtifact, IntegrationError> {
        self.text_artifact(
            "text/yaml",
            "name: Hooray\n\non:\n  pull_request:\n  push:\n    branches: [main]\n\npermissions:\n  contents: read\n  security-events: write\n  checks: write\n\njobs:\n  hooray:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - run: cargo install hooray --locked\n      - run: hooray scan project . --format sarif --output hooray.sarif\n      - uses: github/codeql-action/upload-sarif@v3\n        if: always()\n        with:\n          sarif_file: hooray.sarif\n",
        )
    }

    pub fn gitlab_ci_include(&self) -> Result<GeneratedArtifact, IntegrationError> {
        self.text_artifact(
            "text/yaml",
            "hooray-security:\n  stage: test\n  image: rust:1.90\n  variables:\n    CARGO_NET_GIT_FETCH_WITH_CLI: \"true\"\n  script:\n    - cargo install hooray --locked\n    - hooray scan project . --format gitlab-code-quality --output gl-code-quality-report.json\n  artifacts:\n    when: always\n    reports:\n      codequality: gl-code-quality-report.json\n    expire_in: 1 week\n",
        )
    }

    pub fn vscode_diagnostics(
        &self,
        report: &ScanReport,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let selected = self.selected_findings(report);
        let diagnostics: Vec<Value> = selected
            .items
            .iter()
            .map(|finding| vscode_diagnostic(report, finding, self))
            .collect();
        self.json_artifact(
            json!({
                "schemaVersion": 1,
                "source": "hooray",
                "diagnostics": diagnostics,
                "truncation": truncation_properties(selected.total, selected.items.len())
            }),
            selected.truncated,
        )
    }

    pub fn lsp_publish_diagnostics(
        &self,
        report: &ScanReport,
        document_uri: &str,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let uri = validate_document_uri(document_uri)?;
        let selected = self.selected_findings(report);
        let diagnostics: Vec<Value> = selected
            .items
            .iter()
            .filter(|finding| {
                report_location(report, finding)
                    .is_none_or(|location| uri.ends_with(&percent_encode_path(&location.path)))
            })
            .map(|finding| lsp_diagnostic(report, finding, self))
            .collect();
        self.json_artifact(
            json!({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": uri,
                    "version": Value::Null,
                    "diagnostics": diagnostics,
                    "hoorayTruncation": truncation_properties(selected.total, selected.items.len())
                }
            }),
            selected.truncated,
        )
    }

    pub fn pull_request_gate(&self, diff: &ReportDiff, current: &ScanReport) -> PullRequestGate {
        let introduced: BTreeSet<&FindingId> = diff.introduced.iter().collect();
        let mut denied: Vec<DeniedDecision> = current
            .policy_decisions
            .iter()
            .filter(|decision| {
                decision.outcome == PolicyOutcome::Deny
                    && decision
                        .finding_id
                        .as_ref()
                        .is_some_and(|finding_id| introduced.contains(finding_id))
            })
            .map(|decision| DeniedDecision {
                policy_id: decision.policy_id.to_string(),
                finding_id: decision.finding_id.as_ref().unwrap().to_string(),
                reason: self.clean_text(&decision.reason),
            })
            .collect();
        denied.sort();
        let truncated = denied.len() > self.limits.max_annotations;
        denied.truncate(self.limits.max_annotations);
        PullRequestGate {
            passed: denied.is_empty() && !truncated,
            introduced_findings: diff.introduced.len(),
            new_denied_decisions: denied,
            truncated,
        }
    }

    fn selected_findings<'a>(&self, report: &'a ScanReport) -> Selection<'a> {
        let mut items: Vec<&Finding> = report.findings.values().collect();
        items.sort_by(|left, right| {
            severity_rank(right.severity)
                .cmp(&severity_rank(left.severity))
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = items.len();
        items.truncate(self.limits.max_annotations);
        Selection {
            truncated: items.len() < total,
            items,
            total,
        }
    }

    fn finding_title(&self, finding: &Finding) -> String {
        if finding.kind == FindingKind::Secret {
            return format!("Secret detected ({})", finding.rule_id);
        }
        self.clean_text(
            finding
                .summary
                .as_deref()
                .unwrap_or_else(|| finding.rule_id.as_str()),
        )
    }

    fn finding_message(&self, finding: &Finding) -> String {
        if finding.kind == FindingKind::Secret {
            return format!(
                "A secret-like value was detected and redacted. finding_id={}",
                finding.id
            );
        }
        self.clean_text(
            finding
                .details
                .as_deref()
                .or(finding.summary.as_deref())
                .unwrap_or_else(|| finding.rule_id.as_str()),
        )
    }

    fn clean_text(&self, value: &str) -> String {
        truncate_utf8(&redact_secrets(value), self.limits.max_text_bytes)
    }

    fn json_artifact(
        &self,
        value: Value,
        truncated: bool,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        let body = serde_json::to_vec(&value)?;
        self.ensure_payload_size(body.len())?;
        Ok(GeneratedArtifact {
            content_type: "application/json",
            body,
            truncated,
        })
    }

    fn text_artifact(
        &self,
        content_type: &'static str,
        body: &str,
    ) -> Result<GeneratedArtifact, IntegrationError> {
        self.ensure_payload_size(body.len())?;
        Ok(GeneratedArtifact {
            content_type,
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
    }

    fn ensure_payload_size(&self, size: usize) -> Result<(), IntegrationError> {
        if size > self.limits.max_payload_bytes {
            Err(IntegrationError::PayloadTooLarge {
                maximum: self.limits.max_payload_bytes,
            })
        } else {
            Ok(())
        }
    }
}

struct Selection<'a> {
    items: Vec<&'a Finding>,
    total: usize,
    truncated: bool,
}

fn report_location<'a>(report: &'a ScanReport, finding: &Finding) -> Option<&'a Location> {
    let location_id = finding.location_id.as_ref()?;
    report
        .inventory
        .components
        .values()
        .flat_map(|component| component.locations.iter())
        .find(|location| &location.id == location_id)
}

fn sarif_location(location: &Location) -> Value {
    let start = location.start;
    let end = location.end.or(start);
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": percent_encode_path(&location.path) },
            "region": {
                "startLine": start.map_or(1, |value| value.line.max(1)),
                "startColumn": start.map_or(1, |value| value.column.max(1)),
                "endLine": end.map_or(1, |value| value.line.max(1)),
                "endColumn": end.map_or(1, |value| value.column.max(1))
            }
        }
    })
}

fn vscode_diagnostic(
    report: &ScanReport,
    finding: &Finding,
    generator: &IntegrationGenerator,
) -> Value {
    let location = report_location(report, finding);
    json!({
        "uri": location.map(|value| format!("file:///{}", percent_encode_path(value.path.trim_start_matches('/')))),
        "range": lsp_range(location),
        "severity": lsp_severity(finding.severity),
        "code": finding.rule_id.as_str(),
        "source": "hooray",
        "message": generator.finding_message(finding),
        "findingId": finding.id.as_str(),
        "tags": if finding.kind == FindingKind::Secret { vec!["redacted"] } else { Vec::new() }
    })
}

fn lsp_diagnostic(
    report: &ScanReport,
    finding: &Finding,
    generator: &IntegrationGenerator,
) -> Value {
    json!({
        "range": lsp_range(report_location(report, finding)),
        "severity": lsp_severity(finding.severity),
        "code": finding.rule_id.as_str(),
        "codeDescription": { "href": format!("https://github.com/openhoo/hooray#{}", finding.kind.as_str()) },
        "source": "hooray",
        "message": generator.finding_message(finding),
        "data": { "findingId": finding.id.as_str(), "kind": finding.kind.as_str() }
    })
}

fn lsp_range(location: Option<&Location>) -> Value {
    let start = location.and_then(|value| value.start);
    let end = location.and_then(|value| value.end.or(value.start));
    json!({
        "start": {
            "line": start.map_or(0, |value| value.line.saturating_sub(1)),
            "character": start.map_or(0, |value| value.column.saturating_sub(1))
        },
        "end": {
            "line": end.map_or(0, |value| value.line.saturating_sub(1)),
            "character": end.map_or(1, |value| value.column.max(1))
        }
    })
}

fn truncation_properties(total: usize, included: usize) -> Value {
    json!({
        "truncated": included < total,
        "total": total,
        "included": included,
        "omitted": total.saturating_sub(included)
    })
}

fn bounded_summary(total: usize, included: usize) -> String {
    if included < total {
        format!(
            "Included {included} of {total} findings; {} omitted by configured limit.",
            total - included
        )
    } else {
        format!("Included all {total} findings.")
    }
}

fn validate_https_url(value: &str) -> Result<String, IntegrationError> {
    if value.len() > MAX_URL_BYTES {
        return Err(IntegrationError::InvalidUrl("URL is too long"));
    }
    let url = Url::parse(value).map_err(|_| IntegrationError::InvalidUrl("malformed URL"))?;
    if url.scheme() != "https" {
        return Err(IntegrationError::InvalidUrl("HTTPS is required"));
    }
    if url.host_str().is_none() {
        return Err(IntegrationError::InvalidUrl("host is required"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IntegrationError::InvalidUrl("credentials are forbidden"));
    }
    if url.fragment().is_some() {
        return Err(IntegrationError::InvalidUrl("fragments are forbidden"));
    }
    Ok(url.to_string())
}

fn validate_document_uri(value: &str) -> Result<String, IntegrationError> {
    if value.len() > MAX_URL_BYTES {
        return Err(IntegrationError::InvalidUrl("document URI is too long"));
    }
    let url =
        Url::parse(value).map_err(|_| IntegrationError::InvalidUrl("malformed document URI"))?;
    if url.scheme() != "file" || url.host_str().is_some_and(|host| !host.is_empty()) {
        return Err(IntegrationError::InvalidUrl(
            "document URI must be a local file URI",
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(IntegrationError::InvalidUrl(
            "document URI credentials, query, and fragment are forbidden",
        ));
    }
    Ok(url.to_string())
}

fn webhook_signature(secret: &[u8], event: &str, body: &[u8]) -> String {
    let mut key = [0_u8; 64];
    if secret.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(b"hooray.webhook.v1\0");
    inner.update((event.len() as u64).to_be_bytes());
    inner.update(event.as_bytes());
    inner.update((body.len() as u64).to_be_bytes());
    inner.update(body);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(b"hooray.webhook.v1\0");
    outer.update(inner_digest);
    hex_lower(&outer.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn redact_secrets(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for token in value.split_inclusive(char::is_whitespace) {
        let word_end = token.trim_end_matches(char::is_whitespace).len();
        let (word, suffix) = token.split_at(word_end);
        if looks_secret(word) {
            output.push_str(REDACTED);
        } else {
            output.push_str(word);
        }
        output.push_str(suffix);
    }
    if output.is_empty() && !value.is_empty() {
        REDACTED.into()
    } else {
        output
    }
}

fn looks_secret(word: &str) -> bool {
    let trimmed = word.trim_matches(|character: char| {
        matches!(
            character,
            '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']'
        )
    });
    let lower = trimmed.to_ascii_lowercase();
    let secret_assignment = [
        "token=",
        "secret=",
        "password=",
        "passwd=",
        "api_key=",
        "apikey=",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    secret_assignment
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("gho_")
        || trimmed.starts_with("github_pat_")
        || trimmed.starts_with("glpat-")
        || trimmed.starts_with("xoxb-")
        || trimmed.starts_with("xoxp-")
        || (trimmed.starts_with("AKIA") && trimmed.len() >= 20)
        || lower.starts_with("bearer:")
        || lower.starts_with("bearer=")
        || trimmed.contains("PRIVATE_KEY")
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    const NOTE: &str = "… [truncated]";
    if maximum <= NOTE.len() {
        return NOTE[..maximum].to_owned();
    }
    let mut end = maximum - NOTE.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{NOTE}", &value[..end])
}

fn escape_slack(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn percent_encode_path(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Unknown => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

fn github_annotation_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "failure",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "notice",
    }
}

fn gitlab_quality_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "blocker",
        Severity::High => "critical",
        Severity::Medium => "major",
        Severity::Low => "minor",
        Severity::Unknown => "info",
    }
}

fn lsp_severity(severity: Severity) -> u8 {
    match severity {
        Severity::Critical | Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Unknown => 4,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::Value;

    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, Confidence, Evidence, FindingStatus, Inventory, LocationId,
        PolicyDecision, PolicyId, PolicySummary, Position, RuleId, RunId, RunMetadata,
    };

    fn generator(max_annotations: usize) -> IntegrationGenerator {
        IntegrationGenerator::new(IntegrationLimits {
            max_annotations,
            max_payload_bytes: 1024 * 1024,
            max_text_bytes: 256,
        })
        .unwrap()
    }

    fn finding(id: &str, kind: FindingKind, severity: Severity, location: bool) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            kind,
            rule_id: RuleId::new(format!("rule:{id}")).unwrap(),
            advisory_id: None,
            component_id: None,
            location_id: location.then(|| LocationId::new(format!("location:{id}")).unwrap()),
            aliases: BTreeSet::new(),
            summary: Some(format!("Summary {id}")),
            details: Some(format!("Details {id}")),
            severity,
            confidence: Confidence::High,
            evidence: BTreeSet::new(),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        let asset_id = AssetId::new("asset:test").unwrap();
        let locations: BTreeSet<Location> = findings
            .iter()
            .filter_map(|finding| {
                finding.location_id.as_ref().map(|id| Location {
                    id: id.clone(),
                    asset_id: asset_id.clone(),
                    path: format!("src/{}.rs", finding.id),
                    start: Some(Position { line: 7, column: 3 }),
                    end: Some(Position { line: 7, column: 9 }),
                })
            })
            .collect();
        let component_id = crate::model::ComponentId::new("component:test").unwrap();
        ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new("run:test").unwrap(),
                started_at: "2026-07-21T00:00:00Z".into(),
                completed_at: Some("2026-07-21T00:00:01Z".into()),
                scanner_version: Some("test".into()),
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: Asset {
                    id: asset_id,
                    name: "test".into(),
                    kind: AssetKind::Repository,
                    version: None,
                    metadata: BTreeMap::new(),
                },
                components: BTreeMap::from([(
                    component_id.clone(),
                    crate::model::Component {
                        identity: component_id,
                        name: "test".into(),
                        version: "1".into(),
                        purl: "pkg:cargo/test@1".into(),
                        scope: crate::model::Scope::Runtime,
                        provenance: BTreeSet::new(),
                        licenses: BTreeSet::new(),
                        locations,
                    },
                )]),
                dependencies: BTreeSet::new(),
            },
            findings: findings
                .into_iter()
                .map(|finding| (finding.id.clone(), finding))
                .collect(),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        }
    }

    fn json_artifact(artifact: GeneratedArtifact) -> Value {
        assert_eq!(artifact.content_type, "application/json");
        serde_json::from_slice(&artifact.body).unwrap()
    }

    #[test]
    fn github_payloads_follow_sarif_and_check_run_shapes() {
        let report = report(vec![finding(
            "finding:critical",
            FindingKind::Sast,
            Severity::Critical,
            true,
        )]);
        let sarif = json_artifact(generator(10).github_sarif(&report).unwrap());
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        let check = json_artifact(
            generator(10)
                .github_check_run(&report, Some("https://security.example/report/1"))
                .unwrap(),
        );
        assert_eq!(check["status"], "completed");
        assert_eq!(check["details_url"], "https://security.example/report/1");
        assert_eq!(
            check["output"]["annotations"][0]["path"],
            "src/finding:critical.rs"
        );
    }

    #[test]
    fn gitlab_code_quality_report_has_required_contract() {
        let report = report(vec![finding(
            "finding:high",
            FindingKind::Vulnerability,
            Severity::High,
            true,
        )]);
        let quality = json_artifact(generator(10).gitlab_code_quality(&report).unwrap());
        assert!(quality.is_array());
        assert_eq!(quality[0]["severity"], "critical");
        assert!(quality[0]["fingerprint"].is_string());
        assert_eq!(quality[0]["location"]["path"], "src/finding:high.rs");
        assert_eq!(quality[0]["location"]["lines"]["begin"], 7);
    }

    #[test]
    fn webhook_signature_is_deterministic_domain_separated_and_constant_time_verified() {
        let generator = generator(10);
        let secret = b"0123456789abcdef0123456789abcdef";
        let payload = json!({"run":"one"});
        let first = generator
            .signed_webhook(
                "https://hooks.example/hooray",
                secret,
                "scan.completed",
                &payload,
            )
            .unwrap();
        let second = generator
            .signed_webhook(
                "https://hooks.example/hooray",
                secret,
                "scan.completed",
                &payload,
            )
            .unwrap();
        assert_eq!(first, second);
        let signature = &first.headers["x-hooray-signature-256"];
        assert_eq!(signature.len(), 67);
        assert!(generator.verify_webhook_signature(
            secret,
            "scan.completed",
            &first.body,
            signature
        ));
        assert!(!generator.verify_webhook_signature(secret, "scan.failed", &first.body, signature));
        assert!(!generator.verify_webhook_signature(secret, "scan.completed", b"{}", signature));
        let mut wrong = signature.clone();
        wrong.replace_range(66..67, if wrong.ends_with('0') { "1" } else { "0" });
        assert!(!generator.verify_webhook_signature(secret, "scan.completed", &first.body, &wrong));
    }

    #[test]
    fn urls_and_webhook_inputs_are_strictly_bounded() {
        let generator = generator(10);
        assert!(matches!(
            generator.signed_webhook(
                "http://hooks.example",
                b"0123456789abcdef",
                "scan",
                &json!({})
            ),
            Err(IntegrationError::InvalidUrl(_))
        ));
        assert!(matches!(
            generator.signed_webhook(
                "https://user:pass@hooks.example",
                b"0123456789abcdef",
                "scan",
                &json!({})
            ),
            Err(IntegrationError::InvalidUrl(_))
        ));
        assert!(matches!(
            generator.signed_webhook("https://hooks.example", b"short", "scan", &json!({})),
            Err(IntegrationError::InvalidWebhookSecret)
        ));
        assert!(matches!(
            generator.signed_webhook(
                "https://hooks.example",
                b"0123456789abcdef",
                "bad event",
                &json!({})
            ),
            Err(IntegrationError::InvalidWebhookEvent)
        ));
        assert!(
            generator
                .github_check_run(&report(vec![]), Some("javascript:alert(1)"))
                .is_err()
        );
        assert!(
            generator
                .lsp_publish_diagnostics(&report(vec![]), "https://example/file.rs")
                .is_err()
        );
    }

    #[test]
    fn annotations_are_deterministically_sorted_and_truncation_is_explicit() {
        let report = report(vec![
            finding("finding:low", FindingKind::Sast, Severity::Low, false),
            finding("finding:high-b", FindingKind::Sast, Severity::High, false),
            finding("finding:high-a", FindingKind::Sast, Severity::High, false),
        ]);
        let artifact = generator(2).github_sarif(&report).unwrap();
        assert!(artifact.truncated);
        let value = json_artifact(artifact);
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0]["partialFingerprints"]["hoorayFindingId"],
            "finding:high-a"
        );
        assert_eq!(
            results[1]["partialFingerprints"]["hoorayFindingId"],
            "finding:high-b"
        );
        assert_eq!(value["runs"][0]["properties"]["omitted"], 1);
    }

    #[test]
    fn secret_findings_and_embedded_tokens_never_leak() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
        let mut finding = finding(
            "finding:secret",
            FindingKind::Secret,
            Severity::Critical,
            false,
        );
        finding.summary = Some(format!("Leaked {secret}"));
        finding.details = Some(format!("password={secret}"));
        finding.evidence.insert(Evidence {
            description: secret.into(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::new(),
            redacted: true,
        });
        let report = report(vec![finding]);
        for artifact in [
            generator(10).github_sarif(&report).unwrap(),
            generator(10).gitlab_code_quality(&report).unwrap(),
            generator(10).slack_summary(&report, None).unwrap(),
            generator(10).vscode_diagnostics(&report).unwrap(),
        ] {
            let text = artifact.text().unwrap();
            assert!(!text.contains(secret));
            assert!(text.contains("redact") || text.contains("Secret detected"));
        }
        assert_eq!(
            generator(10).clean_text(&format!("token={secret} okay")),
            "[REDACTED] okay"
        );
    }

    #[test]
    fn slack_vscode_and_lsp_payloads_are_consumable() {
        let report = report(vec![finding(
            "finding:medium",
            FindingKind::Iac,
            Severity::Medium,
            true,
        )]);
        let slack = json_artifact(
            generator(10)
                .slack_summary(&report, Some("https://security.example/runs/1"))
                .unwrap(),
        );
        assert!(slack["blocks"].as_array().unwrap().len() >= 3);
        let vscode = json_artifact(generator(10).vscode_diagnostics(&report).unwrap());
        assert_eq!(vscode["diagnostics"][0]["severity"], 2);
        assert_eq!(vscode["diagnostics"][0]["range"]["start"]["line"], 6);
        let lsp = json_artifact(
            generator(10)
                .lsp_publish_diagnostics(&report, "file:///src/finding%3Amedium.rs")
                .unwrap(),
        );
        assert_eq!(lsp["jsonrpc"], "2.0");
        assert_eq!(lsp["method"], "textDocument/publishDiagnostics");
        assert!(lsp["params"]["diagnostics"].is_array());
    }

    #[test]
    fn generated_ci_and_pre_commit_artifacts_use_runnable_cli_and_supported_reports() {
        let generator = generator(10);
        let pre_commit = generator.pre_commit_config().unwrap();
        let pre_commit: Value = serde_yaml::from_slice(&pre_commit.body).unwrap();
        let hook = &pre_commit["repos"][0]["hooks"][0];
        assert_eq!(pre_commit["repos"][0]["rev"], "v0.2.1");
        assert_eq!(hook["entry"], "hooray scan project . --format json");
        assert_eq!(hook["pass_filenames"], false);

        let github = generator.github_actions_workflow().unwrap();
        let github_text = github.text().unwrap();
        assert!(github_text.contains("permissions:\n  contents: read"));
        assert!(github_text.contains("upload-sarif@v3"));
        assert!(github_text.contains("hooray scan project . --format sarif --output hooray.sarif"));

        let gitlab = generator.gitlab_ci_include().unwrap();
        let gitlab: Value = serde_yaml::from_slice(&gitlab.body).unwrap();
        assert_eq!(
            gitlab["hooray-security"]["script"][1],
            "hooray scan project . --format gitlab-code-quality --output gl-code-quality-report.json"
        );
        assert_eq!(
            gitlab["hooray-security"]["artifacts"]["reports"]["codequality"],
            "gl-code-quality-report.json"
        );
        assert!(
            gitlab["hooray-security"]["artifacts"]["reports"]
                .get("dependency_scanning")
                .is_none()
        );
    }

    #[test]
    fn pull_request_gate_only_blocks_new_denied_findings() {
        let mut current = report(vec![
            finding("finding:new", FindingKind::Sast, Severity::High, false),
            finding("finding:old", FindingKind::Sast, Severity::High, false),
        ]);
        current.policy_decisions = BTreeSet::from([
            PolicyDecision {
                policy_id: PolicyId::new("policy:new").unwrap(),
                finding_id: Some(FindingId::new("finding:new").unwrap()),
                outcome: PolicyOutcome::Deny,
                reason: "newly denied".into(),
                exception_id: None,
            },
            PolicyDecision {
                policy_id: PolicyId::new("policy:old").unwrap(),
                finding_id: Some(FindingId::new("finding:old").unwrap()),
                outcome: PolicyOutcome::Deny,
                reason: "existing denial".into(),
                exception_id: None,
            },
        ]);
        let diff = ReportDiff {
            introduced: vec![FindingId::new("finding:new").unwrap()],
            resolved: vec![],
            unchanged: vec![FindingId::new("finding:old").unwrap()],
        };
        let gate = generator(10).pull_request_gate(&diff, &current);
        assert!(!gate.passed);
        assert_eq!(gate.introduced_findings, 1);
        assert_eq!(gate.new_denied_decisions.len(), 1);
        assert_eq!(gate.new_denied_decisions[0].policy_id, "policy:new");
        let clean = ReportDiff {
            introduced: vec![],
            resolved: vec![],
            unchanged: diff.unchanged,
        };
        assert!(generator(10).pull_request_gate(&clean, &current).passed);
    }

    #[test]
    fn payload_limit_fails_closed_without_partial_json() {
        let generator = IntegrationGenerator::new(IntegrationLimits {
            max_annotations: 10,
            max_payload_bytes: 1_024,
            max_text_bytes: 256,
        })
        .unwrap();
        let payload = json!({ "data": "x".repeat(2_000) });
        assert!(matches!(
            generator.signed_webhook(
                "https://hooks.example",
                b"0123456789abcdef",
                "scan",
                &payload
            ),
            Err(IntegrationError::PayloadTooLarge { maximum: 1_024 })
        ));
    }
}
