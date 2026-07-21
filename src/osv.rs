use std::collections::{BTreeMap, BTreeSet};

use futures::{StreamExt, stream};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{Component, Finding, Severity};

const MAX_BATCH_SIZE: usize = 1_000;

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("invalid OSV API base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("OSV request to {endpoint} failed: {source}")]
    Request {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("OSV request to {endpoint} returned HTTP {status}: {body}")]
    Http {
        endpoint: String,
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("failed to decode OSV response from {endpoint}: {source}")]
    Decode {
        endpoint: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("OSV batch response contained {actual} results for {expected} queries")]
    ResultCount { expected: usize, actual: usize },
}

pub struct OsvClient {
    http: Client,
    base_url: Url,
    concurrency: usize,
}

impl OsvClient {
    pub fn new(base_url: &str, concurrency: usize) -> Result<Self, OsvError> {
        let mut base_url =
            Url::parse(base_url).map_err(|error| OsvError::InvalidBaseUrl(error.to_string()))?;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Ok(Self {
            http: Client::new(),
            base_url,
            concurrency: concurrency.max(1),
        })
    }

    pub async fn scan(&self, components: &[Component]) -> Result<Vec<Finding>, OsvError> {
        let mut components_by_purl: BTreeMap<&str, Vec<&Component>> = BTreeMap::new();
        for component in components {
            components_by_purl
                .entry(&component.purl)
                .or_default()
                .push(component);
        }

        let purls: Vec<&str> = components_by_purl.keys().copied().collect();
        let mut vulnerability_ids: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();

        for chunk in purls.chunks(MAX_BATCH_SIZE) {
            let queries: Vec<Query<'_>> = chunk.iter().map(|purl| Query::new(purl, None)).collect();
            let results = self.query_batch(&queries).await?;

            for (purl, result) in chunk.iter().copied().zip(results) {
                let ids = vulnerability_ids.entry(purl).or_default();
                ids.extend(
                    result
                        .vulns
                        .into_iter()
                        .map(|vulnerability| vulnerability.id),
                );

                let mut page_token = result.next_page_token;
                while let Some(token) = page_token {
                    let page = self
                        .query_batch(&[Query::new(purl, Some(&token))])
                        .await?
                        .into_iter()
                        .next()
                        .expect("validated one-result response");
                    ids.extend(page.vulns.into_iter().map(|vulnerability| vulnerability.id));
                    page_token = page.next_page_token;
                }
            }
        }

        let unique_ids: BTreeSet<String> = vulnerability_ids
            .values()
            .flat_map(|ids| ids.iter().cloned())
            .collect();
        let details = stream::iter(unique_ids.into_iter().map(|id| async move {
            let detail = self.fetch_vulnerability(&id).await?;
            Ok::<_, OsvError>((id, detail))
        }))
        .buffer_unordered(self.concurrency)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(map_findings(
            &components_by_purl,
            &vulnerability_ids,
            &details,
        ))
    }

    async fn query_batch(&self, queries: &[Query<'_>]) -> Result<Vec<QueryResult>, OsvError> {
        let endpoint = self
            .base_url
            .join("v1/querybatch")
            .expect("static relative URL");
        let response = self
            .http
            .post(endpoint.clone())
            .json(&BatchRequest { queries })
            .send()
            .await
            .map_err(|source| OsvError::Request {
                endpoint: endpoint.to_string(),
                source,
            })?;
        let batch: BatchResponse = decode_response(response, &endpoint).await?;
        if batch.results.len() != queries.len() {
            return Err(OsvError::ResultCount {
                expected: queries.len(),
                actual: batch.results.len(),
            });
        }
        Ok(batch.results)
    }

    async fn fetch_vulnerability(&self, id: &str) -> Result<Vulnerability, OsvError> {
        let mut endpoint = self
            .base_url
            .join("v1/vulns/")
            .expect("static relative URL");
        endpoint
            .path_segments_mut()
            .expect("HTTP URL supports path segments")
            .push(id);
        let response = self
            .http
            .get(endpoint.clone())
            .send()
            .await
            .map_err(|source| OsvError::Request {
                endpoint: endpoint.to_string(),
                source,
            })?;
        decode_response(response, &endpoint).await
    }
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: Response,
    endpoint: &Url,
) -> Result<T, OsvError> {
    let status = response.status();
    let bytes = response.bytes().await.map_err(|source| OsvError::Request {
        endpoint: endpoint.to_string(),
        source,
    })?;
    if !status.is_success() {
        return Err(OsvError::Http {
            endpoint: endpoint.to_string(),
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| OsvError::Decode {
        endpoint: endpoint.to_string(),
        source,
    })
}

#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: &'a [Query<'a>],
}

#[derive(Serialize)]
struct Query<'a> {
    package: Package<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

impl<'a> Query<'a> {
    fn new(purl: &'a str, page_token: Option<&'a str>) -> Self {
        Self {
            package: Package { purl },
            page_token,
        }
    }
}

#[derive(Serialize)]
struct Package<'a> {
    purl: &'a str,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnerabilityReference>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct VulnerabilityReference {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    modified: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Value,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: Value,
}

#[derive(Debug, Deserialize)]
struct Affected {
    #[serde(default)]
    database_specific: Value,
    #[serde(default)]
    ecosystem_specific: Value,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

fn map_findings(
    components_by_purl: &BTreeMap<&str, Vec<&Component>>,
    vulnerability_ids: &BTreeMap<&str, BTreeSet<String>>,
    details: &BTreeMap<String, Vulnerability>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (purl, ids) in vulnerability_ids {
        let Some(components) = components_by_purl.get(purl) else {
            continue;
        };
        for id in ids {
            let Some(vulnerability) = details.get(id) else {
                continue;
            };
            for component in components {
                findings.push(Finding {
                    id: vulnerability.id.clone(),
                    package_name: component.name.clone(),
                    package_version: component.version.clone(),
                    purl: component.purl.clone(),
                    aliases: vulnerability.aliases.clone(),
                    summary: vulnerability.summary.clone(),
                    details: vulnerability.details.clone(),
                    severity: vulnerability_severity(vulnerability),
                    modified: vulnerability.modified.clone(),
                });
            }
        }
    }
    findings.sort_by(|left, right| {
        (
            &left.package_name,
            &left.package_version,
            &left.purl,
            &left.id,
        )
            .cmp(&(
                &right.package_name,
                &right.package_version,
                &right.purl,
                &right.id,
            ))
    });
    findings
}

fn vulnerability_severity(vulnerability: &Vulnerability) -> Severity {
    vulnerability
        .severity
        .iter()
        .chain(
            vulnerability
                .affected
                .iter()
                .flat_map(|affected| affected.severity.iter()),
        )
        .filter_map(severity_from_osv)
        .chain(severity_strings(&vulnerability.database_specific))
        .chain(vulnerability.affected.iter().flat_map(|affected| {
            severity_strings(&affected.database_specific)
                .chain(severity_strings(&affected.ecosystem_specific))
        }))
        .max()
        .unwrap_or(Severity::Unknown)
}

fn severity_from_osv(severity: &OsvSeverity) -> Option<Severity> {
    if !severity.kind.to_ascii_uppercase().starts_with("CVSS") {
        return severity.score.as_str().and_then(severity_from_label);
    }
    let score = match &severity.score {
        Value::Number(number) => number.as_f64(),
        Value::String(value) => value.parse::<f64>().ok().or_else(|| cvss_score(value)),
        _ => None,
    }?;
    Some(severity_from_score(score))
}

fn severity_strings(value: &Value) -> impl Iterator<Item = Severity> + '_ {
    let mut severities = Vec::new();
    collect_severity_strings(value, false, &mut severities);
    severities.into_iter()
}

fn collect_severity_strings(value: &Value, severity_key: bool, output: &mut Vec<Severity>) {
    match value {
        Value::String(label) if severity_key => {
            if let Some(severity) = severity_from_label(label) {
                output.push(severity);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_severity_strings(value, severity_key, output);
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields {
                collect_severity_strings(value, key.eq_ignore_ascii_case("severity"), output);
            }
        }
        _ => {}
    }
}

fn severity_from_label(label: &str) -> Option<Severity> {
    match label.trim().to_ascii_lowercase().as_str() {
        "unknown" | "none" | "negligible" => Some(Severity::Unknown),
        "low" => Some(Severity::Low),
        "moderate" | "medium" => Some(Severity::Medium),
        "important" | "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn severity_from_score(score: f64) -> Severity {
    if !score.is_finite() || score <= 0.0 || score > 10.0 {
        Severity::Unknown
    } else if score < 4.0 {
        Severity::Low
    } else if score < 7.0 {
        Severity::Medium
    } else if score < 9.0 {
        Severity::High
    } else {
        Severity::Critical
    }
}

fn cvss_score(vector: &str) -> Option<f64> {
    if vector.starts_with("CVSS:3.0/") || vector.starts_with("CVSS:3.1/") {
        cvss_v3_score(vector)
    } else if vector.starts_with("CVSS:2.0/") || vector.starts_with("AV:") {
        cvss_v2_score(vector)
    } else {
        None
    }
}

fn cvss_v3_score(vector: &str) -> Option<f64> {
    let metrics = parse_cvss_metrics(vector);
    let scope_changed = metrics.get("S")? == &"C";
    let attack_vector = metric(
        &metrics,
        "AV",
        &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)],
    )?;
    let attack_complexity = metric(&metrics, "AC", &[("L", 0.77), ("H", 0.44)])?;
    let privileges_required = metric(
        &metrics,
        "PR",
        if scope_changed {
            &[("N", 0.85), ("L", 0.68), ("H", 0.5)]
        } else {
            &[("N", 0.85), ("L", 0.62), ("H", 0.27)]
        },
    )?;
    let user_interaction = metric(&metrics, "UI", &[("N", 0.85), ("R", 0.62)])?;
    let confidentiality = metric(&metrics, "C", &[("N", 0.0), ("L", 0.22), ("H", 0.56)])?;
    let integrity = metric(&metrics, "I", &[("N", 0.0), ("L", 0.22), ("H", 0.56)])?;
    let availability = metric(&metrics, "A", &[("N", 0.0), ("L", 0.22), ("H", 0.56)])?;

    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let impact_base = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability);
    let impact = if scope_changed {
        7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02).powf(15.0)
    } else {
        6.42 * impact_base
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(round_up_tenth(raw.min(10.0)))
}

fn cvss_v2_score(vector: &str) -> Option<f64> {
    let metrics = parse_cvss_metrics(vector);
    let access_vector = metric(&metrics, "AV", &[("L", 0.395), ("A", 0.646), ("N", 1.0)])?;
    let access_complexity = metric(&metrics, "AC", &[("H", 0.35), ("M", 0.61), ("L", 0.71)])?;
    let authentication = metric(&metrics, "Au", &[("M", 0.45), ("S", 0.56), ("N", 0.704)])?;
    let confidentiality = metric(&metrics, "C", &[("N", 0.0), ("P", 0.275), ("C", 0.66)])?;
    let integrity = metric(&metrics, "I", &[("N", 0.0), ("P", 0.275), ("C", 0.66)])?;
    let availability = metric(&metrics, "A", &[("N", 0.0), ("P", 0.275), ("C", 0.66)])?;
    let impact = 10.41 * (1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability));
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 20.0 * access_vector * access_complexity * authentication;
    Some(round_nearest_tenth(
        ((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176,
    ))
}

fn parse_cvss_metrics(vector: &str) -> BTreeMap<&str, &str> {
    vector
        .split('/')
        .filter_map(|part| part.split_once(':'))
        .filter(|(key, _)| *key != "CVSS")
        .collect()
}

fn metric(metrics: &BTreeMap<&str, &str>, name: &str, values: &[(&str, f64)]) -> Option<f64> {
    let actual = metrics.get(name)?;
    values
        .iter()
        .find_map(|(value, weight)| (actual == value).then_some(*weight))
}

fn round_up_tenth(value: f64) -> f64 {
    (value * 10.0 - 1e-10).ceil() / 10.0
}

fn round_nearest_tenth(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_cvss_score_boundaries() {
        assert_eq!(severity_from_score(0.0), Severity::Unknown);
        assert_eq!(severity_from_score(0.1), Severity::Low);
        assert_eq!(severity_from_score(3.9), Severity::Low);
        assert_eq!(severity_from_score(4.0), Severity::Medium);
        assert_eq!(severity_from_score(6.9), Severity::Medium);
        assert_eq!(severity_from_score(7.0), Severity::High);
        assert_eq!(severity_from_score(8.9), Severity::High);
        assert_eq!(severity_from_score(9.0), Severity::Critical);
        assert_eq!(severity_from_score(10.0), Severity::Critical);
        assert_eq!(severity_from_score(10.1), Severity::Unknown);
        assert_eq!(severity_from_score(f64::NAN), Severity::Unknown);
    }

    #[test]
    fn calculates_cvss_vectors() {
        assert_eq!(
            cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), Some(7.5));
        assert_eq!(cvss_score("not-a-vector"), None);
    }

    #[test]
    fn uses_most_conservative_recognized_severity_source() {
        let vulnerability: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-1",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}],
            "database_specific": {"severity": "MODERATE"},
            "affected": [{
                "database_specific": {"severity": "critical"},
                "ecosystem_specific": {"severity": "LOW"}
            }]
        })).unwrap();
        assert_eq!(vulnerability_severity(&vulnerability), Severity::Critical);
    }

    #[test]
    fn maps_responses_to_each_component_and_sorts_findings() {
        let first = Component {
            name: "zeta".into(),
            version: "1.0".into(),
            purl: "pkg:cargo/shared@1.0".into(),
        };
        let second = Component {
            name: "alpha".into(),
            version: "1.0".into(),
            purl: "pkg:cargo/shared@1.0".into(),
        };
        let mut components = BTreeMap::new();
        components.insert(first.purl.as_str(), vec![&first, &second]);
        let mut ids = BTreeMap::new();
        ids.insert(
            first.purl.as_str(),
            BTreeSet::from(["OSV-2".into(), "OSV-1".into()]),
        );
        let detail_one: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-1", "aliases": ["CVE-1"], "summary": "one",
            "modified": "2026-01-01T00:00:00Z", "database_specific": {"severity": "HIGH"}
        }))
        .unwrap();
        let detail_two: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-2", "details": "two"
        }))
        .unwrap();
        let details = BTreeMap::from([("OSV-1".into(), detail_one), ("OSV-2".into(), detail_two)]);

        let findings = map_findings(&components, &ids, &details);

        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].package_name, "alpha");
        assert_eq!(findings[0].id, "OSV-1");
        assert_eq!(findings[0].aliases, ["CVE-1"]);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].id, "OSV-2");
        assert_eq!(findings[2].package_name, "zeta");
    }
}
