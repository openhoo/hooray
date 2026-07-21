use std::collections::{BTreeMap, BTreeSet};

use futures::{StreamExt, stream};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    analysis::{
        ApplicabilityAnalyzer, ApplicabilityInput, OsvAffectedRange, OsvEvent, OsvRangeType,
    },
    model::{
        Component, ComponentId, Confidence, Evidence, Finding, FindingId, FindingKind,
        FindingStatus, Inventory, Remediation, RuleId, Severity, stable_finding_id,
    },
};

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
    #[error("OSV vulnerability contains an empty identifier")]
    InvalidVulnerabilityId,
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

    pub async fn scan(
        &self,
        inventory: &Inventory,
    ) -> Result<BTreeMap<FindingId, Finding>, OsvError> {
        self.scan_component_map(&inventory.components, Some(inventory))
            .await
    }

    pub async fn scan_components(
        &self,
        components: &BTreeMap<ComponentId, Component>,
    ) -> Result<BTreeMap<FindingId, Finding>, OsvError> {
        self.scan_component_map(components, None).await
    }

    async fn scan_component_map(
        &self,
        components: &BTreeMap<ComponentId, Component>,
        inventory: Option<&Inventory>,
    ) -> Result<BTreeMap<FindingId, Finding>, OsvError> {
        let mut components_by_purl: BTreeMap<&str, Vec<&Component>> = BTreeMap::new();
        for component in components.values() {
            components_by_purl
                .entry(&component.purl)
                .or_default()
                .push(component);
        }
        for matches in components_by_purl.values_mut() {
            matches.sort_by(|left, right| left.identity.cmp(&right.identity));
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
                while let Some(token) = page_token.filter(|token| !token.is_empty()) {
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

        map_findings(&components_by_purl, &vulnerability_ids, &details, inventory)
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
        let mut endpoint = self.base_url.join("v1/vulns").expect("static relative URL");
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
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: Value,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: Option<AffectedPackage>,
    #[serde(default)]
    ranges: Vec<AffectedRange>,
    #[serde(default)]
    database_specific: Value,
    #[serde(default)]
    ecosystem_specific: Value,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    purl: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AffectedRange {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    events: Vec<AffectedEvent>,
}

#[derive(Debug, Deserialize)]
struct AffectedEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    url: String,
}

fn map_findings(
    components_by_purl: &BTreeMap<&str, Vec<&Component>>,
    vulnerability_ids: &BTreeMap<&str, BTreeSet<String>>,
    details: &BTreeMap<String, Vulnerability>,
    inventory: Option<&Inventory>,
) -> Result<BTreeMap<FindingId, Finding>, OsvError> {
    let mut findings = BTreeMap::new();
    for (purl, ids) in vulnerability_ids {
        let Some(components) = components_by_purl.get(purl) else {
            continue;
        };
        for advisory_id in ids {
            let Some(vulnerability) = details.get(advisory_id) else {
                continue;
            };
            let references: BTreeSet<String> = vulnerability
                .references
                .iter()
                .filter_map(|reference| {
                    let url = reference.url.trim();
                    (!url.is_empty()).then(|| url.to_owned())
                })
                .collect();
            for component in components {
                let rule_id = RuleId::new(format!("osv:{}", vulnerability.id))
                    .map_err(|_| OsvError::InvalidVulnerabilityId)?;
                let finding_id = stable_finding_id(
                    FindingKind::Vulnerability,
                    &rule_id,
                    Some(&component.identity),
                    None,
                );
                let affected_ranges = affected_ranges(vulnerability, &component.purl);
                let fixed_versions = fixed_versions(&affected_ranges);
                let remediation =
                    (!fixed_versions.is_empty() || !references.is_empty()).then(|| Remediation {
                        description: if fixed_versions.is_empty() {
                            "Review the advisory references for remediation guidance".to_owned()
                        } else {
                            "Upgrade to a fixed version".to_owned()
                        },
                        fixed_versions,
                        references: references.clone(),
                    });
                let evidence = Evidence {
                    description: format!(
                        "OSV reports a vulnerability match for {} {} ({})",
                        component.name, component.version, vulnerability.id
                    ),
                    locations: component
                        .locations
                        .iter()
                        .map(|location| location.id.clone())
                        .collect(),
                    references: references.clone(),
                    properties: BTreeMap::from([
                        ("package.name".to_owned(), component.name.clone()),
                        ("package.version".to_owned(), component.version.clone()),
                        ("package.purl".to_owned(), component.purl.clone()),
                    ]),
                    redacted: false,
                };
                findings.insert(
                    finding_id.clone(),
                    Finding {
                        id: finding_id,
                        kind: FindingKind::Vulnerability,
                        rule_id,
                        advisory_id: Some(vulnerability.id.clone()),
                        component_id: Some(component.identity.clone()),
                        location_id: None,
                        aliases: vulnerability.aliases.iter().cloned().collect(),
                        summary: vulnerability.summary.clone(),
                        details: vulnerability.details.clone(),
                        severity: vulnerability_severity(vulnerability),
                        confidence: Confidence::High,
                        evidence: BTreeSet::from([evidence.clone()]),
                        applicability: Some(ApplicabilityAnalyzer::analyze(ApplicabilityInput {
                            component,
                            inventory,
                            evidence: &BTreeSet::from([evidence]),
                            affected_ranges: &affected_ranges,
                        })),
                        remediation,
                        risk: None,
                        first_seen: None,
                        last_seen: None,
                        modified: vulnerability.modified.clone(),
                        status: FindingStatus::Open,
                    },
                );
            }
        }
    }
    Ok(findings)
}

fn affected_ranges(vulnerability: &Vulnerability, purl: &str) -> Vec<OsvAffectedRange> {
    vulnerability
        .affected
        .iter()
        .filter(|affected| {
            affected
                .package
                .as_ref()
                .and_then(|package| package.purl.as_deref())
                .is_none_or(|affected_purl| same_package(affected_purl, purl))
        })
        .flat_map(|affected| {
            let ecosystem = affected.package.as_ref().and_then(affected_ecosystem);
            affected.ranges.iter().filter_map(move |range| {
                let range_type = match range
                    .kind
                    .as_deref()
                    .map(str::to_ascii_uppercase)
                    .as_deref()
                {
                    None | Some("ECOSYSTEM") => OsvRangeType::Ecosystem,
                    Some("SEMVER") => OsvRangeType::Semver,
                    Some("GIT") => OsvRangeType::Git,
                    Some(_) => return None,
                };
                Some(OsvAffectedRange {
                    range_type,
                    ecosystem: ecosystem.clone(),
                    events: range
                        .events
                        .iter()
                        .map(|event| OsvEvent {
                            introduced: clean_version(event.introduced.as_deref()),
                            fixed: clean_version(event.fixed.as_deref()),
                            last_affected: clean_version(event.last_affected.as_deref()),
                            limit: clean_version(event.limit.as_deref()),
                        })
                        .collect(),
                })
            })
        })
        .collect()
}

fn affected_ecosystem(package: &AffectedPackage) -> Option<String> {
    package
        .purl
        .as_deref()
        .and_then(|purl| purl.strip_prefix("pkg:"))
        .and_then(|purl| purl.split('/').next())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            package.ecosystem.as_deref().and_then(|ecosystem| {
                let normalized = match ecosystem.to_ascii_lowercase().as_str() {
                    "crates.io" => "cargo",
                    "pypi" => "pypi",
                    "npm" => "npm",
                    "go" => "golang",
                    "maven" => "maven",
                    "nuget" => "nuget",
                    _ => return None,
                };
                Some(normalized.to_owned())
            })
        })
}

fn fixed_versions(ranges: &[OsvAffectedRange]) -> BTreeSet<String> {
    ranges
        .iter()
        .flat_map(|range| range.events.iter())
        .filter_map(|event| event.fixed.clone())
        .collect()
}

fn clean_version(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn same_package(left: &str, right: &str) -> bool {
    package_identity(left) == package_identity(right)
}

fn package_identity(purl: &str) -> &str {
    let package = purl.split(['?', '#']).next().unwrap_or(purl);
    package
        .rsplit_once('@')
        .map_or(package, |(identity, _)| identity)
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
    use std::{collections::BTreeSet, time::Duration};

    use super::*;
    use crate::model::{Asset, AssetId, AssetKind, Scope};
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    fn component(identity: &str, name: &str, version: &str, purl: &str) -> Component {
        Component {
            identity: ComponentId::new(identity).unwrap(),
            name: name.into(),
            version: version.into(),
            purl: purl.into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    fn inventory(components: impl IntoIterator<Item = Component>) -> Inventory {
        Inventory {
            asset: Asset {
                id: AssetId::new("asset:test").unwrap(),
                name: "test".into(),
                kind: AssetKind::Repository,
                version: None,
                metadata: BTreeMap::new(),
            },
            components: components
                .into_iter()
                .map(|component| (component.identity.clone(), component))
                .collect(),
            dependencies: BTreeSet::new(),
        }
    }

    fn detail(id: &str, extra: Value) -> Value {
        let mut value = json!({"id": id});
        value.as_object_mut().unwrap().extend(
            extra
                .as_object()
                .expect("detail additions must be an object")
                .clone(),
        );
        value
    }

    #[test]
    fn rejects_invalid_base_url() {
        assert!(matches!(
            OsvClient::new("not a URL", 4),
            Err(OsvError::InvalidBaseUrl(_))
        ));
    }

    #[tokio::test]
    async fn empty_inventory_performs_no_requests() {
        let server = MockServer::start().await;
        let client = OsvClient::new(&server.uri(), 0).unwrap();

        assert!(client.scan(&inventory([])).await.unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scan_deduplicates_queries_and_advisory_fetches_but_maps_every_component() {
        let server = MockServer::start().await;
        let purl = "pkg:cargo/shared@1.0.0";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({"queries": [{"package": {"purl": purl}}]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-1"}]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/OSV-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail(
                "OSV-1",
                json!({"summary": "shared advisory", "severity": [{"type": "CVSS_V3", "score": 7.2}]}),
            )))
            .expect(1)
            .mount(&server)
            .await;

        let findings = OsvClient::new(&server.uri(), 4)
            .unwrap()
            .scan(&inventory([
                component("component:a", "shared-a", "1.0.0", purl),
                component("component:b", "shared-b", "1.0.0", purl),
            ]))
            .await
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings
                .values()
                .map(|finding| finding.component_id.as_ref().unwrap().as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["component:a", "component:b"])
        );
        assert!(findings.values().all(|finding| {
            finding.summary.as_deref() == Some("shared advisory")
                && finding.severity == Severity::High
        }));
    }

    #[tokio::test]
    async fn scan_follows_pagination_and_deduplicates_ids_across_pages() {
        let server = MockServer::start().await;
        let purl = "pkg:npm/paged@2.0.0";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({"queries": [{"package": {"purl": purl}}]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "next token"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({"queries": [{
                "package": {"purl": purl}, "page_token": "next token"
            }]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}], "next_page_token": ""}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        for id in ["OSV-1", "OSV-2"] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(detail(id, json!({}))))
                .expect(1)
                .mount(&server)
                .await;
        }

        let findings = OsvClient::new(&server.uri(), 2)
            .unwrap()
            .scan(&inventory([component(
                "component:paged",
                "paged",
                "2.0.0",
                purl,
            )]))
            .await
            .unwrap();

        assert_eq!(
            findings
                .values()
                .map(|finding| finding.advisory_id.as_deref().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["OSV-1", "OSV-2"])
        );
    }

    #[tokio::test]
    async fn reports_batch_http_body_decode_and_result_count_failures() {
        async fn scan_with(response: ResponseTemplate) -> OsvError {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(response)
                .mount(&server)
                .await;
            OsvClient::new(&server.uri(), 1)
                .unwrap()
                .scan(&inventory([component(
                    "component:failure",
                    "failure",
                    "1.0.0",
                    "pkg:cargo/failure@1.0.0",
                )]))
                .await
                .unwrap_err()
        }

        let error =
            scan_with(ResponseTemplate::new(503).set_body_string("upstream unavailable")).await;
        assert!(matches!(
            error,
            OsvError::Http { status, body, .. }
                if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    && body == "upstream unavailable"
        ));

        let error = scan_with(ResponseTemplate::new(200).set_body_string("not json")).await;
        assert!(
            matches!(error, OsvError::Decode { endpoint, .. } if endpoint.ends_with("/v1/querybatch"))
        );

        let error =
            scan_with(ResponseTemplate::new(200).set_body_json(json!({"results": []}))).await;
        assert!(matches!(
            error,
            OsvError::ResultCount {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[tokio::test]
    async fn reports_detail_http_and_decode_failures() {
        async fn scan_with(response: ResponseTemplate) -> OsvError {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"vulns": [{"id": "OSV-detail"}]}]
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/vulns/OSV-detail"))
                .respond_with(response)
                .mount(&server)
                .await;
            OsvClient::new(&server.uri(), 1)
                .unwrap()
                .scan(&inventory([component(
                    "component:detail",
                    "detail",
                    "1.0.0",
                    "pkg:cargo/detail@1.0.0",
                )]))
                .await
                .unwrap_err()
        }

        let error = scan_with(ResponseTemplate::new(404).set_body_string("missing advisory")).await;
        assert!(matches!(
            error,
            OsvError::Http { status, body, endpoint }
                if status == reqwest::StatusCode::NOT_FOUND
                    && body == "missing advisory"
                    && endpoint.ends_with("/v1/vulns/OSV-detail")
        ));
        let error = scan_with(ResponseTemplate::new(200).set_body_string("{")).await;
        assert!(matches!(
            error,
            OsvError::Decode { endpoint, .. } if endpoint.ends_with("/v1/vulns/OSV-detail")
        ));
    }

    #[tokio::test]
    async fn escapes_advisory_id_as_one_detail_path_segment() {
        let server = MockServer::start().await;
        let advisory_id = "GHSA/a b?c";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": advisory_id}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/GHSA%2Fa%20b%3Fc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail(advisory_id, json!({}))))
            .expect(1)
            .mount(&server)
            .await;

        let findings = OsvClient::new(&server.uri(), 1)
            .unwrap()
            .scan(&inventory([component(
                "component:escaped",
                "escaped",
                "1.0.0",
                "pkg:cargo/escaped@1.0.0",
            )]))
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let detail_request = requests
            .iter()
            .find(|request| request.method.as_str() == "GET")
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(detail_request.url.path(), "/v1/vulns/GHSA%2Fa%20b%3Fc");
        assert!(detail_request.url.query().is_none());
    }

    #[tokio::test]
    async fn maps_fixed_ranges_references_and_nested_severity_fallbacks_end_to_end() {
        let server = MockServer::start().await;
        let purl = "pkg:cargo/demo@1.0.0";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-rich"}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/OSV-rich"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail(
                "OSV-rich",
                json!({
                    "aliases": ["CVE-2026-1", "CVE-2026-1"],
                    "details": "observable details",
                    "modified": "2026-07-21T12:00:00Z",
                    "database_specific": {"metadata": {"severity": "medium"}},
                    "references": [
                        {"url": " https://example.test/advisory "},
                        {"url": "https://example.test/advisory"},
                        {"url": "  "}
                    ],
                    "affected": [
                        {
                            "package": {"purl": purl},
                            "ranges": [{"events": [
                                {"fixed": " 1.1.0 "}, {"fixed": ""}, {"fixed": "1.1.0"}
                            ]}],
                            "ecosystem_specific": {"severity": ["low", "HIGH"]}
                        },
                        {
                            "package": {"purl": "pkg:cargo/other@1.0.0"},
                            "ranges": [{"events": [{"fixed": "9.9.9"}]}],
                            "database_specific": {"severity": "critical"}
                        }
                    ]
                }),
            )))
            .mount(&server)
            .await;

        let findings = OsvClient::new(&server.uri(), 1)
            .unwrap()
            .scan(&inventory([component(
                "component:demo",
                "demo",
                "1.0.0",
                purl,
            )]))
            .await
            .unwrap();
        let finding = findings.values().next().unwrap();
        let remediation = finding.remediation.as_ref().unwrap();

        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.aliases, BTreeSet::from(["CVE-2026-1".into()]));
        assert_eq!(finding.details.as_deref(), Some("observable details"));
        assert_eq!(finding.modified.as_deref(), Some("2026-07-21T12:00:00Z"));
        assert_eq!(remediation.description, "Upgrade to a fixed version");
        assert_eq!(remediation.fixed_versions, BTreeSet::from(["1.1.0".into()]));
        assert_eq!(
            remediation.references,
            BTreeSet::from(["https://example.test/advisory".into()])
        );
        assert_eq!(
            finding.evidence.iter().next().unwrap().references,
            remediation.references
        );
    }

    #[tokio::test]
    async fn fetches_independent_details_concurrently() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}]}]
            })))
            .mount(&server)
            .await;
        for id in ["OSV-1", "OSV-2"] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(200))
                        .set_body_json(detail(id, json!({}))),
                )
                .mount(&server)
                .await;
        }
        let inventory = inventory([component(
            "component:concurrent",
            "concurrent",
            "1.0.0",
            "pkg:cargo/concurrent@1.0.0",
        )]);

        let started = tokio::time::Instant::now();
        let findings = OsvClient::new(&server.uri(), 2)
            .unwrap()
            .scan(&inventory)
            .await
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "two delayed detail requests should overlap"
        );
    }

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
    fn matches_unversioned_affected_purl_and_preserves_range_semantics() {
        let identity =
            crate::model::stable_component_id("pkg:cargo/shared@1.0.0?source=lock").unwrap();
        let component = Component {
            identity,
            name: "shared".into(),
            version: "1.0.0".into(),
            purl: "pkg:cargo/shared@1.0.0?source=lock".into(),
            scope: crate::model::Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        };
        let components = BTreeMap::from([(component.purl.as_str(), vec![&component])]);
        let ids = BTreeMap::from([(component.purl.as_str(), BTreeSet::from(["OSV-1".into()]))]);
        let detail: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-1",
            "affected": [{
                "package": {"purl": "pkg:cargo/shared"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "2.0.0"}, {"fixed": "3.0.0"}
                ]}]
            }]
        }))
        .unwrap();
        let details = BTreeMap::from([("OSV-1".into(), detail)]);

        let findings = map_findings(&components, &ids, &details, None).unwrap();
        let finding = findings.values().next().unwrap();

        assert_eq!(
            finding.applicability.as_ref().unwrap().status,
            crate::model::ApplicabilityStatus::NotAffected
        );
        assert_eq!(
            finding.remediation.as_ref().unwrap().fixed_versions,
            BTreeSet::from(["3.0.0".into()])
        );
    }

    #[test]
    fn maps_versions_at_or_after_fixed_boundary_as_fixed() {
        let component = component(
            "component:fixed",
            "shared",
            "1.1.0",
            "pkg:cargo/shared@1.1.0",
        );
        let components = BTreeMap::from([(component.purl.as_str(), vec![&component])]);
        let ids = BTreeMap::from([(
            component.purl.as_str(),
            BTreeSet::from(["OSV-fixed".into()]),
        )]);
        let detail: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-fixed",
            "affected": [{
                "package": {"purl": "pkg:cargo/shared"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "1.1.0"}
                ]}]
            }]
        }))
        .unwrap();
        let details = BTreeMap::from([("OSV-fixed".into(), detail)]);

        let findings = map_findings(&components, &ids, &details, None).unwrap();

        assert_eq!(
            findings
                .values()
                .next()
                .unwrap()
                .applicability
                .as_ref()
                .unwrap()
                .status,
            crate::model::ApplicabilityStatus::Fixed
        );
    }

    #[test]
    fn maps_responses_to_stable_rich_findings() {
        let identity = crate::model::stable_component_id("pkg:cargo/shared@1.0").unwrap();
        let component = Component {
            identity: identity.clone(),
            name: "shared".into(),
            version: "1.0".into(),
            purl: "pkg:cargo/shared@1.0".into(),
            scope: crate::model::Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        };
        let components = BTreeMap::from([(component.purl.as_str(), vec![&component])]);
        let ids = BTreeMap::from([(component.purl.as_str(), BTreeSet::from(["OSV-1".into()]))]);
        let detail: Vulnerability = serde_json::from_value(json!({
            "id": "OSV-1", "aliases": ["CVE-1"], "summary": "one",
            "modified": "2026-01-01T00:00:00Z", "database_specific": {"severity": "HIGH"},
            "references": [{"type":"ADVISORY","url":"https://osv.dev/vulnerability/OSV-1"}],
            "affected": [{
                "package": {"purl":"pkg:cargo/shared@1.0"},
                "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.1"}]}]
            }]
        }))
        .unwrap();
        let details = BTreeMap::from([("OSV-1".into(), detail)]);

        let findings = map_findings(&components, &ids, &details, None).unwrap();
        let finding = findings.values().next().unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            finding.id,
            stable_finding_id(
                FindingKind::Vulnerability,
                &finding.rule_id,
                Some(&identity),
                None
            )
        );
        assert_eq!(finding.rule_id.as_str(), "osv:OSV-1");
        assert_eq!(finding.advisory_id.as_deref(), Some("OSV-1"));
        assert_eq!(finding.component_id.as_ref(), Some(&identity));
        assert_eq!(finding.aliases, BTreeSet::from(["CVE-1".into()]));
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.applicability.as_ref().unwrap().status,
            crate::model::ApplicabilityStatus::Affected
        );
        assert_eq!(
            finding.remediation.as_ref().unwrap().fixed_versions,
            BTreeSet::from(["1.1".into()])
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|evidence| evidence.properties["package.purl"] == component.purl)
        );
    }
}
