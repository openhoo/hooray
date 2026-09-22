use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use futures::{StreamExt, stream};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    analysis::{
        ApplicabilityAnalyzer, ApplicabilityInput, DependencyPathIndex, OsvAffectedRange, OsvEvent,
        OsvRangeType,
    },
    model::{
        Component, Confidence, Evidence, Finding, FindingId, FindingKind, FindingStatus, Inventory,
        Remediation, RuleId, Severity, stable_finding_id,
    },
};

const MAX_BATCH_SIZE: usize = 1_000;
/// Upper bound on server-driven pagination pages fetched per queried purl.
/// A conformant endpoint stops returning `next_page_token`; a mirror echoing
/// a stable token must not loop `scan` forever.
const MAX_PAGES_PER_PURL: usize = 100;
/// Upper bound on distinct vulnerability ids whose detail documents are
/// fetched and retained per scan. `MAX_PAGES_PER_PURL` bounds page count but
/// not ids per page, so a hostile or compromised mirror could otherwise
/// force unbounded `GET /v1/vulns/{id}` requests and unbounded memory.
const MAX_VULN_DETAILS: usize = 10_000;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for buffering a single OSV response body, matching the 100 MiB
/// local SBOM input bound. This complements the client-level connection and
/// request timeouts by bounding memory even when a peer streams continuously.
const MAX_RESPONSE_BYTES: usize = 100 * 1024 * 1024;

/// Upper bound for the response body retained inside `OsvError::Http`. The
/// streamed body is already capped at `MAX_RESPONSE_BYTES`; keeping only a
/// bounded prefix in the error stops a hostile 100 MiB failure page from
/// being cloned through error paths and rendered into logs and CLI output.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("invalid OSV API base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("failed to build OSV HTTP client: {0}")]
    Client(#[from] reqwest::Error),
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
    #[error("OSV pagination for {purl} exceeded maximum {maximum} pages")]
    PageLimit { purl: String, maximum: usize },
    #[error("OSV response from {endpoint} of {actual} bytes exceeds maximum {maximum}")]
    TooLarge {
        endpoint: String,
        actual: usize,
        maximum: usize,
    },
}

pub struct OsvClient {
    http: Client,
    base_url: Url,
    concurrency: usize,
}

impl OsvClient {
    pub fn new(base_url: &str, concurrency: usize) -> Result<Self, OsvError> {
        Self::with_timeouts(
            base_url,
            concurrency,
            DEFAULT_CONNECT_TIMEOUT,
            DEFAULT_REQUEST_TIMEOUT,
        )
    }

    pub fn with_timeouts(
        base_url: &str,
        concurrency: usize,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, OsvError> {
        let mut base_url =
            Url::parse(base_url).map_err(|error| OsvError::InvalidBaseUrl(error.to_string()))?;

        // Joining relative endpoints and pushing path segments below both
        // fail for cannot-be-a-base URLs (`data:`, `mailto:`, `urn:`), so the
        // constructor rejects them here instead of relying on configuration
        // validation elsewhere to have enforced an HTTP(S) base URL.
        if base_url.cannot_be_a_base() || !matches!(base_url.scheme(), "http" | "https") {
            return Err(OsvError::InvalidBaseUrl(base_url.to_string()));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Ok(Self {
            // OSV endpoints never legitimately redirect scan traffic, so
            // redirects are refused outright; requests stay pinned to the
            // configured base URL instead of following a hostile Location.
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(connect_timeout)
                .timeout(request_timeout)
                .build()?,
            base_url,
            concurrency: concurrency.max(1),
        })
    }

    pub async fn scan(
        &self,
        inventory: &Inventory,
    ) -> Result<BTreeMap<FindingId, Finding>, OsvError> {
        let mut components_by_purl: BTreeMap<&str, Vec<&Component>> = BTreeMap::new();
        for component in inventory.components.values() {
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

        type PageChain<'a> = std::pin::Pin<
            Box<dyn Future<Output = (usize, Result<BTreeSet<String>, OsvError>)> + Send + 'a>,
        >;
        for chunk in purls.chunks(MAX_BATCH_SIZE) {
            let queries: Vec<Query<'_>> = chunk.iter().map(|purl| Query::new(purl, None)).collect();
            let results = self.query_batch(&queries).await?;

            // OSV page tokens are opaque, so one purl's continuation chain
            // cannot start before its own previous page returns; the chains
            // of different purls are independent and run concurrently here,
            // bounded by the client concurrency. Each chain enforces
            // `MAX_PAGES_PER_PURL` locally and attributes failures to its
            // own purl.
            // Plain for-loop instead of an iterator-adaptor closure: a
            // closure returning an async block that captures the item's
            // borrowed fields makes `buffer_unordered` demand a higher-ranked
            // FnOnce impl rustc cannot prove ("implementation of FnOnce is
            // not general enough"). Pushing concrete pinned futures keeps
            // every capture owned or borrow-of-self, so no item borrow
            // crosses an await.
            let mut chains: Vec<PageChain<'_>> = Vec::with_capacity(chunk.len());
            for (index, (purl, result)) in chunk.iter().copied().zip(results).enumerate() {
                // Own the purl so no borrow of the chunk iteration item
                // crosses an await inside `buffer_unordered`.
                let purl = purl.to_owned();
                chains.push(Box::pin(async move {
                    let mut ids: BTreeSet<String> = result
                        .vulns
                        .into_iter()
                        .map(|vulnerability| vulnerability.id)
                        .collect();
                    let mut page_token = result.next_page_token;
                    let mut pages = 0usize;
                    while let Some(token) = page_token.filter(|token| !token.is_empty()) {
                        pages += 1;
                        if pages > MAX_PAGES_PER_PURL {
                            return (
                                index,
                                Err(OsvError::PageLimit {
                                    purl,
                                    maximum: MAX_PAGES_PER_PURL,
                                }),
                            );
                        }
                        let page = match self.query_batch(&[Query::new(&purl, Some(&token))]).await
                        {
                            Ok(results) => results
                                .into_iter()
                                .next()
                                .expect("validated one-result response"),
                            Err(error) => return (index, Err(error)),
                        };
                        ids.extend(page.vulns.into_iter().map(|vulnerability| vulnerability.id));
                        page_token = page.next_page_token;
                    }
                    (index, Ok(ids))
                }));
            }
            let outcomes = stream::iter(chains)
                .buffer_unordered(self.concurrency.max(1))
                .collect::<Vec<(usize, Result<BTreeSet<String>, OsvError>)>>()
                .await;

            // Completion order is nondeterministic, so outcomes are scattered
            // back to their chunk positions before merging: per-purl sets land
            // in the purl-keyed map independently of order, and the first
            // failure in purl order is surfaced, matching the previous
            // sequential first-error behavior.
            let mut slots: Vec<Option<Result<BTreeSet<String>, OsvError>>> =
                (0..chunk.len()).map(|_| None).collect();
            for (index, outcome) in outcomes {
                slots[index] = Some(outcome);
            }
            for (purl, outcome) in chunk.iter().copied().zip(slots) {
                match outcome.expect("every chunk purl records a chain outcome") {
                    Ok(ids) => vulnerability_ids.entry(purl).or_default().extend(ids),
                    Err(error) => return Err(error),
                }
            }
        }

        let unique_ids: BTreeSet<String> = vulnerability_ids
            .values()
            .flat_map(|ids| ids.iter().cloned())
            .collect();
        // Page count is bounded per purl, but ids per page are not: a mirror
        // could return millions of distinct ids and force an unbounded number
        // of detail fetches plus a full `Vulnerability` retained per id.
        if unique_ids.len() > MAX_VULN_DETAILS {
            return Err(OsvError::TooLarge {
                endpoint: format!(
                    "{}v1/vulns ({} distinct ids)",
                    self.base_url,
                    unique_ids.len()
                ),
                actual: unique_ids.len(),
                maximum: MAX_VULN_DETAILS,
            });
        }
        let details = stream::iter(unique_ids.into_iter().map(|id| async move {
            let detail = self.fetch_vulnerability(&id).await?;
            Ok::<_, OsvError>((id, detail))
        }))
        .buffer_unordered(self.concurrency)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<BTreeMap<_, _>, _>>()?;

        map_findings(
            &components_by_purl,
            &vulnerability_ids,
            &details,
            Some(inventory),
        )
    }

    async fn query_batch(&self, queries: &[Query<'_>]) -> Result<Vec<QueryResult>, OsvError> {
        let endpoint = self
            .base_url
            .join("v1/querybatch")
            .map_err(|_| OsvError::InvalidBaseUrl(self.base_url.to_string()))?;
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
            .join("v1/vulns")
            .map_err(|_| OsvError::InvalidBaseUrl(self.base_url.to_string()))?;
        endpoint
            .path_segments_mut()
            .map_err(|_| OsvError::InvalidBaseUrl(self.base_url.to_string()))?
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
    mut response: Response,
    endpoint: &Url,
) -> Result<T, OsvError> {
    let status = response.status();
    if let Some(length) = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .filter(|length| *length > MAX_RESPONSE_BYTES)
    {
        return Err(OsvError::TooLarge {
            endpoint: endpoint.to_string(),
            actual: length,
            maximum: MAX_RESPONSE_BYTES,
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|source| OsvError::Request {
        endpoint: endpoint.to_string(),
        source,
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OsvError::TooLarge {
                endpoint: endpoint.to_string(),
                actual: bytes.len().saturating_add(chunk.len()),
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(OsvError::Http {
            endpoint: endpoint.to_string(),
            status,
            body: truncated_error_body(&bytes),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| OsvError::Decode {
        endpoint: endpoint.to_string(),
        source,
    })
}

/// Retains at most `MAX_ERROR_BODY_BYTES` of a failed response body, minus
/// control characters: tabs widen to spaces and every other C0/C1 control is
/// dropped, so a hostile body cannot smuggle terminal escapes or log-framing
/// into stderr and CLI diagnostics while printable content stays debuggable.
/// Byte slicing may split a UTF-8 sequence; `from_utf8_lossy` replaces the
/// partial suffix instead of panicking, so truncation at an arbitrary byte is
/// safe.
fn truncated_error_body(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_ERROR_BODY_BYTES)])
        .chars()
        .filter_map(|character| match character {
            '\t' => Some(' '),
            control if control.is_control() => None,
            printable => Some(printable),
        })
        .collect()
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
    /// Timestamp marking an advisory the database pulled back (rejected
    /// CVEs, withdrawn GHSAs). Withdrawn advisories must not surface as open
    /// findings.
    withdrawn: Option<String>,
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
    /// Explicitly enumerated affected versions; advisories may list these
    /// instead of (or alongside) `ranges`.
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    database_specific: Value,
    #[serde(default)]
    ecosystem_specific: Value,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    /// Package name in the advisory's own ecosystem naming (e.g. a PyPI
    /// distribution name). Compared against the component when `purl` is
    /// absent so sibling packages in a multi-package advisory do not
    /// cross-apply their ranges and severities.
    name: Option<String>,
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
    // Shared across every (advisory, component) finding so applicability
    // analysis costs one O(V + E) traversal per scan, not per finding.
    let path_index = inventory.map(DependencyPathIndex::new);
    let mut findings = BTreeMap::new();
    for (purl, ids) in vulnerability_ids {
        let Some(components) = components_by_purl.get(purl) else {
            continue;
        };
        for advisory_id in ids {
            let Some(vulnerability) = details.get(advisory_id) else {
                continue;
            };
            // A `withdrawn` timestamp marks an advisory the database pulled
            // back (rejected CVEs, withdrawn GHSAs); it must not surface as
            // an open finding.
            if vulnerability
                .withdrawn
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                continue;
            }
            // `RuleId::new` only rejects an empty-after-trim rule id, so an
            // empty or whitespace-only advisory id would silently produce
            // `osv:` findings; validate the id itself first.
            if vulnerability.id.trim().is_empty() {
                return Err(OsvError::InvalidVulnerabilityId);
            }
            let references: BTreeSet<String> = vulnerability
                .references
                .iter()
                .filter_map(|reference| {
                    let url = reference.url.trim();
                    (!url.is_empty()).then(|| url.to_owned())
                })
                .collect();
            let rule_id = RuleId::new(format!("osv:{}", vulnerability.id))
                .map_err(|_| OsvError::InvalidVulnerabilityId)?;
            for component in components {
                let finding = vulnerability_finding(
                    vulnerability,
                    component,
                    &rule_id,
                    &references,
                    path_index.as_ref(),
                );
                findings.insert(finding.id.clone(), finding);
            }
        }
    }
    Ok(findings)
}

/// Builds the vulnerability finding for one (advisory, component) pair. The
/// advisory-level invariants (`rule_id`, `references`) are resolved by the
/// caller once per advisory instead of once per component.
fn vulnerability_finding(
    vulnerability: &Vulnerability,
    component: &Component,
    rule_id: &RuleId,
    references: &BTreeSet<String>,
    paths: Option<&DependencyPathIndex<'_>>,
) -> Finding {
    let finding_id = stable_finding_id(
        FindingKind::Vulnerability,
        rule_id,
        Some(&component.identity),
        None,
    );
    let affected_ranges = affected_ranges(vulnerability, component);
    let fixed_versions = fixed_versions(&affected_ranges);
    let remediation = (!fixed_versions.is_empty() || !references.is_empty()).then(|| Remediation {
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
    Finding {
        id: finding_id,
        kind: FindingKind::Vulnerability,
        rule_id: rule_id.clone(),
        advisory_id: Some(vulnerability.id.clone()),
        component_id: Some(component.identity.clone()),
        location_id: None,
        aliases: vulnerability.aliases.iter().cloned().collect(),
        summary: vulnerability.summary.clone(),
        details: vulnerability.details.clone(),
        severity: vulnerability_severity(vulnerability, component),
        confidence: Confidence::High,
        evidence: BTreeSet::from([evidence.clone()]),
        applicability: Some(ApplicabilityAnalyzer::analyze(ApplicabilityInput {
            component,
            paths,
            evidence: &BTreeSet::from([evidence]),
            affected_ranges: &affected_ranges,
        })),
        remediation,
        risk: None,
        first_seen: None,
        last_seen: None,
        modified: vulnerability.modified.clone(),
        status: FindingStatus::Open,
    }
}

fn affected_ranges(vulnerability: &Vulnerability, component: &Component) -> Vec<OsvAffectedRange> {
    vulnerability
        .affected
        .iter()
        .filter(|affected| affected_package_matches(affected.package.as_ref(), component))
        .flat_map(|affected| {
            let ecosystem = affected.package.as_ref().and_then(affected_ecosystem);
            let versions: Vec<String> = affected
                .versions
                .iter()
                .filter_map(|version| clean_version(Some(version)))
                .collect();
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
                    versions: versions.clone(),
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

/// Decides whether an OSV `affected[].package` descriptor names the queried
/// component. A `purl` matches on package identity (type + decoded
/// namespace/name + qualifiers, version stripped). Without a purl, `name`
/// must equal the component's package name and `ecosystem` (when present)
/// must map to the component's purl type; an entry carrying neither name
/// nor purl cannot be attributed to a package and is skipped instead of
/// wildcarding onto every component.
fn affected_package_matches(package: Option<&AffectedPackage>, component: &Component) -> bool {
    let Some(package) = package else {
        // No package descriptor at all: the entry cannot be attributed to a
        // package, so it applies to the queried component (OSV entries may
        // legally omit `package` when the advisory is unscoped).
        return true;
    };
    if let Some(purl) = package.purl.as_deref() {
        return same_package(purl, &component.purl);
    }
    let ecosystem_matches = |package: &AffectedPackage| {
        package.ecosystem.as_deref().is_none_or(|ecosystem| {
            purl_type_matches(&normalize_osv_ecosystem(ecosystem), component)
        })
    };
    match package
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        Some(name) => ecosystem_matches(package) && package_name_matches(name, component),
        // Ecosystem-only entries (no name, no purl) apply ecosystem-wide;
        // ecosystems that do not map to a purl type can never match.
        None => package.ecosystem.is_some() && ecosystem_matches(package),
    }
}

/// Compares a normalized OSV ecosystem name against the component's purl
/// type.
fn purl_type_matches(normalized_ecosystem: &str, component: &Component) -> bool {
    component
        .purl
        .strip_prefix("pkg:")
        .and_then(|body| body.split('/').next())
        .is_some_and(|kind| kind.eq_ignore_ascii_case(normalized_ecosystem))
}

/// Compares an advisory's `package.name` against the component: the declared
/// name first, then the percent-decoded name carried by the purl (namespace
/// joined per ecosystem convention) so lockfile names that differ from purl
/// naming still match.
fn package_name_matches(name: &str, component: &Component) -> bool {
    if name.eq_ignore_ascii_case(component.name.trim()) {
        return true;
    }
    purl_package_name(&component.purl)
        .is_some_and(|purl_name| name.eq_ignore_ascii_case(&purl_name))
}

/// Decodes the package name a purl carries, joining namespace and name the
/// way the ecosystem's OSV naming does (`:` for Maven, `/` elsewhere).
fn purl_package_name(purl: &str) -> Option<String> {
    let body = purl.strip_prefix("pkg:")?;
    let body = body.split(['?', '#']).next().unwrap_or(body);
    let (kind, path) = body.split_once('/')?;
    if path.is_empty() || path.split('/').any(str::is_empty) {
        return None;
    }
    let final_segment = path.rsplit('/').next().unwrap_or(path);
    let name_len = final_segment
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or(final_segment.len(), |(name, _)| name.len());
    let path = &path[..path.len() - final_segment.len() + name_len];
    let decoded = crate::util::percent_decode_strict(path)?;
    Some(match kind.to_ascii_lowercase().as_str() {
        "maven" => decoded.replacen('/', ":", 1),
        _ => decoded,
    })
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
            package
                .ecosystem
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(normalize_osv_ecosystem)
        })
}

/// Maps an OSV ecosystem name to the purl type hooray emits for it. Names
/// without a purl equivalent keep their lowercased OSV spelling, which can
/// never equal a purl type — an advisory scoped to an ecosystem hooray does
/// not emit (Debian, OSS-Fuzz, …) must not wildcard onto every component.
fn normalize_osv_ecosystem(ecosystem: &str) -> String {
    let lowered = ecosystem.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "crates.io" => "cargo".to_owned(),
        "go" => "golang".to_owned(),
        "packagist" => "composer".to_owned(),
        "rubygems" => "gem".to_owned(),
        "debian" => "deb".to_owned(),
        _ => lowered,
    }
}

fn fixed_versions(ranges: &[OsvAffectedRange]) -> BTreeSet<String> {
    ranges
        .iter()
        // GIT-range `fixed` events are commit SHAs, not versions; rendering
        // them as upgrade advice would mislead remediation.
        .filter(|range| range.range_type != OsvRangeType::Git)
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

/// `left` is the advisory's affected purl, `right` the component's. The
/// base identity (type + decoded namespace/name, version stripped) must
/// match; when the advisory purl carries qualifiers (`?distro=`, `?arch=`)
/// they must equal the component's exactly — an unqualified advisory entry
/// applies regardless of the component's qualifiers, while a qualified one
/// stays scoped to its distro/arch so per-distro ranges never merge.
fn same_package(left: &str, right: &str) -> bool {
    let (left_base, left_qualifiers) = package_identity(left);
    let (right_base, right_qualifiers) = package_identity(right);
    left_base == right_base && (left_qualifiers.is_empty() || left_qualifiers == right_qualifiers)
}

/// Splits a purl into its base identity (percent-decoded
/// namespace/name with the version stripped — the last `@` of the final
/// segment, matching `util::parse_purl_body`, so unencoded npm scopes like
/// `pkg:npm/@scope/name` keep their scope instead of collapsing to
/// `pkg:npm/`) and its sorted qualifier list.
fn package_identity(purl: &str) -> (String, Vec<String>) {
    let body = purl.strip_prefix("pkg:").unwrap_or(purl);
    let (path, qualifiers) = match body.split_once(['?', '#']) {
        Some((path, qualifiers)) => (path, qualifiers),
        None => (body, ""),
    };
    let final_segment = path.rsplit('/').next().unwrap_or(path);
    let name_len = final_segment
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or(final_segment.len(), |(name, _)| name.len());
    let path = &path[..path.len() - final_segment.len() + name_len];
    let base = crate::util::percent_decode_strict(path).unwrap_or_else(|| path.to_owned());
    let mut qualifiers: Vec<String> = qualifiers
        .split('&')
        .filter(|qualifier| !qualifier.is_empty())
        .map(str::to_owned)
        .collect();
    qualifiers.sort_unstable();
    (base, qualifiers)
}

fn vulnerability_severity(vulnerability: &Vulnerability, component: &Component) -> Severity {
    // Per-package severity sources (affected[].severity plus the affected[]
    // database_specific/ecosystem_specific labels) must be scoped to the
    // queried purl exactly like `affected_ranges`; a multi-package advisory
    // must not inflate this finding with sibling packages' labels.
    let matching_affected: Vec<&Affected> = vulnerability
        .affected
        .iter()
        .filter(|affected| affected_package_matches(affected.package.as_ref(), component))
        .collect();
    vulnerability
        .severity
        .iter()
        .chain(
            matching_affected
                .iter()
                .flat_map(|affected| affected.severity.iter()),
        )
        .filter_map(severity_from_osv)
        .chain(severity_strings(&vulnerability.database_specific))
        .chain(matching_affected.iter().flat_map(|affected| {
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
    } else if vector.starts_with("CVSS:4.0/") {
        cvss_v4_score(vector)
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

/// CVSS v4.0 scoring, ported from the FIRST.org reference calculator
/// (RedHatProductSecurity/cvss-v4-calculator, BSD-2-Clause): the vector is
/// reduced to a six-digit MacroVector (EQ1–EQ6), the MacroVector's score is
/// looked up, then interpolated downward by the vector's severity distance
/// from the MacroVector's highest-severity members.
mod cvss_v4 {
    use std::collections::BTreeMap;

    /// MacroVector score table (spec Table 23), sorted for binary search.
    static LOOKUP: &[(&str, f64)] = &[
        ("000000", 10.0),
        ("000001", 9.9),
        ("000010", 9.8),
        ("000011", 9.5),
        ("000020", 9.5),
        ("000021", 9.2),
        ("000100", 10.0),
        ("000101", 9.6),
        ("000110", 9.3),
        ("000111", 8.7),
        ("000120", 9.1),
        ("000121", 8.1),
        ("000200", 9.3),
        ("000201", 9.0),
        ("000210", 8.9),
        ("000211", 8.0),
        ("000220", 8.1),
        ("000221", 6.8),
        ("001000", 9.8),
        ("001001", 9.5),
        ("001010", 9.5),
        ("001011", 9.2),
        ("001020", 9.0),
        ("001021", 8.4),
        ("001100", 9.3),
        ("001101", 9.2),
        ("001110", 8.9),
        ("001111", 8.1),
        ("001120", 8.1),
        ("001121", 6.5),
        ("001200", 8.8),
        ("001201", 8.0),
        ("001210", 7.8),
        ("001211", 7.0),
        ("001220", 6.9),
        ("001221", 4.8),
        ("002001", 9.2),
        ("002011", 8.2),
        ("002021", 7.2),
        ("002101", 7.9),
        ("002111", 6.9),
        ("002121", 5.0),
        ("002201", 6.9),
        ("002211", 5.5),
        ("002221", 2.7),
        ("010000", 9.9),
        ("010001", 9.7),
        ("010010", 9.5),
        ("010011", 9.2),
        ("010020", 9.2),
        ("010021", 8.5),
        ("010100", 9.5),
        ("010101", 9.1),
        ("010110", 9.0),
        ("010111", 8.3),
        ("010120", 8.4),
        ("010121", 7.1),
        ("010200", 9.2),
        ("010201", 8.1),
        ("010210", 8.2),
        ("010211", 7.1),
        ("010220", 7.2),
        ("010221", 5.3),
        ("011000", 9.5),
        ("011001", 9.3),
        ("011010", 9.2),
        ("011011", 8.5),
        ("011020", 8.5),
        ("011021", 7.3),
        ("011100", 9.2),
        ("011101", 8.2),
        ("011110", 8.0),
        ("011111", 7.2),
        ("011120", 7.0),
        ("011121", 5.9),
        ("011200", 8.4),
        ("011201", 7.0),
        ("011210", 7.1),
        ("011211", 5.2),
        ("011220", 5.0),
        ("011221", 3.0),
        ("012001", 8.6),
        ("012011", 7.5),
        ("012021", 5.2),
        ("012101", 7.1),
        ("012111", 5.2),
        ("012121", 2.9),
        ("012201", 6.3),
        ("012211", 2.9),
        ("012221", 1.7),
        ("100000", 9.8),
        ("100001", 9.5),
        ("100010", 9.4),
        ("100011", 8.7),
        ("100020", 9.1),
        ("100021", 8.1),
        ("100100", 9.4),
        ("100101", 8.9),
        ("100110", 8.6),
        ("100111", 7.4),
        ("100120", 7.7),
        ("100121", 6.4),
        ("100200", 8.7),
        ("100201", 7.5),
        ("100210", 7.4),
        ("100211", 6.3),
        ("100220", 6.3),
        ("100221", 4.9),
        ("101000", 9.4),
        ("101001", 8.9),
        ("101010", 8.8),
        ("101011", 7.7),
        ("101020", 7.6),
        ("101021", 6.7),
        ("101100", 8.6),
        ("101101", 7.6),
        ("101110", 7.4),
        ("101111", 5.8),
        ("101120", 5.9),
        ("101121", 5.0),
        ("101200", 7.2),
        ("101201", 5.7),
        ("101210", 5.7),
        ("101211", 5.2),
        ("101220", 5.2),
        ("101221", 2.5),
        ("102001", 8.3),
        ("102011", 7.0),
        ("102021", 5.4),
        ("102101", 6.5),
        ("102111", 5.8),
        ("102121", 2.6),
        ("102201", 5.3),
        ("102211", 2.1),
        ("102221", 1.3),
        ("110000", 9.5),
        ("110001", 9.0),
        ("110010", 8.8),
        ("110011", 7.6),
        ("110020", 7.6),
        ("110021", 7.0),
        ("110100", 9.0),
        ("110101", 7.7),
        ("110110", 7.5),
        ("110111", 6.2),
        ("110120", 6.1),
        ("110121", 5.3),
        ("110200", 7.7),
        ("110201", 6.6),
        ("110210", 6.8),
        ("110211", 5.9),
        ("110220", 5.2),
        ("110221", 3.0),
        ("111000", 8.9),
        ("111001", 7.8),
        ("111010", 7.6),
        ("111011", 6.7),
        ("111020", 6.2),
        ("111021", 5.8),
        ("111100", 7.4),
        ("111101", 5.9),
        ("111110", 5.7),
        ("111111", 5.7),
        ("111120", 4.7),
        ("111121", 2.3),
        ("111200", 6.1),
        ("111201", 5.2),
        ("111210", 5.7),
        ("111211", 2.9),
        ("111220", 2.4),
        ("111221", 1.6),
        ("112001", 7.1),
        ("112011", 5.9),
        ("112021", 3.0),
        ("112101", 5.8),
        ("112111", 2.6),
        ("112121", 1.5),
        ("112201", 2.3),
        ("112211", 1.3),
        ("112221", 0.6),
        ("200000", 9.3),
        ("200001", 8.7),
        ("200010", 8.6),
        ("200011", 7.2),
        ("200020", 7.5),
        ("200021", 5.8),
        ("200100", 8.6),
        ("200101", 7.4),
        ("200110", 7.4),
        ("200111", 6.1),
        ("200120", 5.6),
        ("200121", 3.4),
        ("200200", 7.0),
        ("200201", 5.4),
        ("200210", 5.2),
        ("200211", 4.0),
        ("200220", 4.0),
        ("200221", 2.2),
        ("201000", 8.5),
        ("201001", 7.5),
        ("201010", 7.4),
        ("201011", 5.5),
        ("201020", 6.2),
        ("201021", 5.1),
        ("201100", 7.2),
        ("201101", 5.7),
        ("201110", 5.5),
        ("201111", 4.1),
        ("201120", 4.6),
        ("201121", 1.9),
        ("201200", 5.3),
        ("201201", 3.6),
        ("201210", 3.4),
        ("201211", 1.9),
        ("201220", 1.9),
        ("201221", 0.8),
        ("202001", 6.4),
        ("202011", 5.1),
        ("202021", 2.0),
        ("202101", 4.7),
        ("202111", 2.1),
        ("202121", 1.1),
        ("202201", 2.4),
        ("202211", 0.9),
        ("202221", 0.4),
        ("210000", 8.8),
        ("210001", 7.5),
        ("210010", 7.3),
        ("210011", 5.3),
        ("210020", 6.0),
        ("210021", 5.0),
        ("210100", 7.3),
        ("210101", 5.5),
        ("210110", 5.9),
        ("210111", 4.0),
        ("210120", 4.1),
        ("210121", 2.0),
        ("210200", 5.4),
        ("210201", 4.3),
        ("210210", 4.5),
        ("210211", 2.2),
        ("210220", 2.0),
        ("210221", 1.1),
        ("211000", 7.5),
        ("211001", 5.5),
        ("211010", 5.8),
        ("211011", 4.5),
        ("211020", 4.0),
        ("211021", 2.1),
        ("211100", 6.1),
        ("211101", 5.1),
        ("211110", 4.8),
        ("211111", 1.8),
        ("211120", 2.0),
        ("211121", 0.9),
        ("211200", 4.6),
        ("211201", 1.8),
        ("211210", 1.7),
        ("211211", 0.7),
        ("211220", 0.8),
        ("211221", 0.2),
        ("212001", 5.3),
        ("212011", 2.4),
        ("212021", 1.4),
        ("212101", 2.4),
        ("212111", 1.2),
        ("212121", 0.5),
        ("212201", 1.0),
        ("212211", 0.3),
        ("212221", 0.1),
    ];

    /// Severity level index per metric value (spec interpolation weights).
    fn metric_level(metric: &str, value: &str) -> Option<f64> {
        Some(match (metric, value) {
            ("AV", "N") => 0.0,
            ("AV", "A") => 0.1,
            ("AV", "L") => 0.2,
            ("AV", "P") => 0.3,
            ("PR", "N") => 0.0,
            ("PR", "L") => 0.1,
            ("PR", "H") => 0.2,
            ("UI", "N") => 0.0,
            ("UI", "P") => 0.1,
            ("UI", "A") => 0.2,
            ("AC", "L") => 0.0,
            ("AC", "H") => 0.1,
            ("AT", "N") => 0.0,
            ("AT", "P") => 0.1,
            ("VC", "H") | ("VI", "H") | ("VA", "H") => 0.0,
            ("VC", "L") | ("VI", "L") | ("VA", "L") => 0.1,
            ("VC", "N") | ("VI", "N") | ("VA", "N") => 0.2,
            ("SC", "H") => 0.1,
            ("SC", "L") => 0.2,
            ("SC", "N") => 0.3,
            ("SI", "S") | ("SA", "S") => 0.0,
            ("SI", "H") | ("SA", "H") => 0.1,
            ("SI", "L") | ("SA", "L") => 0.2,
            ("SI", "N") | ("SA", "N") => 0.3,
            ("CR", "H") | ("IR", "H") | ("AR", "H") => 0.0,
            ("CR", "M") | ("IR", "M") | ("AR", "M") => 0.1,
            ("CR", "L") | ("IR", "L") | ("AR", "L") => 0.2,
            ("E", "U") => 0.2,
            ("E", "P") => 0.1,
            ("E", "A") => 0.0,
            _ => return None,
        })
    }

    /// Highest-severity vector fragments for each MacroVector level
    /// (spec MAX_COMPOSED table).
    fn max_composed(eq: usize, level: usize) -> &'static [&'static str] {
        match (eq, level) {
            (1, 0) => &["AV:N/PR:N/UI:N/"],
            (1, 1) => &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            (1, 2) => &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
            (2, 0) => &["AC:L/AT:N/"],
            (2, 1) => &["AC:H/AT:N/", "AC:L/AT:P/"],
            (4, 0) => &["SC:H/SI:S/SA:S/"],
            (4, 1) => &["SC:H/SI:H/SA:H/"],
            (4, 2) => &["SC:L/SI:L/SA:L/"],
            (5, 0) => &["E:A/"],
            (5, 1) => &["E:P/"],
            (5, 2) => &["E:U/"],
            _ => &[],
        }
    }

    /// EQ3+EQ6 highest-severity fragments, keyed by (eq3 level, eq6 level).
    fn max_composed_eq3(eq3: usize, eq6: usize) -> &'static [&'static str] {
        match (eq3, eq6) {
            (0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            (0, 1) => &[
                "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
            ],
            (1, 0) => &[
                "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
            ],
            (1, 1) => &[
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
            (2, 1) => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
            _ => &[],
        }
    }

    /// Max severity distance inside each MacroVector (+1), spec MAX_SEVERITY.
    fn max_severity(eq: usize, level: usize, eq6: usize) -> Option<f64> {
        Some(match (eq, level, eq6) {
            (1, 0, _) => 1.0,
            (1, 1, _) => 4.0,
            (1, 2, _) => 5.0,
            (2, 0, _) => 1.0,
            (2, 1, _) => 2.0,
            (3, 0, 0) => 7.0,
            (3, 0, 1) => 6.0,
            (3, 1, 0) | (3, 1, 1) => 8.0,
            (3, 2, 1) => 10.0,
            (4, 0, _) => 6.0,
            (4, 1, _) => 5.0,
            (4, 2, _) => 4.0,
            _ => return None,
        })
    }

    /// Valid values per metric; base metrics are mandatory, the rest default
    /// to "X" (not defined).
    fn metric_values(metric: &str) -> Option<&'static [&'static str]> {
        Some(match metric {
            "AV" => &["N", "A", "L", "P"],
            "AC" => &["L", "H"],
            "AT" => &["N", "P"],
            "PR" => &["N", "L", "H"],
            "UI" => &["N", "P", "A"],
            "VC" | "VI" | "VA" | "SC" | "SI" | "SA" => &["N", "L", "H"],
            "E" => &["X", "A", "P", "U"],
            "CR" | "IR" | "AR" => &["X", "H", "M", "L"],
            "MAV" => &["X", "N", "A", "L", "P"],
            "MAC" => &["X", "L", "H"],
            "MAT" => &["X", "N", "P"],
            "MPR" => &["X", "N", "L", "H"],
            "MUI" => &["X", "N", "P", "A"],
            "MVC" | "MVI" | "MVA" | "MSC" => &["X", "H", "L", "N"],
            "MSI" | "MSA" => &["X", "S", "H", "L", "N"],
            "S" => &["X", "N", "P"],
            "AU" => &["X", "N", "Y"],
            "R" => &["X", "A", "U", "I"],
            "V" => &["X", "D", "C"],
            "RE" => &["X", "L", "M", "H"],
            "U" => &["X", "Clear", "Green", "Amber", "Red"],
            _ => return None,
        })
    }

    const BASE_METRICS: &[&str] = &[
        "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    ];

    /// Effective metric value: an explicit modified (M*) value wins, then the
    /// raw value, with "X" resolving to the spec's worst-case defaults for
    /// E/CR/IR/AR.
    fn effective<'a>(metrics: &'a BTreeMap<&'a str, &'a str>, metric: &str) -> Option<&'a str> {
        let modified = format!("M{metric}");
        if let Some(value) = metrics.get(modified.as_str())
            && *value != "X"
        {
            return Some(value);
        }
        match metrics.get(metric).copied() {
            Some("X") | None => match metric {
                "E" => Some("A"),
                "CR" | "IR" | "AR" => Some("H"),
                _ => metrics.get(metric).copied(),
            },
            value => value,
        }
    }

    /// Scores a `CVSS:4.0/…` vector; `None` when the vector is malformed.
    pub(super) fn score(vector: &str) -> Option<f64> {
        let mut metrics: BTreeMap<&str, &str> = BTreeMap::new();
        for part in vector.split('/').skip(1) {
            let (key, value) = part.split_once(':')?;
            if !metric_values(key)?.contains(&value) {
                return None;
            }
            metrics.insert(key, value);
        }
        // Every base metric is mandatory.
        if !BASE_METRICS.iter().all(|key| metrics.contains_key(key)) {
            return None;
        }

        let get = |metric: &str| effective(&metrics, metric);

        // No impact on the vulnerable or subsequent system → 0.0.
        if ["VC", "VI", "VA", "SC", "SI", "SA"]
            .iter()
            .all(|metric| get(metric) == Some("N"))
        {
            return Some(0.0);
        }

        let (av, pr, ui) = (get("AV")?, get("PR")?, get("UI")?);
        let eq1 = if av == "N" && pr == "N" && ui == "N" {
            0
        } else if (av == "N" || pr == "N" || ui == "N") && av != "P" {
            1
        } else {
            2
        };
        let eq2 = if get("AC")? == "L" && get("AT")? == "N" {
            0
        } else {
            1
        };
        let (vc, vi, va) = (get("VC")?, get("VI")?, get("VA")?);
        let eq3 = if vc == "H" && vi == "H" {
            0
        } else if vc == "H" || vi == "H" || va == "H" {
            1
        } else {
            2
        };
        let eq4 = if get("MSI") == Some("S") || get("MSA") == Some("S") {
            0
        } else if get("SC")? == "H" || get("SI")? == "H" || get("SA")? == "H" {
            1
        } else {
            2
        };
        let eq5 = match get("E")? {
            "A" => 0,
            "P" => 1,
            "U" => 2,
            _ => return None,
        };
        let eq6 = if (get("CR")? == "H" && vc == "H")
            || (get("IR")? == "H" && vi == "H")
            || (get("AR")? == "H" && va == "H")
        {
            0
        } else {
            1
        };

        let macro_vector = format!("{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}");
        let value = LOOKUP
            .binary_search_by(|(key, _)| (*key).cmp(macro_vector.as_str()))
            .ok()
            .map(|index| LOOKUP[index].1)?;

        // Next-lower MacroVector scores per EQ (NaN → absent, ignored below).
        let next = |digits: [usize; 6]| -> f64 {
            let key = digits.map(|digit| char::from(b'0' + digit as u8));
            let key: String = key.iter().collect();
            LOOKUP
                .binary_search_by(|(probe, _)| (*probe).cmp(key.as_str()))
                .ok()
                .map(|index| LOOKUP[index].1)
                .unwrap_or(f64::NAN)
        };
        let mv = [eq1, eq2, eq3, eq4, eq5, eq6];
        let lower = |index: usize, bump: usize| {
            let mut digits = mv;
            digits[index] += bump;
            next(digits)
        };
        let score_eq1 = lower(0, 1);
        let score_eq2 = lower(1, 1);
        let score_eq3eq6 = match (eq3, eq6) {
            (0, 0) => next([eq1, eq2, eq3, eq4, eq5, eq6 + 1]).max(next([
                eq1,
                eq2,
                eq3 + 1,
                eq4,
                eq5,
                eq6,
            ])),
            (1, 1) | (0, 1) => next([eq1, eq2, eq3 + 1, eq4, eq5, eq6]),
            (1, 0) => next([eq1, eq2, eq3, eq4, eq5, eq6 + 1]),
            _ => next([eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]),
        };
        let score_eq4 = lower(3, 1);
        let score_eq5 = lower(4, 1);

        // Compose candidate maximum vectors and pick the first whose
        // severity distance to the scored vector is non-negative.
        fn parse_fragment(fragment: &str) -> BTreeMap<&str, &str> {
            fragment
                .split('/')
                .filter_map(|part| part.split_once(':'))
                .collect()
        }

        let mut max_vector: Option<BTreeMap<&str, &str>> = None;
        let mut distances: BTreeMap<&str, f64> = BTreeMap::new();
        'outer: for eq1_max in max_composed(1, eq1) {
            for eq2_max in max_composed(2, eq2) {
                for eq3_max in max_composed_eq3(eq3, eq6) {
                    for eq4_max in max_composed(4, eq4) {
                        for eq5_max in max_composed(5, eq5) {
                            let mut candidate = parse_fragment(eq1_max);
                            candidate.extend(parse_fragment(eq2_max));
                            candidate.extend(parse_fragment(eq3_max));
                            candidate.extend(parse_fragment(eq4_max));
                            candidate.extend(parse_fragment(eq5_max));
                            distances.clear();
                            let mut all_non_negative = true;
                            for metric in [
                                "AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA",
                                "CR", "IR", "AR", "E",
                            ] {
                                let effective_level = metric_level(metric, get(metric)?)?;
                                let max_level = candidate
                                    .get(metric)
                                    .and_then(|value| metric_level(metric, value))?;
                                let distance = effective_level - max_level;
                                distances.insert(metric, distance);
                                if distance < 0.0 {
                                    all_non_negative = false;
                                }
                            }
                            if all_non_negative {
                                max_vector = Some(candidate);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
        max_vector?;

        let distance_eq1 = distances["AV"] + distances["PR"] + distances["UI"];
        let distance_eq2 = distances["AC"] + distances["AT"];
        let distance_eq3eq6 = distances["VC"]
            + distances["VI"]
            + distances["VA"]
            + distances["CR"]
            + distances["IR"]
            + distances["AR"];
        let distance_eq4 = distances["SC"] + distances["SI"] + distances["SA"];

        const STEP: f64 = 0.1;
        let mut normalized = 0.0;
        let mut existing_lower = 0;
        for (available, distance, max_severity) in [
            (
                value - score_eq1,
                distance_eq1,
                max_severity(1, eq1, eq6)? * STEP,
            ),
            (
                value - score_eq2,
                distance_eq2,
                max_severity(2, eq2, eq6)? * STEP,
            ),
            (
                value - score_eq3eq6,
                distance_eq3eq6,
                max_severity(3, eq3, eq6)? * STEP,
            ),
            (
                value - score_eq4,
                distance_eq4,
                max_severity(4, eq4, eq6)? * STEP,
            ),
        ] {
            if !available.is_nan() {
                existing_lower += 1;
                normalized += available * (distance / max_severity);
            }
        }
        // EQ5's proportional distance is always zero but still counts as an
        // existing lower MacroVector.
        if !(value - score_eq5).is_nan() {
            existing_lower += 1;
        }
        let mean = if existing_lower == 0 {
            0.0
        } else {
            normalized / existing_lower as f64
        };
        let raw = (value - mean).clamp(0.0, 10.0);
        Some(((raw + 1e-6) * 10.0).round() / 10.0)
    }
}

fn cvss_v4_score(vector: &str) -> Option<f64> {
    cvss_v4::score(vector)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;
    use crate::model::{Asset, AssetId, AssetKind, ComponentId, Scope};
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
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
            locations: BTreeSet::new(),
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
        for url in [
            "not a URL",
            "data:text/plain,hello",
            "mailto:advisories@example.com",
            "urn:isbn:0451450523",
            "ftp://mirror.example.com/osv",
        ] {
            assert!(
                matches!(OsvClient::new(url, 4), Err(OsvError::InvalidBaseUrl(_))),
                "expected {url} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn configured_request_timeout_bounds_osv_calls() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_json(json!({"results":[{"vulns":[]}]})),
            )
            .mount(&server)
            .await;
        let inventory = inventory([component(
            "component:timeout",
            "timeout",
            "1.0.0",
            "pkg:cargo/timeout@1.0.0",
        )]);
        let error = OsvClient::with_timeouts(
            &server.uri(),
            1,
            Duration::from_secs(1),
            Duration::from_millis(5),
        )
        .unwrap()
        .scan(&inventory)
        .await
        .unwrap_err();
        assert!(
            matches!(&error, OsvError::Request { source, .. } if source.is_timeout()),
            "configured request timeout must surface as a bounded request failure: {error}"
        );
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
    async fn scan_fails_closed_when_pagination_exceeds_page_limit() {
        let server = MockServer::start().await;
        let purl = "pkg:npm/looped@1.0.0";
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
                "results": [{"vulns": [], "next_page_token": "next token"}]
            })))
            .expect(MAX_PAGES_PER_PURL as u64)
            .mount(&server)
            .await;

        let error = OsvClient::new(&server.uri(), 1)
            .unwrap()
            .scan(&inventory([component(
                "component:looped",
                "looped",
                "1.0.0",
                purl,
            )]))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OsvError::PageLimit { purl, maximum }
                if purl == "pkg:npm/looped@1.0.0" && maximum == MAX_PAGES_PER_PURL
        ));
    }

    #[tokio::test]
    async fn fetches_page_chains_concurrently_across_purls() {
        let server = MockServer::start().await;
        let purl_a = "pkg:npm/chain-a@1.0.0";
        let purl_b = "pkg:npm/chain-b@1.0.0";
        // Structural overlap proof for continuation chains: each chain's
        // page request registers itself as in-flight on arrival and holds
        // its slot for at most the 200ms response delay, so the recorded
        // peak reaches 2 only if both purl chains genuinely run
        // concurrently; a sequential per-purl chain loop would serialize
        // the two page requests and peak at 1.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));
        let spawner = tokio::runtime::Handle::current();

        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({
                "queries": [
                    {"package": {"purl": purl_a}},
                    {"package": {"purl": purl_b}},
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"vulns": [{"id": "OSV-A"}], "next_page_token": "token-a"},
                    {"vulns": [{"id": "OSV-B"}], "next_page_token": "token-b"},
                ]
            })))
            .mount(&server)
            .await;
        for (purl, token) in [(purl_a, "token-a"), (purl_b, "token-b")] {
            let in_flight = Arc::clone(&in_flight);
            let peak_in_flight = Arc::clone(&peak_in_flight);
            let spawner = spawner.clone();
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(json!({
                    "queries": [
                        {"package": {"purl": purl}, "page_token": token}
                    ]
                })))
                .respond_with(move |_request: &_| {
                    let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_in_flight.fetch_max(current, Ordering::SeqCst);

                    // Release the slot strictly before the delayed response
                    // is delivered (120ms < 400ms): sequential chains would
                    // therefore never observe a stale slot, while genuinely
                    // overlapping chains push the recorded peak to 2.
                    let release = Arc::clone(&in_flight);
                    spawner.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        release.fetch_sub(1, Ordering::SeqCst);
                    });
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(400))
                        .set_body_json(json!({
                            "results": [{"vulns": [], "next_page_token": ""}]
                        }))
                })
                .mount(&server)
                .await;
        }
        for id in ["OSV-A", "OSV-B"] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(detail(id, json!({}))))
                .mount(&server)
                .await;
        }

        let findings = OsvClient::new(&server.uri(), 2)
            .unwrap()
            .scan(&inventory([
                component("component:chain-a", "chain-a", "1.0.0", purl_a),
                component("component:chain-b", "chain-b", "1.0.0", purl_b),
            ]))
            .await
            .unwrap();

        assert_eq!(findings.len(), 2);
        let peak = peak_in_flight.load(Ordering::SeqCst);
        assert!(peak >= 2, "two purl chains should overlap: peak {peak}");
        assert!(
            peak <= 2,
            "chain concurrency must stay bounded by the client concurrency: peak {peak}"
        );
    }

    #[tokio::test]
    async fn merges_page_chain_results_identically_to_sequential_reference() {
        let server = MockServer::start().await;
        let purl_a = "pkg:npm/merge-a@1.0.0";
        let purl_b = "pkg:npm/merge-b@1.0.0";
        let purl_c = "pkg:npm/merge-c@1.0.0";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({
                "queries": [
                    {"package": {"purl": purl_a}},
                    {"package": {"purl": purl_b}},
                    {"package": {"purl": purl_c}},
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"vulns": [{"id": "OSV-1"}, {"id": "OSV-shared"}], "next_page_token": "a1"},
                    {"vulns": [{"id": "OSV-shared"}], "next_page_token": "b1"},
                    {"vulns": [{"id": "OSV-4"}]},
                ]
            })))
            .mount(&server)
            .await;
        for (purl, token, vulns, next) in [
            (purl_a, "a1", vec![json!({"id": "OSV-2"})], Some("a2")),
            (purl_a, "a2", vec![json!({"id": "OSV-3"})], None),
            (purl_b, "b1", Vec::<serde_json::Value>::new(), None),
        ] {
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(json!({
                    "queries": [
                        {"package": {"purl": purl}, "page_token": token}
                    ]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{
                        "vulns": vulns,
                        "next_page_token": next,
                    }]
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        for id in ["OSV-1", "OSV-2", "OSV-3", "OSV-4", "OSV-shared"] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(detail(id, json!({}))))
                .expect(1)
                .mount(&server)
                .await;
        }

        let findings = OsvClient::new(&server.uri(), 4)
            .unwrap()
            .scan(&inventory([
                component("component:merge-a", "merge-a", "1.0.0", purl_a),
                component("component:merge-b", "merge-b", "1.0.0", purl_b),
                component("component:merge-c", "merge-c", "1.0.0", purl_c),
            ]))
            .await
            .unwrap();

        // Sequential reference: fold each purl's pages in purl order exactly
        // as the previous per-purl sequential chain loop did.
        let pages_by_component: [(&str, Vec<Vec<&str>>); 3] = [
            (
                "component:merge-a",
                vec![vec!["OSV-1", "OSV-shared"], vec!["OSV-2"], vec!["OSV-3"]],
            ),
            ("component:merge-b", vec![vec!["OSV-shared"], Vec::new()]),
            ("component:merge-c", vec![vec!["OSV-4"]]),
        ];
        let reference: BTreeMap<&str, BTreeSet<&str>> = pages_by_component
            .into_iter()
            .map(|(component, pages)| {
                let mut ids = BTreeSet::new();
                for page in pages {
                    ids.extend(page);
                }
                (component, ids)
            })
            .collect();
        let observed: BTreeMap<&str, BTreeSet<&str>> =
            findings.values().fold(BTreeMap::new(), |mut acc, finding| {
                acc.entry(finding.component_id.as_ref().unwrap().as_str())
                    .or_default()
                    .insert(finding.advisory_id.as_deref().unwrap());
                acc
            });

        assert_eq!(observed, reference);
    }

    #[tokio::test]
    async fn fails_with_lowest_purl_when_concurrent_chains_exceed_page_limit() {
        let server = MockServer::start().await;
        let purl_first = "pkg:npm/looped-a@1.0.0";
        let purl_second = "pkg:npm/looped-b@1.0.0";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(json!({
                "queries": [
                    {"package": {"purl": purl_first}},
                    {"package": {"purl": purl_second}},
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"vulns": [], "next_page_token": "token-a"},
                    {"vulns": [], "next_page_token": "token-b"},
                ]
            })))
            .mount(&server)
            .await;
        // Both chains echo a stable token forever, so each independently
        // enforces `MAX_PAGES_PER_PURL` under concurrency; the scan must
        // attribute the failure to the first failing purl in input order.
        for (purl, token) in [(purl_first, "token-a"), (purl_second, "token-b")] {
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(json!({
                    "queries": [
                        {"package": {"purl": purl}, "page_token": token}
                    ]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{
                        "vulns": [],
                        "next_page_token": token,
                    }]
                })))
                .expect(MAX_PAGES_PER_PURL as u64)
                .mount(&server)
                .await;
        }

        let error = OsvClient::new(&server.uri(), 2)
            .unwrap()
            .scan(&inventory([
                component("component:looped-a", "looped-a", "1.0.0", purl_first),
                component("component:looped-b", "looped-b", "1.0.0", purl_second),
            ]))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OsvError::PageLimit { purl, maximum }
                if purl == purl_first && maximum == MAX_PAGES_PER_PURL
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_response_bodies() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("a".repeat(MAX_RESPONSE_BYTES + 1)),
            )
            .mount(&server)
            .await;

        let error = OsvClient::new(&server.uri(), 1)
            .unwrap()
            .scan(&inventory([component(
                "component:failure",
                "failure",
                "1.0.0",
                "pkg:cargo/failure@1.0.0",
            )]))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OsvError::TooLarge { actual, maximum, .. }
                if actual > maximum && maximum == MAX_RESPONSE_BYTES
        ));
    }

    /// Shared failure-matrix harness: mounts `batch` on POST /v1/querybatch and,
    /// when present, `detail` on GET /v1/vulns/OSV-detail, then returns the
    /// scan error for a single-component inventory.
    async fn scan_failing_via(
        batch: ResponseTemplate,
        detail: Option<ResponseTemplate>,
    ) -> OsvError {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(batch)
            .mount(&server)
            .await;
        if let Some(detail_response) = detail {
            Mock::given(method("GET"))
                .and(path("/v1/vulns/OSV-detail"))
                .respond_with(detail_response)
                .mount(&server)
                .await;
        }
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

    #[tokio::test]
    async fn reports_batch_http_body_decode_and_result_count_failures() {
        let error = scan_failing_via(
            ResponseTemplate::new(503).set_body_string("upstream unavailable"),
            None,
        )
        .await;
        assert!(matches!(
            error,
            OsvError::Http { status, body, .. }
                if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    && body == "upstream unavailable"
        ));

        let error =
            scan_failing_via(ResponseTemplate::new(200).set_body_string("not json"), None).await;
        assert!(
            matches!(error, OsvError::Decode { endpoint, .. } if endpoint.ends_with("/v1/querybatch"))
        );

        let error = scan_failing_via(
            ResponseTemplate::new(200).set_body_json(json!({"results": []})),
            None,
        )
        .await;
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
        let successful_batch = ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [{"id": "OSV-detail"}]}]
        }));

        let error = scan_failing_via(
            successful_batch.clone(),
            Some(ResponseTemplate::new(404).set_body_string("missing advisory")),
        )
        .await;
        assert!(matches!(
            error,
            OsvError::Http { status, body, endpoint }
                if status == reqwest::StatusCode::NOT_FOUND
                    && body == "missing advisory"
                    && endpoint.ends_with("/v1/vulns/OSV-detail")
        ));
        let error = scan_failing_via(
            successful_batch.clone(),
            Some(ResponseTemplate::new(429).set_body_string("rate limited")),
        )
        .await;
        assert!(matches!(
            error,
            OsvError::Http { status, body, endpoint }
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    && body == "rate limited"
                    && endpoint.ends_with("/v1/vulns/OSV-detail")
        ));
        let error = scan_failing_via(
            successful_batch,
            Some(ResponseTemplate::new(200).set_body_string("{")),
        )
        .await;
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

        // Severity must come from demo's own affected entry ("HIGH"); the
        // sibling pkg:cargo/other "critical" label must not inflate it.
        assert_eq!(finding.severity, Severity::High);
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
        // Structural overlap proof instead of a wall-clock upper bound: every
        // GET registers itself as in flight on arrival and holds its slot for
        // most of the 400ms response delay, so the recorded peak reaches 2
        // only if both detail fetches genuinely ran concurrently.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));
        let spawner = tokio::runtime::Handle::current();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}]}]
            })))
            .mount(&server)
            .await;
        for id in ["OSV-1", "OSV-2"] {
            let in_flight = Arc::clone(&in_flight);
            let peak_in_flight = Arc::clone(&peak_in_flight);
            let spawner = spawner.clone();
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(move |_: &Request| {
                    let outstanding = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_in_flight.fetch_max(outstanding, Ordering::SeqCst);
                    // Release the slot strictly before the delayed response is
                    // delivered (120ms < 400ms): a sequential client therefore
                    // never observes a stale slot, while truly overlapping
                    // fetches push the recorded peak to 2.
                    let release = Arc::clone(&in_flight);
                    spawner.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        release.fetch_sub(1, Ordering::SeqCst);
                    });
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(400))
                        .set_body_json(detail(id, json!({})))
                })
                .mount(&server)
                .await;
        }
        let inventory = inventory([component(
            "component:concurrent",
            "concurrent",
            "1.0.0",
            "pkg:cargo/concurrent@1.0.0",
        )]);

        let findings = OsvClient::new(&server.uri(), 2)
            .unwrap()
            .scan(&inventory)
            .await
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert!(
            peak_in_flight.load(Ordering::SeqCst) >= 2,
            "two independent detail requests should overlap"
        );
    }

    #[test]
    fn truncates_retained_http_error_bodies() {
        assert_eq!(
            truncated_error_body(b"upstream unavailable"),
            "upstream unavailable"
        );

        let long = vec![b'a'; MAX_ERROR_BODY_BYTES + 1];
        assert_eq!(truncated_error_body(&long).len(), MAX_ERROR_BODY_BYTES);

        // A multi-byte sequence cut at the retention boundary decodes lossily
        // instead of panicking.
        let mut multibyte = vec![b'x'; MAX_ERROR_BODY_BYTES - 1];
        multibyte.extend_from_slice("é".as_bytes());
        let retained = truncated_error_body(&multibyte);
        assert_eq!(retained.chars().count(), MAX_ERROR_BODY_BYTES);
        assert!(retained.ends_with('\u{FFFD}'));
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
        let component = component("demo", "demo", "1.0.0", "pkg:cargo/demo@1.0.0");
        assert_eq!(
            vulnerability_severity(&vulnerability, &component),
            Severity::Critical
        );
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
