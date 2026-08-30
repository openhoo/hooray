use std::{
    borrow::Cow,
    collections::BTreeMap,
    future::Future,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{net::TcpListener, sync::Semaphore};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::{
    config::Config,
    engine::{
        FinalizeError, ScanParts, attach_dependency_remediation, contextualize_and_score,
        finalize_scan, merge_findings, merge_operational_risk,
    },
    graph::DependencyGraph,
    license,
    model::{Finding, FindingKind, Inventory, RunId, ScanReport, Severity},
    monitor::FindingDiff,
    osv::{OsvClient, OsvError},
    policy::{Policy, PolicyException},
    report::{sanitize_report, sanitize_value},
    store::{FindingFilter, InventoryFilter, MAX_PAGE_SIZE, Store, StoreError},
};

const API_VERSION: &str = "v1";
const DEFAULT_PAGE_SIZE: u32 = 100;
const MAX_FILTER_LENGTH: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Route whose authoritative store write must complete once started; the
/// timeout middleware exempts exactly this route via `is_write_completing`.
const SCAN_SUBMIT_PATH: &str = "/v1/scans";

#[derive(Debug, Error)]
pub enum ApiStateError {
    #[error("invalid configuration: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("invalid vulnerability service endpoint: {0}")]
    Osv(#[from] OsvError),
}

#[derive(Clone)]
pub struct ApiState {
    store: Arc<Mutex<Store>>,
    config: Arc<Config>,
    osv: Arc<OsvClient>,
    scan_slots: Arc<Semaphore>,
}

impl ApiState {
    pub fn new(store: Store, config: Config) -> Result<Self, ApiStateError> {
        config.validate()?;
        // One shared OSV client per API process: endpoint validation happens
        // once at state construction instead of on every scan request.
        let osv = Arc::new(OsvClient::with_timeouts(
            &config.osv_url,
            config.max_concurrency,
            Duration::from_secs(config.osv_connect_timeout_secs),
            Duration::from_secs(config.osv_request_timeout_secs),
        )?);
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            scan_slots: Arc::new(Semaphore::new(config.max_concurrency)),
            osv,
            config: Arc::new(config),
        })
    }
}

pub fn router(state: ApiState) -> Router {
    let max_body = usize::try_from(state.config.max_request_bytes).unwrap_or(usize::MAX);
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route(SCAN_SUBMIT_PATH, post(create_scan))
        .route("/v1/runs", get(list_runs))
        .route("/v1/runs/{run_id}", get(get_run))
        .route("/v1/runs/{run_id}/diff/{baseline_run_id}", get(diff_runs))
        .route("/v1/runs/{run_id}/findings", get(get_findings))
        .route("/v1/runs/{run_id}/inventory", get(get_inventory))
        .route("/v1/findings", get(query_findings))
        .route("/v1/inventory", get(query_inventory))
        .route("/v1/reports/{run_id}", get(get_report))
        .route("/v1/policies/validate", post(validate_policy))
        .route("/v1/policies/evaluate", post(evaluate_policy))
        .route("/v1/exceptions/validate", post(validate_exception))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(middleware::from_fn(timeout_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(safe_cors())
        .with_state(state)
}

/// Serves the router on an already-bound listener; readiness is therefore
/// bind-and-listen completion in the caller, and graceful shutdown drains
/// in-flight requests before returning.
pub async fn serve<F>(
    listener: TcpListener,
    state: ApiState,
    shutdown: F,
) -> Result<(), std::io::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
}

pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async move {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

fn safe_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT, REQUEST_ID_HEADER])
        .expose_headers([REQUEST_ID_HEADER])
        .max_age(Duration::from_secs(600))
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok","version":API_VERSION}))
}

async fn ready(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    store_call(&state, |store| store.latest_run().map(|_| ())).await?;
    Ok(Json(json!({"status":"ready","version":API_VERSION})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    inventory: Inventory,
    #[serde(default)]
    policy: Option<Policy>,
    #[serde(default)]
    metadata: BTreeMap<String, Value>,
}

async fn create_scan(
    State(state): State<ApiState>,
    payload: Result<Json<ScanRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    scan_with_deadline(state, payload, REQUEST_TIMEOUT).await
}

/// POST /v1/scans must complete its authoritative store write once started, so
/// the timeout middleware never aborts this route; the upstream vulnerability
/// fetch is bounded here instead so a stalled OSV connection cannot pin scan
/// slots indefinitely.
async fn scan_with_deadline(
    state: ApiState,
    payload: Result<Json<ScanRequest>, JsonRejection>,
    fetch_bound: Duration,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    request
        .inventory
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_inventory", error.to_string()))?;
    let permit = state.scan_slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "scan_capacity_exceeded",
            "scan capacity is exhausted",
        )
    })?;
    let started_at = timestamp();
    let as_of = Utc::now();
    let mut findings = if state.config.offline {
        BTreeMap::new()
    } else {
        match tokio::time::timeout(fetch_bound, state.osv.scan(&request.inventory)).await {
            Ok(result) => result.map_err(|error| vulnerability_service_error(&error))?,
            Err(_) => {
                return Err(ApiError::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "vulnerability_service_timeout",
                    "vulnerability service processing exceeded the time limit",
                ));
            }
        }
    };
    // Run every inventory-only analysis stage exposed by the CLI. Filesystem
    // analysis is intentionally absent because this endpoint receives a
    // normalized inventory rather than an untrusted filesystem path.
    let graph = DependencyGraph::from_inventory(&request.inventory)
        .map_err(|error| ApiError::internal("finding_scoring_failed", error.to_string()))?;
    contextualize_and_score(&request.inventory, &graph, &mut findings, as_of)
        .map_err(|error| ApiError::internal("finding_scoring_failed", error.to_string()))?;
    let license_findings = license::analyze(
        &request.inventory,
        None,
        state.config.max_input_bytes.min(8 * 1024 * 1024),
    )
    .map_err(|error| ApiError::internal("license_analysis_failed", error.to_string()))?
    .findings;
    merge_findings(&mut findings, license_findings);
    attach_dependency_remediation(&request.inventory, &graph, &mut findings)
        .map_err(|error| ApiError::internal("finding_scoring_failed", error.to_string()))?;
    merge_operational_risk(&request.inventory, &graph, &mut findings, as_of);
    contextualize_and_score(&request.inventory, &graph, &mut findings, as_of)
        .map_err(|error| ApiError::internal("finding_scoring_failed", error.to_string()))?;
    let report = finalize_scan(
        request.policy.as_ref(),
        ScanParts {
            inventory: request.inventory,
            findings,
            run_id: RunId::new(format!("run:{}", Uuid::new_v4()))
                .expect("generated UUID run identifier is non-empty"),
            started_at,
            completed_at: timestamp(),
            scanner_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            metadata: request.metadata,
        },
        as_of,
    )
    .map_err(|error| match error {
        FinalizeError::Policy(error) => {
            ApiError::unprocessable("invalid_policy", error.to_string())
        }
        FinalizeError::Invariant(error) => {
            ApiError::internal("invalid_generated_report", error.to_string())
        }
    })?;
    let run_id = report.run.id.clone();
    store_call(&state, move |store| {
        let _permit = permit;
        store.save_report(&report)
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "version": API_VERSION,
            "run_id": run_id,
            "status": "completed"
        })),
    ))
}

/// Maps upstream OSV failures onto the error envelope without echoing the
/// configured endpoint URL, upstream response bodies, or transport details:
/// upstream internals are never rendered to API callers (redaction contract).
fn vulnerability_service_error(error: &OsvError) -> ApiError {
    let message = match error {
        OsvError::Http { .. } => "the vulnerability service returned an error response",
        OsvError::Request { .. } => "the vulnerability service could not be reached",
        OsvError::Decode { .. } => "the vulnerability service returned an unreadable response",
        OsvError::ResultCount { .. } => {
            "the vulnerability service returned a malformed batch result"
        }
        OsvError::InvalidVulnerabilityId => {
            "the vulnerability service returned a malformed advisory"
        }
        OsvError::PageLimit { .. } => "the vulnerability service returned too many results",
        OsvError::TooLarge { .. } => {
            "the vulnerability service response exceeds the supported size"
        }
        OsvError::InvalidBaseUrl(_) => "the vulnerability service location is invalid",
        OsvError::Client(_) => "the vulnerability service client could not be initialized",
    };
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "vulnerability_service_failed",
        message,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    #[serde(default = "default_page_size")]
    limit: u32,
    #[serde(default)]
    offset: u64,
}

const fn default_page_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

impl PageQuery {
    const fn new(limit: u32, offset: u64) -> Self {
        Self { limit, offset }
    }

    fn validate(&self) -> Result<(), ApiError> {
        if self.limit == 0 || self.limit > MAX_PAGE_SIZE {
            return Err(ApiError::bad_request(
                "invalid_pagination",
                format!("limit must be between 1 and {MAX_PAGE_SIZE}"),
            ));
        }
        if self.offset > i64::MAX as u64 {
            return Err(ApiError::bad_request(
                "invalid_pagination",
                "offset exceeds the supported range",
            ));
        }
        Ok(())
    }
}

async fn list_runs(
    State(state): State<ApiState>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(page) = query.map_err(ApiError::from_query_rejection)?;
    page.validate()?;
    let limit = page.limit;
    let offset = page.offset;
    let runs = store_call(&state, move |store| store.list_runs(limit, offset)).await?;
    let runs = runs
        .iter()
        .map(sanitize_api_report)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({
        "version": API_VERSION,
        "limit": limit,
        "offset": offset,
        "count": runs.len(),
        "runs": runs
    })))
}

async fn get_run(
    State(state): State<ApiState>,
    Path(run_id): Path<String>,
) -> Result<Json<ScanReport>, ApiError> {
    Ok(Json(load_report(&state, run_id).await?))
}

async fn diff_runs(
    State(state): State<ApiState>,
    Path((run_id, baseline_run_id)): Path<(String, String)>,
) -> Result<Json<DiffResponse>, ApiError> {
    let current = parse_run_id(run_id)?;
    let baseline = parse_run_id(baseline_run_id)?;
    let current_id = current.clone();
    let baseline_id = baseline.clone();
    let diff = store_call(&state, move |store| {
        store.diff_runs(&baseline_id, &current_id)
    })
    .await?;
    Ok(Json(DiffResponse::new(baseline, current, diff)))
}

#[derive(Debug, Serialize)]
struct DiffResponse {
    version: &'static str,
    baseline_run_id: RunId,
    run_id: RunId,
    introduced: Vec<crate::model::FindingId>,
    resolved: Vec<crate::model::FindingId>,
    unchanged: Vec<crate::model::FindingId>,
}

impl DiffResponse {
    fn new(baseline_run_id: RunId, run_id: RunId, diff: FindingDiff) -> Self {
        Self {
            version: API_VERSION,
            baseline_run_id,
            run_id,
            introduced: diff.introduced,
            resolved: diff.resolved,
            unchanged: diff.unchanged,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingQuery {
    #[serde(default = "default_page_size")]
    limit: u32,
    #[serde(default)]
    offset: u64,
    kind: Option<String>,
    severity: Option<String>,
    rule_id: Option<String>,
}

impl FindingQuery {
    /// Filter parsing shared by `/v1/findings` and the per-run findings route
    /// so validation cannot drift between them.
    fn parsed(&self) -> Result<(Option<FindingKind>, Option<Severity>), ApiError> {
        validate_filter("rule_id", self.rule_id.as_deref())?;
        let kind = self.kind.as_deref().map(parse_finding_kind).transpose()?;
        let severity = self
            .severity
            .as_deref()
            .map(|value| {
                Severity::from_str(value)
                    .map_err(|error| ApiError::bad_request("invalid_filter", error.to_string()))
            })
            .transpose()?;
        Ok((kind, severity))
    }
}

async fn query_findings(
    State(state): State<ApiState>,
    query: Result<Query<FindingQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    PageQuery::new(query.limit, query.offset).validate()?;
    let (kind, severity) = query.parsed()?;
    let filter = FindingFilter {
        kind: kind.map(|value| value.as_str().to_owned()),
        severity: severity.map(|value| value.as_str().to_owned()),
        rule_id: query.rule_id,
        ..Default::default()
    };
    let limit = query.limit;
    let offset = query.offset;
    let findings = store_call(&state, move |store| {
        store.query_findings(&filter, limit, offset)
    })
    .await?;
    let mut response = json!({"version":API_VERSION,"limit":limit,"offset":offset,"count":findings.len(),"findings":findings});
    sanitize_value(&mut response);
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryQuery {
    #[serde(default = "default_page_size")]
    limit: u32,
    #[serde(default)]
    offset: u64,
    asset_id: Option<String>,
    component_id: Option<String>,
    name: Option<String>,
    purl: Option<String>,
    scope: Option<String>,
}

async fn query_inventory(
    State(state): State<ApiState>,
    query: Result<Query<InventoryQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    PageQuery::new(query.limit, query.offset).validate()?;
    for (name, value) in [
        ("asset_id", query.asset_id.as_deref()),
        ("component_id", query.component_id.as_deref()),
        ("name", query.name.as_deref()),
        ("purl", query.purl.as_deref()),
        ("scope", query.scope.as_deref()),
    ] {
        validate_filter(name, value)?;
    }
    let filter = InventoryFilter {
        asset_id: query.asset_id,
        component_id: query.component_id,
        name: query.name,
        purl: query.purl,
        scope: query.scope,
        ..Default::default()
    };
    let limit = query.limit;
    let offset = query.offset;
    let components = store_call(&state, move |store| {
        store.query_inventory(&filter, limit, offset)
    })
    .await?;
    let mut response = json!({"version":API_VERSION,"limit":limit,"offset":offset,"count":components.len(),"components":components});
    sanitize_value(&mut response);
    Ok(Json(response))
}

async fn get_findings(
    State(state): State<ApiState>,
    Path(run_id): Path<String>,
    query: Result<Query<FindingQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    PageQuery::new(query.limit, query.offset).validate()?;
    let (kind, severity) = query.parsed()?;
    let report = load_report(&state, run_id).await?;
    let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
    let findings: Vec<&Finding> = report
        .findings
        .values()
        .filter(|finding| kind.is_none_or(|value| finding.kind == value))
        .filter(|finding| severity.is_none_or(|value| finding.severity == value))
        .filter(|finding| {
            query
                .rule_id
                .as_deref()
                .is_none_or(|value| finding.rule_id.as_str() == value)
        })
        .skip(offset)
        .take(query.limit as usize)
        .collect();
    Ok(Json(json!({
        "version": API_VERSION,
        "run_id": report.run.id,
        "limit": query.limit,
        "offset": query.offset,
        "count": findings.len(),
        "findings": findings
    })))
}

async fn get_inventory(
    State(state): State<ApiState>,
    Path(run_id): Path<String>,
) -> Result<Json<Inventory>, ApiError> {
    Ok(Json(load_report(&state, run_id).await?.inventory))
}

async fn get_report(
    State(state): State<ApiState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let report = load_report(&state, run_id).await?;
    negotiate_report(&headers, &report)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    policy: Policy,
}

async fn validate_policy(
    payload: Result<Json<PolicyDocument>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    request
        .policy
        .validate()
        .map_err(|error| ApiError::unprocessable("invalid_policy", error.to_string()))?;
    Ok(Json(json!({"version":API_VERSION,"valid":true})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationRequest {
    policy: Policy,
    report: ScanReport,
    evaluated_at: String,
}

async fn evaluate_policy(
    payload: Result<Json<EvaluationRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    request
        .report
        .validate()
        .map_err(|error| ApiError::unprocessable("invalid_scan_report", error.to_string()))?;
    let evaluated_at = DateTime::parse_from_rfc3339(&request.evaluated_at)
        .map_err(|_| ApiError::bad_request("invalid_timestamp", "evaluated_at must be RFC 3339"))?;
    let evaluation = request
        .policy
        .evaluate(
            &request.report.findings,
            &request.report.inventory,
            evaluated_at,
        )
        .map_err(|error| ApiError::unprocessable("invalid_policy", error.to_string()))?;
    Ok(Json(json!({
        "version": API_VERSION,
        "decisions": evaluation.decisions,
        "summary": evaluation.summary
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionDocument {
    exception: PolicyException,
}

async fn validate_exception(
    payload: Result<Json<ExceptionDocument>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let policy = Policy {
        version: crate::policy::POLICY_SCHEMA_VERSION,
        fail_closed: Default::default(),
        default_outcome: crate::model::PolicyOutcome::Allow,
        rules: Vec::new(),
        exceptions: vec![request.exception],
    };
    policy
        .validate()
        .map_err(|error| ApiError::unprocessable("invalid_exception", error.to_string()))?;
    Ok(Json(json!({"version":API_VERSION,"valid":true})))
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

async fn load_report(state: &ApiState, raw_id: String) -> Result<ScanReport, ApiError> {
    let run_id = parse_run_id(raw_id)?;
    let lookup_id = run_id.clone();
    let report = store_call(state, move |store| store.get_run(&lookup_id))
        .await?
        .ok_or_else(|| {
            ApiError::not_found("run_not_found", format!("run '{run_id}' was not found"))
        })?;
    match sanitize_api_report(&report)? {
        // Clean reports stay zero-copy: the freshly loaded owned value is
        // returned as-is instead of cloning the borrowed view.
        Cow::Borrowed(_) => Ok(report),
        Cow::Owned(sanitized) => Ok(sanitized),
    }
}

fn sanitize_api_report(report: &ScanReport) -> Result<Cow<'_, ScanReport>, ApiError> {
    sanitize_report(report)
        .map_err(|error| ApiError::internal("report_sanitization_failed", error.to_string()))
}

fn parse_run_id(value: String) -> Result<RunId, ApiError> {
    validate_filter("run_id", Some(&value))?;
    RunId::new(value)
        .map_err(|_| ApiError::bad_request("invalid_run_id", "run_id must not be empty"))
}

fn validate_filter(name: &str, value: Option<&str>) -> Result<(), ApiError> {
    if let Some(value) = value
        && (value.is_empty()
            || value.len() > MAX_FILTER_LENGTH
            || value.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(
            "invalid_filter",
            format!("{name} must contain 1 to {MAX_FILTER_LENGTH} non-control characters"),
        ));
    }
    Ok(())
}

fn parse_finding_kind(value: &str) -> Result<FindingKind, ApiError> {
    match value {
        "vulnerability" => Ok(FindingKind::Vulnerability),
        "license" => Ok(FindingKind::License),
        "secret" => Ok(FindingKind::Secret),
        "iac" => Ok(FindingKind::Iac),
        "sast" => Ok(FindingKind::Sast),
        "malware" => Ok(FindingKind::Malware),
        "operational-risk" => Ok(FindingKind::OperationalRisk),
        _ => Err(ApiError::bad_request(
            "invalid_filter",
            "unknown finding kind",
        )),
    }
}

fn negotiate_report(headers: &HeaderMap, report: &ScanReport) -> Result<Response, ApiError> {
    match preferred_report_media(headers) {
        Some(ReportMedia::Json) => {
            let bytes = serde_json::to_vec(report)
                .map_err(|error| ApiError::internal("serialization_failed", error.to_string()))?;
            Ok(([(CONTENT_TYPE, "application/json")], bytes).into_response())
        }
        Some(ReportMedia::Yaml) => {
            let bytes = serde_yaml::to_string(report)
                .map_err(|error| ApiError::internal("serialization_failed", error.to_string()))?;
            Ok(([(CONTENT_TYPE, "application/yaml")], bytes).into_response())
        }
        None => Err(ApiError::new(
            StatusCode::NOT_ACCEPTABLE,
            "unsupported_report_format",
            "supported report formats are application/json and application/yaml",
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportMedia {
    Json,
    Yaml,
}

fn preferred_report_media(headers: &HeaderMap) -> Option<ReportMedia> {
    if !headers.contains_key(ACCEPT) {
        return Some(ReportMedia::Json);
    }
    let ranges = headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(parse_media_range)
        .collect::<Vec<_>>();
    let json = representation_quality(&ranges, &["application/json"]);
    let yaml = representation_quality(
        &ranges,
        &["application/yaml", "application/x-yaml", "text/yaml"],
    );
    match (json, yaml) {
        (0, 0) => None,
        (json, yaml) if yaml > json => Some(ReportMedia::Yaml),
        _ => Some(ReportMedia::Json),
    }
}

fn parse_media_range(value: &str) -> Option<(String, u16)> {
    let mut parts = value.split(';');
    let media = parts.next()?.trim().to_ascii_lowercase();
    let (kind, subtype) = media.split_once('/')?;
    if kind.is_empty()
        || subtype.is_empty()
        || kind.contains(char::is_whitespace)
        || subtype.contains(char::is_whitespace)
    {
        return None;
    }
    let mut quality = 1_000;
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            quality = parse_quality(value.trim()).unwrap_or(0);
        }
    }
    Some((media, quality))
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    if fractional.len() > 3 || !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let padded = format!("{fractional:0<3}");
            padded.parse().ok()
        }
        "1" if fractional.bytes().all(|byte| byte == b'0') => Some(1_000),
        _ => None,
    }
}

fn representation_quality(ranges: &[(String, u16)], aliases: &[&str]) -> u16 {
    ranges
        .iter()
        .filter_map(|(range, quality)| {
            let specificity = if aliases.contains(&range.as_str()) {
                2
            } else if range == "*/*" {
                0
            } else if let Some(kind) = range.strip_suffix("/*") {
                aliases
                    .iter()
                    .any(|alias| alias.starts_with(&format!("{kind}/")))
                    .then_some(1)?
            } else {
                return None;
            };
            Some((specificity, *quality))
        })
        .max_by_key(|(specificity, quality)| (*specificity, *quality))
        .map_or(0, |(_, quality)| quality)
}

async fn store_call<T, F>(state: &ApiState, operation: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
{
    let store = Arc::clone(&state.store);
    tokio::task::spawn_blocking(move || {
        let mut store = store
            .lock()
            .map_err(|_| ApiError::internal("store_unavailable", "store lock is poisoned"))?;
        operation(&mut store).map_err(ApiError::from)
    })
    .await
    .map_err(|_| ApiError::internal("store_unavailable", "store operation was cancelled"))?
}

async fn auth_middleware(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let Some(expected) = &state.config.auth_bearer_sha256 else {
        return next.run(request).await;
    };
    let authenticated = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer_token)
        .is_some_and(|token| expected.matches_token(token));
    if !authenticated {
        let mut response = ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid bearer authentication is required",
        )
        .into_response();
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer"),
        );
        return response;
    }
    next.run(request).await
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(token)
}

async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_write_completing(method: &Method, path: &str) -> bool {
    method == Method::POST && path == SCAN_SUBMIT_PATH
}

async fn timeout_middleware(request: Request, next: Next) -> Response {
    timeout_middleware_with_duration(request, next, REQUEST_TIMEOUT).await
}

async fn timeout_middleware_with_duration(
    request: Request,
    next: Next,
    timeout: Duration,
) -> Response {
    let request_id = request.extensions().get::<RequestId>().cloned();
    // POST /v1/scans must complete its authoritative store write once started,
    // so this route is never aborted here; its upstream vulnerability fetch is
    // bounded inside create_scan instead, so a stalled OSV connection cannot
    // pin scan slots indefinitely.
    let write_outcome_must_complete = is_write_completing(request.method(), request.uri().path());
    if write_outcome_must_complete {
        return next.run(request).await;
    }
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::with_request_id(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timeout",
            "request processing exceeded the time limit",
            request_id,
        )
        .into_response(),
    }
}

async fn not_found() -> ApiError {
    ApiError::not_found("route_not_found", "the requested route does not exist")
}

#[derive(Clone)]
struct RequestId(String);

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: Option<String>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: None,
        }
    }

    fn with_request_id(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        request_id: Option<RequestId>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: request_id.map(|value| value.0),
        }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }
    fn from_json_rejection(rejection: JsonRejection) -> Self {
        let status = rejection.status();
        let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
            "request_too_large"
        } else {
            "invalid_json"
        };
        Self::new(status, code, rejection.body_text())
    }

    fn from_query_rejection(rejection: QueryRejection) -> Self {
        Self::bad_request("invalid_query", rejection.body_text())
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::RunNotFound(_) => Self::not_found("run_not_found", error.to_string()),
            StoreError::InvalidPageLimit(_) | StoreError::InvalidPageOffset(_) => {
                Self::bad_request("invalid_pagination", error.to_string())
            }
            StoreError::InvalidReport(_) | StoreError::UnredactedSecret { .. } => {
                Self::unprocessable("invalid_scan_report", error.to_string())
            }
            _ => Self::internal("store_error", "the store operation failed"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            version: API_VERSION,
            error: ErrorBody {
                code: self.code,
                message: self.message,
                request_id: self.request_id,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    version: &'static str,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{
        body::Body,
        http::{Request, header},
    };
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::oneshot,
    };
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, Component, Confidence, Evidence, FindingId, FindingStatus,
        Location, LocationId, PolicyDecision, PolicyId, PolicyOutcome, PolicySummary, Position,
        RuleId, RunMetadata, Scope,
    };

    fn report(id: &str) -> ScanReport {
        ScanReport {
            schema_version: "1".to_owned(),
            run: RunMetadata {
                id: RunId::new(id).unwrap(),
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                completed_at: Some("2026-01-01T00:00:01Z".to_owned()),
                scanner_version: Some("test".to_owned()),
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: Asset {
                    id: AssetId::new("asset:test").unwrap(),
                    name: "test".to_owned(),
                    kind: AssetKind::Repository,
                    version: None,
                    metadata: BTreeMap::new(),
                },
                components: BTreeMap::new(),
                locations: BTreeSet::from([Location {
                    id: LocationId::new("location:sample").unwrap(),
                    asset_id: AssetId::new("asset:test").unwrap(),
                    path: "sample.py".into(),
                    start: Some(Position { line: 1, column: 1 }),
                    end: Some(Position { line: 1, column: 8 }),
                }]),
                dependencies: BTreeSet::new(),
            },
            findings: BTreeMap::new(),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        }
    }
    fn component(_id: &str, name: &str, purl: &str, scope: Scope) -> Component {
        // Inventory::validate now requires identities derived from the purl.
        Component {
            identity: crate::model::stable_component_id(purl).unwrap(),
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            purl: purl.to_owned(),
            scope,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    fn finding(id: &str, kind: FindingKind, severity: Severity, rule_id: &str) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            kind,
            rule_id: RuleId::new(rule_id).unwrap(),
            advisory_id: None,
            component_id: None,
            location_id: None,
            aliases: BTreeSet::new(),
            summary: Some(format!("summary for {id}")),
            details: None,
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

    fn rich_report(id: &str, findings: &[Finding]) -> ScanReport {
        let mut value = report(id);
        let runtime = component(
            "component:runtime",
            "runtime-lib",
            "pkg:cargo/runtime-lib@1.0.0",
            Scope::Runtime,
        );
        let development = component(
            "component:dev",
            "dev-lib",
            "pkg:cargo/dev-lib@1.0.0",
            Scope::Development,
        );
        value.inventory.components = BTreeMap::from([
            (runtime.identity.clone(), runtime),
            (development.identity.clone(), development),
        ]);
        value.findings = findings
            .iter()
            .cloned()
            .map(|finding| (finding.id.clone(), finding))
            .collect();
        value
    }

    fn app(config: Config) -> Router {
        router(ApiState::new(Store::open_memory().unwrap(), config).unwrap())
    }

    fn seeded_app(config: Config, reports: &[ScanReport]) -> Router {
        let mut store = Store::open_memory().unwrap();
        for report in reports {
            store.save_report(report).unwrap();
        }
        router(ApiState::new(store, config).unwrap())
    }

    async fn response(app: Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        (status, json_body(response).await)
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    fn token_config(token: &str) -> Config {
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        Config {
            auth_bearer_sha256: Some(serde_json::from_value(Value::String(hash)).unwrap()),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn health_readiness_and_poisoned_store_are_observable() {
        let application = app(Config::default());
        let (status, body) = response(
            application.clone(),
            Request::get("/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"status":"ok","version":"v1"}));

        let (status, body) = response(
            application,
            Request::get("/ready").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"status":"ready","version":"v1"}));

        let state = ApiState::new(Store::open_memory().unwrap(), Config::default()).unwrap();
        let store = Arc::clone(&state.store);
        assert!(
            std::thread::spawn(move || {
                let _guard = store.lock().unwrap();
                panic!("poison test store");
            })
            .join()
            .is_err()
        );
        let (status, body) = response(
            router(state),
            Request::get("/ready").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "store_unavailable");
    }

    #[tokio::test]
    async fn creates_online_and_offline_scans_with_inventory_analyses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results":[{"vulns":[]},{"vulns":[]}]})),
            )
            .mount(&server)
            .await;
        let inventory = rich_report("template", &[]).inventory;
        let config = Config {
            osv_url: server.uri(),
            ..Config::default()
        };
        let application = app(config);
        let (status, body) = response(
            application.clone(),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inventory":inventory,"metadata":{"source":"api-test"}}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], "completed");
        let run_id = body["run_id"].as_str().unwrap();
        let (status, saved) = response(
            application,
            Request::get(format!("/v1/runs/{run_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["run"]["metadata"]["source"], "api-test");
        assert_eq!(saved["findings"].as_object().unwrap().len(), 2);
        assert!(
            saved["findings"]
                .as_object()
                .unwrap()
                .values()
                .all(|finding| finding["kind"] == "license"
                    && finding["rule_id"] == "license:unknown")
        );

        let mut invalid = rich_report("template", &[]).inventory;
        invalid.asset.name.clear();
        let (status, body) = response(
            app(Config::default()),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"inventory":invalid}).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_inventory");

        let offline_application = app(Config {
            offline: true,
            ..Config::default()
        });
        let (status, body) = response(
            offline_application.clone(),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inventory":rich_report("template", &[]).inventory}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let offline_run_id = body["run_id"].as_str().unwrap();
        let (status, offline_report) = response(
            offline_application,
            Request::get(format!("/v1/runs/{offline_run_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(offline_report["findings"].as_object().unwrap().len(), 2);

        let failing_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
            .mount(&failing_server)
            .await;
        let (status, body) = response(
            app(Config {
                osv_url: failing_server.uri(),
                ..Config::default()
            }),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inventory":rich_report("template", &[]).inventory}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"]["code"], "vulnerability_service_failed");

        let state = ApiState::new(
            Store::open_memory().unwrap(),
            Config {
                osv_url: server.uri(),
                max_concurrency: 1,
                ..Config::default()
            },
        )
        .unwrap();
        let permit = state.scan_slots.clone().acquire_owned().await.unwrap();
        let (status, body) = response(
            router(state),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inventory":rich_report("template", &[]).inventory}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        drop(permit);
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "scan_capacity_exceeded");
    }

    #[tokio::test]
    async fn run_detail_diff_and_missing_paths_return_stable_contracts() {
        let shared = finding(
            "finding:shared",
            FindingKind::Sast,
            Severity::Medium,
            "rule:shared",
        );
        let old = finding(
            "finding:old",
            FindingKind::License,
            Severity::Low,
            "rule:old",
        );
        let new = finding(
            "finding:new",
            FindingKind::Vulnerability,
            Severity::Critical,
            "rule:new",
        );
        let baseline = rich_report("run:baseline", &[shared.clone(), old]);
        let current = rich_report("run:current", &[shared, new]);
        let application = seeded_app(Config::default(), &[baseline, current]);

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/runs?limit=1&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/runs/run:current")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["run"]["id"], "run:current");

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/runs/run:current/diff/run:baseline")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["introduced"], json!(["finding:new"]));
        assert_eq!(body["resolved"], json!(["finding:old"]));
        assert_eq!(body["unchanged"], json!(["finding:shared"]));

        for uri in [
            "/v1/runs/run:missing",
            "/v1/runs/run:current/diff/run:missing",
        ] {
            let (status, body) = response(
                application.clone(),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body["error"]["code"], "run_not_found");
        }
    }

    #[tokio::test]
    async fn findings_and_inventory_routes_apply_filters_and_validate_boundaries() {
        let target = finding(
            "finding:target",
            FindingKind::Vulnerability,
            Severity::High,
            "rule:target",
        );
        let other = finding(
            "finding:other",
            FindingKind::License,
            Severity::Low,
            "rule:other",
        );
        let application = seeded_app(
            Config::default(),
            &[rich_report("run:filters", &[target, other])],
        );

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/runs/run:filters/findings?kind=vulnerability&severity=HIGH&rule_id=rule:target")
                .body(Body::empty()).unwrap(),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);
        assert_eq!(body["findings"][0]["id"], "finding:target");

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/findings?kind=license&severity=low&rule_id=rule:other&limit=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);
        assert_eq!(body["findings"][0]["finding"]["id"], "finding:other");

        let (status, body) = response(
            application.clone(),
            Request::get("/v1/runs/run:filters/inventory")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["components"].as_object().unwrap().len(), 2);

        let runtime_id = crate::model::stable_component_id("pkg:cargo/runtime-lib@1.0.0").unwrap();
        let (status, body) = response(
            application.clone(),
            Request::get(format!(
                "/v1/inventory?asset_id=asset:test&component_id={}&name=runtime-lib&purl=pkg:cargo/runtime-lib@1.0.0&scope=runtime",
                runtime_id.as_str()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);
        assert_eq!(body["components"][0]["component"]["name"], "runtime-lib");

        for uri in [
            "/v1/findings?kind=unknown-kind",
            "/v1/findings?severity=urgent",
            "/v1/findings?rule_id=",
            "/v1/inventory?name=",
            "/v1/inventory?offset=9223372036854775808",
        ] {
            let (status, body) = response(
                application.clone(),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert!(matches!(
                body["error"]["code"].as_str(),
                Some("invalid_filter" | "invalid_pagination")
            ));
        }
    }

    #[tokio::test]
    async fn policy_evaluation_rejects_parse_errors_invalid_timestamps_and_missing_findings() {
        let malformed = response(
            app(Config::default()),
            Request::post("/v1/policies/validate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"policy":{"version":"wrong"}}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(malformed.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(malformed.1["error"]["code"], "invalid_json");

        let valid_policy = json!({
            "version": 1, "default_outcome": "allow", "rules": [], "exceptions": []
        });
        let evaluation = json!({
            "policy": valid_policy.clone(),
            "report": report("run:evaluate"),
            "evaluated_at": "not-a-timestamp"
        });
        let (status, body) = response(
            app(Config::default()),
            Request::post("/v1/policies/evaluate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(evaluation.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_timestamp");

        let mut invalid_report = report("run:evaluate");
        invalid_report.policy_decisions.insert(PolicyDecision {
            policy_id: PolicyId::new("policy:deny").unwrap(),
            finding_id: Some(FindingId::new("finding:missing").unwrap()),
            outcome: PolicyOutcome::Deny,
            reason: "missing finding".to_owned(),
            exception_id: None,
        });
        let (status, body) = response(
            app(Config::default()),
            Request::post("/v1/policies/evaluate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "policy": valid_policy.clone(),
                        "report": invalid_report,
                        "evaluated_at": "2026-01-01T00:00:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], "invalid_scan_report");

        let (status, body) = response(
            app(Config::default()),
            Request::post("/v1/policies/evaluate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "policy": valid_policy,
                        "report": report("run:evaluate"),
                        "evaluated_at": "2026-01-01T00:00:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["summary"], json!({"allowed":0,"warned":0,"denied":0}));
    }

    #[tokio::test]
    async fn serve_honors_graceful_shutdown_and_auth_protects_health_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(
            listener,
            ApiState::new(Store::open_memory().unwrap(), token_config("top-secret")).unwrap(),
            async move {
                let _ = shutdown_rx.await;
            },
        ));
        // The caller-bound listener is already listening, so the connection
        // queues in the accept backlog and readiness needs no sleeping.
        let mut connection = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET /health HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer top-secret\r\nConnection: close\r\n\r\n"
        );
        connection.write_all(request.as_bytes()).await.unwrap();
        let mut served = String::new();
        connection.read_to_string(&mut served).await.unwrap();
        assert!(
            served.starts_with("HTTP/1.1 200"),
            "the authorized health request must be served before draining"
        );
        assert!(served.contains("\"status\":\"ok\""));
        // The served response finished, so graceful shutdown drains and the
        // server task returns Ok instead of being aborted mid-request.
        drop(connection);
        shutdown_tx.send(()).unwrap();
        assert!(task.await.unwrap().is_ok());

        let application = app(token_config("top-secret"));
        let unauthorized = application
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let authorized = application
            .oneshot(
                Request::get("/health")
                    .header(AUTHORIZATION, "Bearer top-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn requires_configured_bearer_token_and_never_echoes_it() {
        let response = app(token_config("top-secret"))
            .oneshot(Request::get("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(response).await;
        assert_eq!(body["error"]["code"], "unauthorized");
        assert!(!body.to_string().contains("top-secret"));

        let response = app(token_config("top-secret"))
            .oneshot(
                Request::get("/v1/runs")
                    .header(AUTHORIZATION, "Bearer top-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app(token_config("top-secret"))
            .oneshot(
                Request::get("/v1/runs")
                    .header(AUTHORIZATION, "bearer top-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app(token_config("top-secret"))
            .oneshot(
                Request::get("/v1/runs")
                    .header(AUTHORIZATION, "Bearer top-secret extra")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[axum::http::header::WWW_AUTHENTICATE],
            "Bearer"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_request_body() {
        let config = Config {
            max_request_bytes: 16,
            ..Config::default()
        };
        let response = app(config)
            .oneshot(
                Request::post("/v1/scans")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("x".repeat(17)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn returns_versioned_errors_and_request_ids() {
        let response = app(Config::default())
            .oneshot(
                Request::get("/missing")
                    .header(&REQUEST_ID_HEADER, "client-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[&REQUEST_ID_HEADER], "client-123");
        let body = json_body(response).await;
        assert_eq!(body["version"], API_VERSION);
        assert_eq!(body["error"]["code"], "route_not_found");
    }

    #[tokio::test]
    async fn validates_pagination_and_unknown_query_fields() {
        let response = app(Config::default())
            .oneshot(
                Request::get("/v1/runs?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "invalid_pagination"
        );

        let response = app(Config::default())
            .oneshot(
                Request::get("/v1/runs?unexpected=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn report_and_run_responses_redact_sensitive_metadata() {
        let mut sensitive = report("run:sensitive");
        sensitive.run.metadata = BTreeMap::from([
            ("api_token".to_owned(), json!("run-secret")),
            ("branch".to_owned(), json!("main")),
        ]);
        sensitive.inventory.asset.metadata = BTreeMap::from([(
            "deployment".to_owned(),
            json!({"clientSecret":"asset-secret","region":"eu"}),
        )]);
        let mut sensitive_finding = finding(
            "finding:sensitive",
            FindingKind::Sast,
            Severity::High,
            "rule:sensitive",
        );
        sensitive_finding.evidence.insert(Evidence {
            description: "metadata redaction fixture".to_owned(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::from([
                ("access_key".to_owned(), "finding-secret".to_owned()),
                ("safe".to_owned(), "visible".to_owned()),
            ]),
            redacted: true,
        });
        sensitive
            .findings
            .insert(sensitive_finding.id.clone(), sensitive_finding);
        let application = seeded_app(Config::default(), &[sensitive]);
        for path in [
            "/v1/runs",
            "/v1/runs/run:sensitive",
            "/v1/reports/run:sensitive",
            "/v1/runs/run:sensitive/findings",
            "/v1/runs/run:sensitive/inventory",
            "/v1/findings",
        ] {
            let response = application
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(!body.contains("finding-secret"), "{path}: {body}");
            assert!(!body.contains("run-secret"), "{path}: {body}");
            assert!(!body.contains("asset-secret"), "{path}: {body}");
            assert!(body.contains("[REDACTED]"), "{path}: {body}");
            assert!(
                body.contains("visible") || path.ends_with("inventory"),
                "{path}: {body}"
            );
            if path == "/v1/runs"
                || path == "/v1/runs/run:sensitive"
                || path == "/v1/reports/run:sensitive"
            {
                assert!(body.contains("main"), "{path}: {body}");
            }
            if !path.ends_with("findings") && path != "/v1/findings" {
                assert!(body.contains("eu"), "{path}: {body}");
            }
        }

        let response = application
            .oneshot(
                Request::get("/v1/reports/run:sensitive")
                    .header(ACCEPT, "application/yaml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("run-secret"));
        assert!(!body.contains("asset-secret"));
        assert!(body.contains("'[REDACTED]'"));
    }

    #[test]
    fn sanitize_api_report_borrows_clean_reports() {
        let clean = report("run:clean");
        assert!(matches!(
            sanitize_api_report(&clean).unwrap(),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn sanitize_api_report_redacts_sensitive_carriers_into_owned_cow() {
        let mut sensitive = report("run:sensitive");
        sensitive.run.metadata = BTreeMap::from([
            ("api_token".to_owned(), json!("run-secret")),
            ("branch".to_owned(), json!("main")),
        ]);
        sensitive.inventory.asset.metadata = BTreeMap::from([(
            "deployment".to_owned(),
            json!({"clientSecret":"asset-secret","region":"eu"}),
        )]);
        let sanitized = sanitize_api_report(&sensitive).unwrap();
        assert!(matches!(sanitized, Cow::Owned(_)));
        let body = serde_json::to_string(&*sanitized).unwrap();
        assert!(body.contains("[REDACTED]"));
        assert!(!body.contains("run-secret"));
        assert!(!body.contains("asset-secret"));
        assert!(body.contains("main"));
    }

    async fn delayed_blocking_write(State(commits): State<Arc<AtomicUsize>>) -> StatusCode {
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(40));
            commits.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();
        StatusCode::CREATED
    }

    async fn delayed_read() -> StatusCode {
        tokio::time::sleep(Duration::from_millis(40)).await;
        StatusCode::OK
    }

    async fn short_timeout(request: Request<Body>, next: Next) -> Response {
        timeout_middleware_with_duration(request, next, Duration::from_millis(5)).await
    }

    #[tokio::test]
    async fn timed_write_reports_its_authoritative_outcome_while_reads_still_timeout() {
        let commits = Arc::new(AtomicUsize::new(0));
        let application = Router::new()
            .route("/v1/scans", post(delayed_blocking_write))
            .route("/slow-read", get(delayed_read))
            .layer(middleware::from_fn(short_timeout))
            .with_state(Arc::clone(&commits));

        let response = application
            .clone()
            .oneshot(Request::post("/v1/scans").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(commits.load(Ordering::SeqCst), 1);

        let response = application
            .oneshot(Request::get("/slow-read").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "request_timeout"
        );
    }

    #[tokio::test]
    async fn report_round_trip_preserves_global_locations_with_content_negotiation() {
        let application = seeded_app(Config::default(), &[report("run:test")]);

        let response = application
            .clone()
            .oneshot(
                Request::get("/v1/reports/run:test")
                    .header(ACCEPT, "application/yaml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/yaml");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let decoded: ScanReport = serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(decoded.run.id.as_str(), "run:test");
        assert_eq!(
            decoded.inventory.locations.iter().next().unwrap().path,
            "sample.py"
        );

        let response = application
            .oneshot(
                Request::get("/v1/reports/run:test")
                    .header(ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn accept_negotiation_honors_quality_specificity_and_multiple_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json;q=0, application/yaml;q=0.8"),
        );
        assert_eq!(preferred_report_media(&headers), Some(ReportMedia::Yaml));

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json;q=0, */*;q=0.5"),
        );
        assert_eq!(preferred_report_media(&headers), Some(ReportMedia::Yaml));

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json;q=0, application/yaml;q=0"),
        );
        assert_eq!(preferred_report_media(&headers), None);

        headers.clear();
        headers.append(ACCEPT, HeaderValue::from_static("application/json;q=0.2"));
        headers.append(ACCEPT, HeaderValue::from_static("text/yaml;q=0.7"));
        assert_eq!(preferred_report_media(&headers), Some(ReportMedia::Yaml));

        headers.clear();
        assert_eq!(preferred_report_media(&headers), Some(ReportMedia::Json));
    }

    #[tokio::test]
    async fn policy_and_exception_validation_are_deterministic() {
        let policy = json!({
            "policy": {
                "version": 1,
                "default_outcome": "allow",
                "rules": [],
                "exceptions": []
            }
        });
        let response = app(Config::default())
            .oneshot(
                Request::post("/v1/policies/validate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(policy.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({"version":"v1","valid":true})
        );

        let invalid = json!({
            "exception": {
                "id":"exception-1", "owner":"security", "reason":"reviewed", "ticket":"SEC-1",
                "expires_at":"2027-01-01T00:00:00Z", "selectors": {}
            }
        });
        let response = app(Config::default())
            .oneshot(
                Request::post("/v1/exceptions/validate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(invalid.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "invalid_exception"
        );
    }

    #[tokio::test]
    async fn scan_failure_envelope_never_leaks_upstream_details() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
            .mount(&server)
            .await;
        let (status, body) = response(
            app(Config {
                osv_url: server.uri(),
                ..Config::default()
            }),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"inventory": rich_report("template", &[]).inventory}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"]["code"], "vulnerability_service_failed");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(
            !message.contains(&server.uri()),
            "leaked endpoint: {message}"
        );
        assert!(
            !message.contains("temporarily unavailable"),
            "leaked upstream body: {message}"
        );
    }

    #[tokio::test]
    async fn scan_policy_enforces_risk_selectors_on_scored_findings() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "OSV-1"}]}, {"vulns": []}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/OSV-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "OSV-1",
                "summary": "high severity advisory",
                "severity": [{"type": "CVSS_V3", "score": 7.2}]
            })))
            .mount(&server)
            .await;
        let policy = json!({
            "version": 1,
            "default_outcome": "allow",
            "rules": [{
                "id": "deny-high-risk",
                "outcome": "deny",
                "reason": "scored risk findings are denied",
                "selectors": {"risk": {"minimum": 1}}
            }],
            "exceptions": []
        });
        let application = app(Config {
            osv_url: server.uri(),
            ..Config::default()
        });
        let (status, body) = response(
            application.clone(),
            Request::post("/v1/scans")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "inventory": rich_report("template", &[]).inventory,
                        "policy": policy
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let run_id = body["run_id"].as_str().unwrap();
        let (status, saved) = response(
            application,
            Request::get(format!("/v1/runs/{run_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let findings = saved["findings"].as_object().unwrap();
        assert!(!findings.is_empty(), "the OSV stub must produce a finding");
        for (id, finding) in findings {
            assert!(
                finding["risk"] != Value::Null,
                "finding {id} must be scored before policy evaluation"
            );
        }
        assert_eq!(saved["policy_summary"]["allowed"], 0);
        assert_eq!(saved["policy_summary"]["warned"], 0);
        assert_eq!(
            saved["policy_summary"]["denied"].as_u64(),
            Some(findings.len() as u64)
        );
    }

    // Virtual time: the paused clock auto-advances past the fetch bound as
    // soon as the stalled upstream leaves the task idle, so no wall-clock
    // elapsed assertion is needed.
    #[tokio::test(start_paused = true)]
    async fn scan_fetch_is_bounded_so_stalled_vulnerability_service_cannot_pin_slots() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results": [{"vulns": []}, {"vulns": []}]}))
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        let state = ApiState::new(
            Store::open_memory().unwrap(),
            Config {
                osv_url: server.uri(),
                max_concurrency: 1,
                ..Config::default()
            },
        )
        .unwrap();
        let slots = Arc::clone(&state.scan_slots);
        let payload = Ok(Json(ScanRequest {
            inventory: rich_report("template", &[]).inventory,
            policy: None,
            metadata: BTreeMap::new(),
        }));
        let error = scan_with_deadline(state, payload, Duration::from_millis(100))
            .await
            .expect_err("stalled vulnerability service must exceed the fetch bound");
        assert_eq!(error.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(error.code, "vulnerability_service_timeout");
        assert_eq!(
            slots.available_permits(),
            1,
            "a timed-out scan must release its slot"
        );
    }
}
