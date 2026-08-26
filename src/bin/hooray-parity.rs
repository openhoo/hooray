//! `hooray-parity`: JFrog Xray parity record–replay harness CLI.
//!
//! Subcommands:
//!
//! * `scan-case` — pinned deterministic in-process hooray scan, printed as
//!   canonical JSON.
//! * `normalize-xray` — convert captured Xray artifacts to canonical JSON
//!   (debug aid).
//! * `record` — persist both sides of one case into a recording file.
//! * `check` — enforce corpus tier-1 expectations, an always-on drift guard,
//!   and operator-chosen scorecard thresholds across all recordings.
//!
//! Hooray input failures are fail-closed: they abort the scan and surface as
//! operational errors (exit code 2), never as silent parse errors.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

use hooray::config::Config;
use hooray::engine::{Engine, ScanRequest};
use hooray::input::ScanInput;
use hooray::model::{RunId, ScanReport};
use hooray::parity::compare::{self, CaseCheck};
use hooray::parity::corpus::{self, CorpusCase, CorpusManifest};
use hooray::parity::normalize;
use hooray::parity::recording::{Enforcement, Provenance, Recording};
use hooray::parity::xray::{self, XrayArtifacts};
use hooray::store::Store;

/// Pinned run id making repeated scans byte-comparable.
const PINNED_RUN_ID: &str = "run:00000000-0000-4000-8000-000000000000";
/// Pinned `as_of` timestamp making repeated scans byte-comparable.
const PINNED_AS_OF: &str = "2026-01-01T00:00:00Z";
/// Repo-relative default policy location (owned by the corpus fixtures).
const DEFAULT_POLICY: &str = "tests/fixtures/parity/policy/minimal-policy.yaml";
/// Minimal allow-all policy materialized when no policy fixture exists yet.
const FALLBACK_POLICY_YAML: &str =
    "version: 1\ndefault_outcome: allow\nrules: []\nexceptions: []\n";

#[derive(Debug, Parser)]
#[command(
    name = "hooray-parity",
    version,
    about = "JFrog Xray parity record-replay harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a pinned in-process hooray scan and print canonical JSON.
    ScanCase {
        /// Case directory (or SBOM/archive file path).
        #[arg(long)]
        case: PathBuf,
        /// Disable live OSV queries; vulnerabilities will be empty.
        #[arg(long)]
        offline: bool,
        /// Output format (only `json` is supported).
        #[arg(long, default_value = "json")]
        format: String,
        /// Policy file override; defaults to the corpus minimal policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Convert Xray artifacts into canonical JSON (debug aid).
    NormalizeXray {
        /// Case identifier stamped into the canonical report.
        #[arg(long)]
        case: String,
        /// Path to the `jf audit --format json` output.
        #[arg(long)]
        xray_json: Option<PathBuf>,
        /// Path to the `jf audit --format cyclonedx` output.
        #[arg(long)]
        xray_sbom: Option<PathBuf>,
        /// Xray CLI version to record in the generator identity.
        #[arg(long)]
        xray_cli_version: Option<String>,
        /// Vulnerability database snapshot date (provenance only).
        #[arg(long)]
        xray_db_date: Option<String>,
    },
    /// Record both scanner sides for one case into a replay file.
    Record {
        /// Case directory (or SBOM/archive file path).
        #[arg(long)]
        case: PathBuf,
        /// Output recording file path.
        #[arg(long)]
        out: PathBuf,
        /// Path to the `jf audit --format json` output.
        #[arg(long)]
        xray_json: Option<PathBuf>,
        /// Path to the `jf audit --format cyclonedx` output.
        #[arg(long)]
        xray_sbom: Option<PathBuf>,
        /// Disable live OSV queries when scanning the hooray side.
        #[arg(long)]
        offline: bool,
        /// Policy file override; defaults to the corpus minimal policy.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Xray CLI version.
        #[arg(long)]
        xray_cli_version: Option<String>,
        /// Xray vulnerability database snapshot date (`YYYY-MM-DD`).
        #[arg(long)]
        xray_db_date: Option<String>,
        /// Exact `jf audit` invocations used (repeatable).
        #[arg(long = "commands")]
        commands: Vec<String>,
        /// Free-text environment description.
        #[arg(long, default_value = "operator workstation")]
        environment: String,
        /// Minimum purl recall gate.
        #[arg(long)]
        enforcement_min_purl_recall: Option<f64>,
        /// Minimum purl precision gate.
        #[arg(long)]
        enforcement_min_purl_precision: Option<f64>,
        /// Minimum CVE Jaccard gate.
        #[arg(long)]
        enforcement_min_cve_jaccard: Option<f64>,
    },
    /// Check all recordings against fresh scans, drift guards, and gates.
    Check {
        /// Corpus directory containing `manifest.json` and case inputs.
        #[arg(long)]
        corpus: PathBuf,
        /// Directory containing `*.recording.json` files.
        #[arg(long)]
        recordings: PathBuf,
        /// Output format: `table` or `json`.
        #[arg(long, default_value = "table")]
        format: String,
        /// Global minimum purl recall; combined strictly with recording gates.
        #[arg(long)]
        min_purl_recall: Option<f64>,
        /// Global minimum purl precision.
        #[arg(long)]
        min_purl_precision: Option<f64>,
        /// Global minimum CVE Jaccard.
        #[arg(long)]
        min_cve_jaccard: Option<f64>,
    },
}

fn resolve_policy(explicit: Option<&PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_file() {
            bail!("policy file {} does not exist", path.display());
        }
        return Ok(path.clone());
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_POLICY);
    if candidate.is_file() {
        return Ok(candidate);
    }
    // No corpus policy fixture yet (it may land concurrently): materialize a
    // deterministic minimal allow-all policy instead of failing.
    let dir = std::env::temp_dir().join("hooray-parity");
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join("minimal-policy.yaml");
    std::fs::write(&path, FALLBACK_POLICY_YAML)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn pinned_request(input: ScanInput, policy_path: PathBuf) -> anyhow::Result<ScanRequest> {
    let mut request = ScanRequest::new(input, policy_path);
    request.run_id = Some(RunId::new(PINNED_RUN_ID).context("pinned run id must be valid")?);
    request.as_of = Some(
        chrono::DateTime::parse_from_rfc3339(PINNED_AS_OF)
            .context("pinned as-of timestamp must be valid")?
            .with_timezone(&chrono::Utc),
    );
    Ok(request)
}

async fn run_pinned_scan(
    case_path: &Path,
    offline: bool,
    policy: Option<&PathBuf>,
) -> anyhow::Result<ScanReport> {
    let config = Config {
        offline,
        ..Config::default()
    };
    // Hooray's fail-closed symlink checks require canonical absolute paths.
    let resolved = std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_owned());
    let case_path: &Path = resolved.as_path();
    let input = match ScanInput::detect(case_path, &config) {
        Ok(input) => input,
        Err(error) => {
            // Wrapped SBOM/zip cases are directories containing the artifact.
            let Some(artifact) = corpus::find_artifact(None, case_path) else {
                return Err(anyhow::anyhow!(error)).with_context(|| {
                    format!("failed to classify case input {}", case_path.display())
                });
            };
            ScanInput::detect(&artifact, &config)
                .with_context(|| format!("failed to classify case input {}", case_path.display()))?
        }
    };
    pinned_scan_input(input, &config, policy).await
}

/// Offline configuration shared by all corpus-driven checks.
fn offline_config() -> Config {
    Config {
        offline: true,
        ..Config::default()
    }
}

/// Runs one already-classified input through the pinned in-memory scan
/// pipeline (memory store, pinned run id and `as_of`, resolved policy).
async fn pinned_scan_input(
    input: ScanInput,
    config: &Config,
    policy: Option<&PathBuf>,
) -> anyhow::Result<ScanReport> {
    let mut store = Store::open_memory().context("failed to open in-memory store")?;
    let mut engine = Engine::new(config, &mut store, None);
    let request = pinned_request(input, resolve_policy(policy)?)?;
    engine.scan(request).await.context("hooray scan failed")
}

fn read_optional(path: &Option<PathBuf>, label: &str) -> anyhow::Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    Ok(Some(std::fs::read_to_string(path).with_context(|| {
        format!("failed to read {label} {}", path.display())
    })?))
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn case_label(case: &Path) -> String {
    // Recordings key on this label, so it must be stable regardless of how
    // the operator spelled the path ('.', './dir/', absolute, relative).
    let resolved = std::fs::canonicalize(case).unwrap_or_else(|_| case.to_owned());
    match resolved.file_name().and_then(|name| name.to_str()) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => resolved.display().to_string(),
    }
}

async fn command_scan_case(command: &Command) -> anyhow::Result<i32> {
    let Command::ScanCase {
        case,
        offline,
        format,
        policy,
    } = command
    else {
        bail!("scan-case invoked with wrong subcommand");
    };
    if format != "json" {
        bail!("unsupported format '{format}'; only 'json' is supported");
    }
    let report = run_pinned_scan(case, *offline, policy.as_ref()).await?;
    let scan_mode = if *offline { "offline" } else { "osv-live" };
    let canonical = normalize::normalize_hooray(&report, &case_label(case), scan_mode)?;
    print_json(&canonical)?;
    Ok(0)
}

async fn command_normalize_xray(command: &Command) -> anyhow::Result<i32> {
    let Command::NormalizeXray {
        case,
        xray_json,
        xray_sbom,
        xray_cli_version,
        ..
    } = command
    else {
        bail!("normalize-xray invoked with wrong subcommand");
    };
    if xray_json.is_none() && xray_sbom.is_none() {
        bail!("at least one of --xray-json or --xray-sbom is required");
    }
    let audit = read_optional(xray_json, "--xray-json")?;
    let sbom = read_optional(xray_sbom, "--xray-sbom")?;
    let artifacts = XrayArtifacts {
        audit_json: audit.as_deref(),
        sbom_json: sbom.as_deref(),
    };
    let (report, summary) =
        xray::build_xray_canonical(case, xray_cli_version.as_deref(), &artifacts)?;
    eprintln!(
        "xray parse summary: {} components, {} vulnerabilities, {} skipped",
        summary.returned_components, summary.returned_vulnerabilities, summary.skipped_entries
    );
    print_json(&report)?;
    Ok(0)
}

async fn command_record(command: &Command) -> anyhow::Result<i32> {
    let Command::Record {
        case,
        out,
        xray_json,
        xray_sbom,
        offline,
        policy,
        xray_cli_version,
        xray_db_date,
        commands,
        environment,
        enforcement_min_purl_recall,
        enforcement_min_purl_precision,
        enforcement_min_cve_jaccard,
    } = command
    else {
        bail!("record invoked with wrong subcommand");
    };
    if xray_json.is_none() && xray_sbom.is_none() {
        bail!("at least one of --xray-json or --xray-sbom is required");
    }
    let case_id = case_label(case);
    let scan_mode = if *offline { "offline" } else { "osv-live" };
    let report = run_pinned_scan(case, *offline, policy.as_ref()).await?;
    let hooray = normalize::normalize_hooray(&report, &case_id, scan_mode)?;

    let audit = read_optional(xray_json, "--xray-json")?;
    let sbom = read_optional(xray_sbom, "--xray-sbom")?;
    let artifacts = XrayArtifacts {
        audit_json: audit.as_deref(),
        sbom_json: sbom.as_deref(),
    };
    let (xray_side, summary) =
        xray::build_xray_canonical(&case_id, xray_cli_version.as_deref(), &artifacts)?;
    if summary.skipped_entries > 0 {
        eprintln!(
            "note: skipped {} xray entries: {}",
            summary.skipped_entries,
            summary.skip_reasons.join("; ")
        );
    }

    let recording = Recording {
        schema_version: hooray::parity::recording::RECORDING_SCHEMA_VERSION,
        case_id,
        recorded_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        provenance: Provenance {
            hooray_version: env!("CARGO_PKG_VERSION").to_owned(),
            xray_cli_version: xray_cli_version.clone(),
            xray_version: None,
            xray_db_date: xray_db_date.clone(),
            commands: commands.clone(),
            environment: environment.clone(),
        },
        hooray,
        xray: xray_side,
        enforcement: Some(Enforcement {
            min_purl_recall: *enforcement_min_purl_recall,
            min_purl_precision: *enforcement_min_purl_precision,
            min_cve_jaccard: *enforcement_min_cve_jaccard,
        }),
    };
    recording
        .save(out)
        .with_context(|| format!("failed to save recording {}", out.display()))?;
    println!("recorded {} -> {}", recording.case_id, out.display());
    Ok(0)
}

async fn run_case_checks(case: &CorpusCase, case_path: &Path) -> anyhow::Result<Vec<String>> {
    let input = corpus::scan_input_for_kind(&case.kind, case_path, &offline_config())?;
    let report = pinned_scan_input(input, &offline_config(), None).await?;
    let canonical = normalize::normalize_hooray(&report, &case.case_id, "offline")?;
    Ok(corpus::corpus_case_notes(case, &canonical))
}

async fn command_check(command: &Command) -> anyhow::Result<i32> {
    let Command::Check {
        corpus,
        recordings,
        format,
        min_purl_recall,
        min_purl_precision,
        min_cve_jaccard,
    } = command
    else {
        bail!("check invoked with wrong subcommand");
    };
    if !corpus.is_dir() {
        bail!("corpus directory {} does not exist", corpus.display());
    }
    if !recordings.is_dir() {
        bail!(
            "recordings directory {} does not exist",
            recordings.display()
        );
    }
    if format != "table" && format != "json" {
        bail!("unsupported format '{format}'; expected 'table' or 'json'");
    }

    let mut results: Vec<CaseCheck> = Vec::new();

    // Corpus manifest: drives tier-1 expectations and gives the tier-2
    // drift guard the case kind so every consumer classifies identically.
    let manifest_path = corpus.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        let text = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        Some(
            serde_json::from_str::<CorpusManifest>(&text)
                .with_context(|| format!("invalid corpus manifest {}", manifest_path.display()))?,
        )
    } else {
        eprintln!(
            "tier-1 skipped: corpus manifest not found at {}",
            manifest_path.display()
        );
        None
    };

    // Tier 1: corpus expectations against fresh normalization.
    if let Some(manifest) = &manifest {
        if manifest.cases.is_empty() {
            eprintln!("tier-1 skipped: corpus manifest contains no cases");
        }
        for case in &manifest.cases {
            let mut notes = Vec::new();
            let case_path = corpus.join(&case.case_id);
            if !case_path.exists() {
                notes.push(format!(
                    "manifest references missing case path {}",
                    case_path.display()
                ));
                results.push(CaseCheck {
                    case_id: case.case_id.clone(),
                    status: "violation".to_owned(),
                    notes,
                    scorecard: None,
                });
                continue;
            }
            match run_case_checks(case, &case_path).await {
                Ok(case_notes) => {
                    let status = if case_notes.is_empty() {
                        "ok"
                    } else {
                        "violation"
                    };
                    notes.extend(case_notes);
                    results.push(CaseCheck {
                        case_id: case.case_id.clone(),
                        status: status.to_owned(),
                        notes,
                        scorecard: None,
                    });
                }
                Err(error) => {
                    notes.push(format!("tier-1 error: {error:#}"));
                    results.push(CaseCheck {
                        case_id: case.case_id.clone(),
                        status: "violation".to_owned(),
                        notes,
                        scorecard: None,
                    });
                }
            }
        }
    }

    // Tier 2: recordings — drift guard always, thresholds when configured.
    let mut recording_paths = Vec::new();
    for entry in std::fs::read_dir(recordings)
        .with_context(|| format!("failed to list {}", recordings.display()))?
    {
        let entry = entry.with_context(|| "failed to read recordings entry".to_owned())?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".recording.json"))
        {
            recording_paths.push(path);
        }
    }
    recording_paths.sort();
    if recording_paths.is_empty() {
        eprintln!(
            "tier-2 skipped: no *.recording.json files under {}",
            recordings.display()
        );
    }

    for path in recording_paths {
        let recording = match Recording::load(&path) {
            Ok(recording) => recording,
            Err(error) => {
                results.push(CaseCheck {
                    // Key on the file name, never the full path: the row
                    // must be identical no matter how --recordings was
                    // spelled (absolute vs relative).
                    case_id: path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_owned)
                        .unwrap_or_else(|| path.display().to_string()),
                    status: "violation".to_owned(),
                    notes: vec![format!("recording failed to load: {error}")],
                    scorecard: None,
                });
                continue;
            }
        };
        let mut drift_notes = Vec::new();

        // Drift guard: ALWAYS runs when a recording exists. Offline scans
        // produce no vulnerabilities, so those are exempt by construction.
        let case_path = corpus.join(&recording.case_id);
        if !case_path.exists() {
            drift_notes.push(format!(
                "cannot re-scan: case path {} is missing",
                case_path.display()
            ));
        } else if let Some(case) = manifest.as_ref().and_then(|manifest| {
            manifest
                .cases
                .iter()
                .find(|case| case.case_id == recording.case_id)
        }) {
            // Classify through the shared kind-aware resolver so the drift
            // re-scan sees exactly what tier-1 and `record` saw.
            match corpus::scan_input_for_kind(&case.kind, &case_path, &offline_config()) {
                Ok(input) => match pinned_scan_input(input, &offline_config(), None).await {
                    Ok(report) => {
                        let fresh =
                            normalize::normalize_hooray(&report, &recording.case_id, "offline")?;
                        drift_notes.extend(compare::drift_violations(&fresh, &recording.hooray));
                    }
                    Err(error) => drift_notes.push(format!("drift re-scan failed: {error:#}")),
                },
                Err(error) => drift_notes.push(format!("drift re-scan failed: {error:#}")),
            }
        } else {
            drift_notes.push(format!(
                "cannot re-scan: corpus manifest has no case '{}'",
                recording.case_id
            ));
        }

        // Scorecard + thresholds (strictest of recording gate vs CLI flag).
        let card = compare::scorecard(&recording.hooray, &recording.xray);
        let mut threshold_notes = Vec::new();
        if let Some(enforcement) = &recording.enforcement {
            let checks = [
                (
                    compare::effective_threshold(enforcement.min_purl_recall, *min_purl_recall),
                    card.purl_recall,
                    "purl recall",
                ),
                (
                    compare::effective_threshold(
                        enforcement.min_purl_precision,
                        *min_purl_precision,
                    ),
                    card.purl_precision,
                    "purl precision",
                ),
                (
                    compare::effective_threshold(enforcement.min_cve_jaccard, *min_cve_jaccard),
                    card.cve_jaccard,
                    "cve jaccard",
                ),
            ];
            for (threshold, value, label) in checks {
                if compare::violates(threshold, value) {
                    threshold_notes.push(format!(
                        "{label} {:.3} below threshold {:.3}",
                        value,
                        threshold.unwrap_or_default()
                    ));
                }
            }
        }
        compare::apply_recording_check(
            &mut results,
            &recording.case_id.clone(),
            drift_notes,
            threshold_notes,
            card,
        );
    }

    let any_violation = results.iter().any(|r| r.status == "violation");
    if format == "json" {
        print_json(&results)?;
    } else {
        render_table(&results);
    }
    Ok(i32::from(any_violation))
}

fn render_table(results: &[CaseCheck]) {
    let headers = ["case", "status", "recall", "precision", "jaccard", "notes"];
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|result| {
            let score = result.scorecard.as_ref();
            vec![
                result.case_id.clone(),
                result.status.clone(),
                score
                    .map(|s| format!("{:.3}", s.purl_recall))
                    .unwrap_or_else(|| "-".into()),
                score
                    .map(|s| format!("{:.3}", s.purl_precision))
                    .unwrap_or_else(|| "-".into()),
                score
                    .map(|s| format!("{:.3}", s.cve_jaccard))
                    .unwrap_or_else(|| "-".into()),
                result.notes.join("; "),
            ]
        })
        .collect();
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .max()
                .unwrap_or(0)
                .max(header.chars().count())
        })
        .collect();
    let line = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, cell)| format!("{cell:<width$}", width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };
    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    println!("{}", line(&header_cells));
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in rows {
        println!("{}", line(&row));
    }
}

/// Exit codes: `0` success; `check` returns `i32::from(any_violation)` so
/// policy or drift violations exit `1`; all other subcommands exit `0`.
/// Operational failures — including fail-closed hooray input aborts — exit
/// `2` uniformly across scan-case, normalize-xray, record, and check.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::ScanCase { .. } => command_scan_case(&cli.command).await,
        Command::NormalizeXray { .. } => command_normalize_xray(&cli.command).await,
        Command::Record { .. } => command_record(&cli.command).await,
        Command::Check { .. } => command_check(&cli.command).await,
    };
    match outcome {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::from(2)
        }
    }
}
