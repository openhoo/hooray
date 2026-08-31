use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use hooray::{
    config::Config,
    engine::{Engine, ScanRequest, load_policy},
    input::ScanInput,
    integrations::{
        IntegrationGenerator, IntegrationLimits, SignedWebhook, validate_webhook_config,
    },
    model::{RunId, ScanReport},
    monitor::{
        AdvisoryCursor, AdvisoryRefresh, AlertEvent, Evaluation, MonitorConfig, MonitorError,
        MonitorFuture, MonitorRunner, MonitorService, Notifier, SystemClock,
    },
    report::{self, ReportFormat},
    store::{MonitorTarget, Store},
    util::{sanitize_cell_text, sha256_hex},
};
use serde::Serialize;

const EXIT_SUCCESS: u8 = 0;
const EXIT_POLICY_DENIED: u8 = 1;
const EXIT_OPERATIONAL_ERROR: u8 = 2;
const MAX_STDIN_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "hooray",
    version,
    about = "Enterprise software security analysis and policy enforcement",
    propagate_version = true
)]
struct Cli {
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan(ScanArgs),
    Policy(PolicyArgs),
    Inventory(InventoryArgs),
    History(HistoryArgs),
    Report(ReportArgs),
    Serve(ServeArgs),
    Monitor(MonitorArgs),
    Integrations(IntegrationsArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[command(subcommand)]
    command: ScanCommand,
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    Project(ScanTargetArgs),
    Sbom(ScanTargetArgs),
    Artifact(ScanTargetArgs),
    Container(ScanTargetArgs),
    Auto(ScanTargetArgs),
}

#[derive(Debug, Args)]
struct ScanTargetArgs {
    #[arg(value_name = "INPUT")]
    input: PathBuf,
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    #[arg(long, value_name = "RUN_ID")]
    baseline: Option<RunId>,
    #[arg(long)]
    new_findings_only: bool,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Validate(PolicyValidateArgs),
    Evaluate(PolicyEvaluateArgs),
}

#[derive(Debug, Args)]
struct PolicyValidateArgs {
    #[arg(value_name = "FILE")]
    policy: PathBuf,
}

#[derive(Debug, Args)]
struct PolicyEvaluateArgs {
    #[arg(value_name = "FILE")]
    policy: PathBuf,
    #[arg(long, value_name = "RUN_ID")]
    run_id: RunId,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct InventoryArgs {
    #[arg(long, value_name = "RUN_ID")]
    run_id: Option<RunId>,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    #[command(subcommand)]
    command: HistoryCommand,
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    List(HistoryListArgs),
    Show(HistoryShowArgs),
    Diff(HistoryDiffArgs),
}

#[derive(Debug, Args)]
struct HistoryListArgs {
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct HistoryShowArgs {
    #[arg(value_name = "RUN_ID")]
    run_id: RunId,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct HistoryDiffArgs {
    #[arg(value_name = "PREVIOUS_RUN_ID")]
    previous: RunId,
    #[arg(value_name = "CURRENT_RUN_ID")]
    current: RunId,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(value_name = "RUN_ID")]
    run_id: RunId,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct ServeArgs {
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Args)]
struct MonitorArgs {
    #[arg(long)]
    once: bool,
    #[arg(long, value_name = "URL")]
    webhook_url: Option<String>,
    #[arg(long, value_name = "VAR")]
    webhook_secret_env: Option<String>,
    #[command(subcommand)]
    command: Option<MonitorCommand>,
}

#[derive(Debug, Subcommand)]
enum MonitorCommand {
    /// Manage the targets the monitor watches
    Targets(MonitorTargetsArgs),
}

#[derive(Debug, Args)]
struct MonitorTargetsArgs {
    #[command(subcommand)]
    command: MonitorTargetsCommand,
}

#[derive(Debug, Subcommand)]
enum MonitorTargetsCommand {
    /// Register a target so future monitor cycles watch it
    Add(MonitorTargetAddArgs),
    /// List registered targets
    List(MonitorTargetsListArgs),
    /// Remove a registered target and its queued events
    Remove(MonitorTargetRemoveArgs),
}

#[derive(Debug, Args)]
struct MonitorTargetAddArgs {
    #[arg(value_name = "TARGET_ID")]
    target_id: String,
    #[arg(long, value_name = "SOURCE")]
    source: String,
    // Mirrors MonitorTarget::validate so out-of-range intervals are rejected
    // at registration time instead of poisoning every later monitor cycle.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=hooray::monitor::MAX_BACKOFF_SECONDS as u64)
    )]
    interval_seconds: u64,
}

#[derive(Debug, Args)]
struct MonitorTargetsListArgs {
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct MonitorTargetRemoveArgs {
    #[arg(value_name = "TARGET_ID")]
    target_id: String,
}

#[derive(Debug, Args)]
struct IntegrationsArgs {
    #[command(subcommand)]
    command: IntegrationsCommand,
}

#[derive(Debug, Subcommand)]
enum IntegrationsCommand {
    Generate(IntegrationGenerateArgs),
}

#[derive(Debug, Args)]
struct IntegrationGenerateArgs {
    #[arg(value_enum)]
    kind: IntegrationKind,
    #[arg(long, default_value = "-", value_name = "FILE")]
    output: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IntegrationKind {
    PreCommit,
    GithubActions,
    GitlabCi,
    GitlabSecurity,
}

#[derive(Debug, Args)]
struct OutputArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
    #[arg(long, default_value = "-", value_name = "FILE")]
    output: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Json,
    Yaml,
    Table,
    Sarif,
    GitlabSarif,
    Junit,
    Html,
    CycloneDxVex,
    GitlabCyclonedx,
    Spdx,
    GitlabCodeQuality,
    JsonLines,
    GitlabArtifacts,
    Csv,
}

#[derive(Debug, thiserror::Error)]
#[error("'{0}' is a directory artifact bundle, not a single report format")]
struct ReportFormatConversionError(&'static str);

impl TryFrom<OutputFormat> for ReportFormat {
    type Error = ReportFormatConversionError;

    fn try_from(value: OutputFormat) -> Result<Self, Self::Error> {
        match value {
            OutputFormat::Json => Ok(Self::Json),
            OutputFormat::Yaml => Ok(Self::Yaml),
            OutputFormat::Table => Ok(Self::Table),
            OutputFormat::Sarif => Ok(Self::Sarif),
            OutputFormat::GitlabSarif => Ok(Self::GitLabSarif),
            OutputFormat::Junit => Ok(Self::Junit),
            OutputFormat::Html => Ok(Self::Html),
            OutputFormat::CycloneDxVex => Ok(Self::CycloneDxVex),
            OutputFormat::GitlabCyclonedx => Ok(Self::GitLabCycloneDx),
            OutputFormat::Spdx => Ok(Self::Spdx),
            OutputFormat::GitlabCodeQuality => Ok(Self::GitLabCodeQuality),
            OutputFormat::JsonLines => Ok(Self::JsonLines),
            OutputFormat::Csv => Ok(Self::Csv),
            OutputFormat::GitlabArtifacts => Err(ReportFormatConversionError("gitlab-artifacts")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandOutcome {
    Passed,
    PolicyDenied,
}

impl CommandOutcome {
    const fn exit_status(self) -> u8 {
        match self {
            Self::Passed => EXIT_SUCCESS,
            Self::PolicyDenied => EXIT_POLICY_DENIED,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(outcome) => ExitCode::from(outcome.exit_status()),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_OPERATIONAL_ERROR)
        }
    }
}

async fn run(cli: Cli) -> Result<CommandOutcome> {
    let config = Config::load(cli.config.as_deref()).context("failed to load configuration")?;
    match cli.command {
        Command::Scan(args) => run_scan(&config, args).await,
        Command::Policy(args) => run_policy(&config, args),
        Command::Inventory(args) => run_inventory(&config, args),
        Command::History(args) => run_history(&config, args),
        Command::Report(args) => run_report(&config, args),
        Command::Serve(args) => run_serve(config, args).await,
        Command::Monitor(args) => run_monitor(&config, args).await,
        Command::Integrations(args) => run_integrations(args),
    }
}

async fn run_scan(config: &Config, args: ScanArgs) -> Result<CommandOutcome> {
    let (kind, args) = match args.command {
        ScanCommand::Project(args) => (ScanKind::Project, args),
        ScanCommand::Sbom(args) => (ScanKind::Sbom, args),
        ScanCommand::Artifact(args) => (ScanKind::Artifact, args),
        ScanCommand::Container(args) => (ScanKind::Container, args),
        ScanCommand::Auto(args) => (ScanKind::Auto, args),
    };
    let stdin = if args.input == Path::new("-") {
        if !matches!(kind, ScanKind::Sbom | ScanKind::Auto) {
            bail!("standard input is supported only for scan sbom and scan auto");
        }
        Some(StdinFile::read(
            config.max_input_bytes.min(MAX_STDIN_BYTES),
        )?)
    } else {
        None
    };
    let path = stdin
        .as_ref()
        .map_or(args.input.as_path(), |file| file.path.as_path());
    let input = detect_input(kind, path, config)?;
    let policy_path = args.policy.unwrap_or_else(|| config.policy_path.clone());
    let mut store = open_store(config)?;
    let mut engine = Engine::new(config, &mut store, None);
    let mut request = ScanRequest::new(input, policy_path);
    request.baseline = args.baseline;
    request.new_findings_only = args.new_findings_only;
    let report = engine
        .scan(request)
        .await
        .context("scan orchestration failed")?;
    write_report_output(&report, &args.output)?;
    Ok(classify_report(&report))
}

#[derive(Clone, Copy)]
enum ScanKind {
    Project,
    Sbom,
    Artifact,
    Container,
    Auto,
}

fn detect_input(kind: ScanKind, path: &Path, config: &Config) -> Result<ScanInput> {
    let detected = ScanInput::detect(path, config)?;
    let valid = matches!(
        (&kind, &detected),
        (ScanKind::Auto, _)
            | (ScanKind::Project, ScanInput::ProjectDirectory(_))
            | (ScanKind::Sbom, ScanInput::CycloneDx(_))
            | (ScanKind::Artifact, ScanInput::Archive { .. })
            | (
                ScanKind::Container,
                ScanInput::OciImageLayout(_) | ScanInput::OciImageTar(_)
            )
    );
    if !valid {
        bail!("input type does not match the selected scan subcommand");
    }
    Ok(detected)
}

fn run_policy(config: &Config, args: PolicyArgs) -> Result<CommandOutcome> {
    match args.command {
        PolicyCommand::Validate(args) => {
            load_policy(&args.policy).context("policy is invalid")?;
            println!("policy is valid");
            Ok(CommandOutcome::Passed)
        }
        PolicyCommand::Evaluate(args) => {
            let policy = load_policy(&args.policy).context("policy is invalid")?;
            let store = open_store(config)?;
            let report = required_run(&store, &args.run_id)?;
            let evaluation = policy.evaluate(
                &report.findings,
                &report.inventory,
                Utc::now().fixed_offset(),
            )?;
            write_output(&evaluation.summary, &args.output)?;
            Ok(if evaluation.summary.denied == 0 {
                CommandOutcome::Passed
            } else {
                CommandOutcome::PolicyDenied
            })
        }
    }
}

fn run_inventory(config: &Config, args: InventoryArgs) -> Result<CommandOutcome> {
    let store = open_store(config)?;
    let report = match args.run_id {
        Some(id) => required_run(&store, &id)?,
        None => store.latest_run()?.context("no scan runs exist")?,
    };
    write_output(&report.inventory, &args.output)?;
    Ok(CommandOutcome::Passed)
}

fn run_history(config: &Config, args: HistoryArgs) -> Result<CommandOutcome> {
    let store = open_store(config)?;
    match args.command {
        HistoryCommand::List(args) => {
            write_output(&store.list_runs(args.limit, args.offset)?, &args.output)?
        }
        HistoryCommand::Show(args) => {
            write_output(&required_run(&store, &args.run_id)?, &args.output)?
        }
        HistoryCommand::Diff(args) => {
            let diff = store.diff_runs(&args.previous, &args.current)?;
            write_output(&diff, &args.output)?;
        }
    }
    Ok(CommandOutcome::Passed)
}

fn run_report(config: &Config, args: ReportArgs) -> Result<CommandOutcome> {
    let store = open_store(config)?;
    let report = required_run(&store, &args.run_id)?;
    write_report_output(&report, &args.output)?;
    Ok(classify_report(&report))
}

async fn run_serve(config: Config, args: ServeArgs) -> Result<CommandOutcome> {
    if args.once {
        bail!("serve does not support --once; use monitor --once for bounded execution");
    }
    let store = open_store(&config)?;
    let state =
        hooray::api::ApiState::new(store, config.clone()).context("failed to initialize API")?;
    let shutdown =
        hooray::api::shutdown_signal().context("failed to register shutdown signal handlers")?;
    let listener = tokio::net::TcpListener::bind(config.api_bind)
        .await
        .with_context(|| format!("failed to bind {}", config.api_bind))?;
    hooray::api::serve(listener, state, shutdown).await?;
    Ok(CommandOutcome::Passed)
}

async fn run_monitor(config: &Config, args: MonitorArgs) -> Result<CommandOutcome> {
    if let Some(MonitorCommand::Targets(targets)) = args.command {
        return run_monitor_targets(config, targets);
    }
    let webhook = match (
        args.webhook_url.as_deref(),
        args.webhook_secret_env.as_deref(),
    ) {
        (Some(url), Some(secret_env)) => {
            let secret = WebhookNotifier::resolve_secret(secret_env)?;
            Some(WebhookNotifier::new(config, url, secret)?)
        }
        (Some(_), None) => bail!("--webhook-secret-env is required when --webhook-url is set"),
        (None, Some(_)) => bail!("--webhook-url is required when --webhook-secret-env is set"),
        (None, None) => None,
    };
    let store = open_store(config)?;
    let runner = Arc::new(CliMonitorRunner {
        config: config.clone(),
    });
    let poll_interval = Duration::from_secs(config.monitor_interval_secs);
    match webhook {
        Some(notifier) => {
            run_monitor_loop(store, runner, args.once, Arc::new(notifier), poll_interval).await
        }
        None => {
            run_monitor_loop(
                store,
                runner,
                args.once,
                Arc::new(StderrNotifier),
                poll_interval,
            )
            .await
        }
    }
}

async fn run_monitor_loop<N: Notifier>(
    store: Store,
    runner: Arc<CliMonitorRunner>,
    once: bool,
    notifier: Arc<N>,
    poll_interval: Duration,
) -> Result<CommandOutcome> {
    let mut service = MonitorService::new(
        store,
        Arc::new(SystemClock),
        runner,
        notifier,
        MonitorConfig {
            poll_interval,
            ..MonitorConfig::default()
        },
    )?;
    if once {
        service.run_once().await?;
    } else {
        service
            .run_until_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
    }
    Ok(CommandOutcome::Passed)
}

fn run_monitor_targets(config: &Config, args: MonitorTargetsArgs) -> Result<CommandOutcome> {
    let mut store = open_store(config)?;
    match args.command {
        MonitorTargetsCommand::Add(args) => {
            let target = MonitorTarget::new(
                args.target_id,
                args.source,
                args.interval_seconds,
                Utc::now().timestamp(),
            )?;
            store.add_monitor_target(&target)?;
            println!("added monitor target '{}'", target.target_id);
        }
        MonitorTargetsCommand::List(args) => {
            let targets = store.list_monitor_targets(args.limit, args.offset)?;
            if args.output.format == OutputFormat::Table {
                write_bytes(
                    render_monitor_targets_table(&targets).as_bytes(),
                    &args.output.output,
                )?;
            } else {
                write_output(&targets, &args.output)?;
            }
        }
        MonitorTargetsCommand::Remove(args) => {
            if !store.remove_monitor_target(&args.target_id)? {
                bail!("monitor target '{}' was not found", args.target_id);
            }
            println!("removed monitor target '{}'", args.target_id);
        }
    }
    Ok(CommandOutcome::Passed)
}

fn render_monitor_targets_table(targets: &[MonitorTarget]) -> String {
    let headers = [
        "TARGET_ID",
        "SOURCE",
        "INTERVAL_SECONDS",
        "NEXT_DUE_AT",
        "UPDATED_AT",
    ];
    let rows: Vec<[String; 5]> = targets
        .iter()
        .map(|target| {
            [
                sanitize_cell_text(&target.target_id),
                sanitize_cell_text(&target.source),
                target.interval_seconds.to_string(),
                sanitize_cell_text(&target.next_due_at),
                sanitize_cell_text(&target.updated_at),
            ]
        })
        .collect();
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.len());
        }
    }
    let render_row = |cells: &[String; 5]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(column, cell)| {
                if column + 1 == cells.len() {
                    cell.clone()
                } else {
                    format!("{cell:<width$}  ", width = widths[column])
                }
            })
            .collect()
    };
    let mut rendered = render_row(&headers.map(str::to_owned));
    for row in &rows {
        rendered.push('\n');
        rendered.push_str(&render_row(row));
    }
    rendered.push('\n');
    rendered
}

struct CliMonitorRunner {
    config: Config,
}

impl MonitorRunner for CliMonitorRunner {
    fn refresh_advisories<'a>(
        &'a self,
        cursor: &'a AdvisoryCursor,
    ) -> MonitorFuture<'a, Result<AdvisoryRefresh, MonitorError>> {
        Box::pin(async move {
            // OSV's query API exposes no global feed revision. Advance a persisted
            // refresh generation every cycle so targets are conservatively
            // reevaluated instead of claiming unchanged advisory state.
            let generation = cursor
                .cursor
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default()
                .saturating_add(1);
            let token = generation.to_string();
            let digest = sha256_hex(format!("osv-periodic-refresh-v1:{token}").as_bytes());
            Ok(AdvisoryRefresh {
                changed: cursor.digest.as_deref() != Some(digest.as_str()),
                cursor: AdvisoryCursor {
                    cursor: Some(token),
                    digest: Some(digest),
                    etag: None,
                    last_modified: None,
                    updated_at: cursor.updated_at,
                },
            })
        })
    }

    fn policy_digest(&self) -> Result<String, MonitorError> {
        let bytes = read_bounded(&self.config.policy_path, self.config.max_input_bytes)
            .map_err(|error| MonitorError::Runner(error.to_string()))?;
        if bytes.len() as u64 > self.config.max_input_bytes {
            return Err(MonitorError::Runner(
                "policy exceeds configured input bound".into(),
            ));
        }
        Ok(sha256_hex(&bytes))
    }

    fn source_fingerprint<'a>(
        &'a self,
        target: &'a hooray::monitor::MonitorTarget,
    ) -> MonitorFuture<'a, Result<String, MonitorError>> {
        Box::pin(async move {
            use sha2::{Digest, Sha256};
            use walkdir::WalkDir;

            let requested_root = PathBuf::from(target.source.as_str());
            let max_input_bytes = self.config.max_input_bytes;
            let max_archive_entries = self.config.max_archive_entries;
            let database_path = self.config.database_path.clone();
            tokio::task::spawn_blocking(move || -> Result<String, MonitorError> {
                let metadata = std::fs::symlink_metadata(&requested_root)
                    .map_err(|error| MonitorError::Runner(error.to_string()))?;
                if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
                    return Err(MonitorError::Runner(format!(
                        "monitor source '{}' is not a regular file or directory",
                        requested_root.display()
                    )));
                }
                let root = std::fs::canonicalize(&requested_root)
                    .map_err(|error| MonitorError::Runner(error.to_string()))?;
                let excluded_database_paths = std::fs::canonicalize(&database_path)
                    .ok()
                    .map(|database| {
                        let mut paths = BTreeSet::from([database.clone()]);
                        for suffix in ["-wal", "-shm", "-journal"] {
                            if let Some(name) = database.file_name() {
                                let mut sidecar_name = name.to_os_string();
                                sidecar_name.push(suffix);
                                paths.insert(database.with_file_name(sidecar_name));
                            }
                        }
                        paths
                    })
                    .unwrap_or_default();
                let mut paths = if metadata.is_file() {
                    (!excluded_database_paths.contains(&root))
                        .then(|| root.clone())
                        .into_iter()
                        .collect()
                } else {
                    WalkDir::new(&root)
                        .follow_links(false)
                        .sort_by_file_name()
                        .into_iter()
                        .filter_map(|entry| match entry {
                            Err(error) => Some(Err(error)),
                            Ok(entry)
                                if entry.file_type().is_file()
                                    && !excluded_database_paths.contains(entry.path()) =>
                            {
                                Some(Ok(entry.into_path()))
                            }
                            Ok(_) => None,
                        })
                        .take(max_archive_entries.saturating_add(1))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| {
                            MonitorError::Runner(format!(
                                "failed to walk source '{}': {error}",
                                root.display()
                            ))
                        })?
                };
                if paths.len() > max_archive_entries {
                    return Err(MonitorError::Runner(format!(
                        "source fingerprint exceeds configured file bound of {max_archive_entries}"
                    )));
                }
                paths.sort();
                let mut digest = Sha256::new();
                digest.update(b"hooray.source-fingerprint.v2\0");
                let mut total = 0_u64;
                for path in paths {
                    let relative = path.strip_prefix(&root).unwrap_or(&path);
                    let relative = relative.as_os_str().as_encoded_bytes();
                    digest.update((relative.len() as u64).to_be_bytes());
                    digest.update(relative);
                    // Bound enforced during the read (mirrors StdinFile::take) so
                    // an oversized file never allocates fully before rejection.
                    let bytes = read_bounded(&path, max_input_bytes)
                        .map_err(|error| MonitorError::Runner(error.to_string()))?;
                    total = total.saturating_add(bytes.len() as u64);
                    if total > max_input_bytes {
                        return Err(MonitorError::Runner(
                            "source fingerprint exceeds configured input bound".into(),
                        ));
                    }
                    digest.update((bytes.len() as u64).to_be_bytes());
                    digest.update(bytes);
                }
                Ok(format!("{:x}", digest.finalize()))
            })
            .await
            .map_err(|_| MonitorError::Runner("source fingerprint task was cancelled".into()))?
        })
    }

    fn evaluate<'a>(
        &'a self,
        target: &'a hooray::monitor::MonitorTarget,
    ) -> MonitorFuture<'a, Result<Evaluation, MonitorError>> {
        Box::pin(async move {
            let input = ScanInput::detect(Path::new(&target.source), &self.config)
                .map_err(|error| MonitorError::Runner(error.to_string()))?;
            let mut store =
                Store::open_memory().map_err(|error| MonitorError::Runner(error.to_string()))?;
            let mut engine = Engine::new(&self.config, &mut store, None);
            let report = engine
                .scan(ScanRequest::new(input, self.config.policy_path.clone()))
                .await
                .map_err(|error| MonitorError::Runner(error.to_string()))?;
            Ok(Evaluation {
                inventory: report.inventory,
                finding_ids: report.findings.into_keys().collect(),
            })
        })
    }
}

struct StderrNotifier;
impl Notifier for StderrNotifier {
    fn notify<'a>(&'a self, event: &'a AlertEvent) -> MonitorFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let line = serde_json::to_string(event).map_err(|error| error.to_string())?;
            eprintln!("{line}");
            Ok(())
        })
    }
}

const WEBHOOK_EVENT: &str = "alert";

/// Delivers monitor alert events to an HTTPS webhook endpoint. Payloads are
/// signed with the shared integration HMAC scheme; the secret is resolved
/// from the named environment variable before the loop starts and is never
/// rendered in errors or logs.
#[derive(Debug)]
struct WebhookNotifier {
    http: reqwest::Client,
    url: reqwest::Url,
    secret: Vec<u8>,
    generator: IntegrationGenerator,
}

impl WebhookNotifier {
    fn new(config: &Config, url: &str, secret: Vec<u8>) -> Result<Self> {
        // integrations.rs enforces these rules at delivery time inside
        // signed_webhook too; enforcing them here keeps undeliverable
        // configurations from starting and silently dead-lettering every
        // alert.
        validate_webhook_config(Some(url), &secret, WEBHOOK_EVENT)
            .map_err(|error| anyhow!("--webhook-url/--webhook-secret-env rejected: {error}"))?;
        let parsed = reqwest::Url::parse(url)
            .map_err(|error| anyhow!("invalid --webhook-url '{url}': {error}"))?;
        let generator = IntegrationGenerator::new(IntegrationLimits::default())
            .context("invalid webhook integration limits")?;
        let http = reqwest::Client::builder()
            // Signed webhook headers and payload must never replay to a
            // redirect target: reqwest's default follows up to 10 hops,
            // including https->http downgrades, stripping only
            // Authorization/Cookie-class headers.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(config.osv_connect_timeout_secs))
            .timeout(Duration::from_secs(config.osv_request_timeout_secs))
            .build()
            .context("failed to build webhook HTTP client")?;
        Ok(Self {
            http,
            url: parsed,
            secret,
            generator,
        })
    }

    fn resolve_secret(secret_env: &str) -> Result<Vec<u8>> {
        let secret = std::env::var(secret_env).map_err(|error| match error {
            std::env::VarError::NotUnicode(raw) => anyhow!(
                "--webhook-secret-env '{secret_env}' is set but its value is not valid UTF-8 ({} bytes)",
                raw.len()
            ),
            _ => anyhow!("--webhook-secret-env '{secret_env}' is not set to a value"),
        })?;
        if secret.is_empty() {
            bail!("--webhook-secret-env '{secret_env}' is empty");
        }
        Ok(secret.into_bytes())
    }

    fn signed_request(&self, event: &AlertEvent) -> Result<SignedWebhook, String> {
        let payload = serde_json::to_value(event).map_err(|error| error.to_string())?;
        self.generator
            .signed_webhook(self.url.as_str(), &self.secret, WEBHOOK_EVENT, &payload)
            .map_err(|error| error.to_string())
    }
}

impl Notifier for WebhookNotifier {
    fn notify<'a>(&'a self, event: &'a AlertEvent) -> MonitorFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let signed = self.signed_request(event)?;
            let mut request = self.http.post(signed.url.clone());
            for (name, value) in &signed.headers {
                request = request.header(name, value);
            }
            let response =
                request.body(signed.body).send().await.map_err(|error| {
                    format!("webhook delivery to {} failed: {error}", signed.url)
                })?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("webhook endpoint returned HTTP {status}"));
            }
            Ok(())
        })
    }
}

/// Reads at most `cap + 1` bytes so callers can enforce an input bound
/// without ever allocating the whole file. The extra byte lets the caller
/// distinguish "at cap" from "over cap".
fn read_bounded(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?.take(cap.saturating_add(1));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn run_integrations(args: IntegrationsArgs) -> Result<CommandOutcome> {
    let IntegrationsCommand::Generate(args) = args.command;
    let generator = IntegrationGenerator::new(IntegrationLimits::default())?;
    let artifact = match args.kind {
        IntegrationKind::PreCommit => generator.pre_commit_config()?,
        IntegrationKind::GithubActions => generator.github_actions_workflow()?,
        IntegrationKind::GitlabCi => generator.gitlab_ci_include()?,
        IntegrationKind::GitlabSecurity => generator.gitlab_security_ci_include()?,
    };
    write_bytes(&artifact.body, &args.output)?;
    Ok(CommandOutcome::Passed)
}

fn open_store(config: &Config) -> Result<Store> {
    Store::open(&config.database_path)
        .with_context(|| format!("failed to open {}", config.database_path.display()))
}

fn required_run(store: &Store, id: &RunId) -> Result<ScanReport> {
    store
        .get_run(id)?
        .with_context(|| format!("scan run '{id}' was not found"))
}

fn classify_report(report: &ScanReport) -> CommandOutcome {
    if report.policy_summary.denied == 0 {
        CommandOutcome::Passed
    } else {
        CommandOutcome::PolicyDenied
    }
}

fn write_report_output(report: &ScanReport, args: &OutputArgs) -> Result<()> {
    if args.format == OutputFormat::GitlabArtifacts {
        report::write_gitlab_artifacts(&args.output, report)?;
    } else {
        let bytes = report::render(report, ReportFormat::try_from(args.format)?)?;
        write_bytes(&bytes, &args.output)?;
    }
    Ok(())
}

fn write_output<T: Serialize>(value: &T, args: &OutputArgs) -> Result<()> {
    if !matches!(args.format, OutputFormat::Json | OutputFormat::Yaml) {
        bail!("this command supports only json and yaml output");
    }
    let mut bytes = if args.format == OutputFormat::Json {
        serde_json::to_vec_pretty(value)?
    } else {
        serde_yaml::to_string(value)?.into_bytes()
    };
    bytes.push(b'\n');
    write_bytes(&bytes, &args.output)
}

fn write_bytes(bytes: &[u8], path: &Path) -> Result<()> {
    if path == Path::new("-") {
        io::stdout().lock().write_all(bytes)?;
    } else {
        // Open in place rather than temp-file-plus-rename: rename swaps the
        // directory entry itself, which breaks outputs bound to devices or
        // bind mounts such as /dev/null.
        write_in_place(bytes, path)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

/// Creates or truncates `path` and writes `bytes` in place.
///
/// On unix the open refuses a symlink at the final path component
/// (`O_NOFOLLOW`) so planted links cannot redirect report output elsewhere,
/// while regular-file overwrite keeps working. Other platforms keep plain
/// create/truncate semantics: creating symlinks there already requires
/// elevated privileges.
fn write_in_place(bytes: &[u8], path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

struct StdinFile {
    path: PathBuf,
}
impl StdinFile {
    fn read(maximum: u64) -> Result<Self> {
        let mut bytes = Vec::new();
        io::stdin().take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            bail!("standard input exceeds {maximum} bytes");
        }
        let path =
            std::env::temp_dir().join(format!("hooray-stdin-{}.cdx.json", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .context("failed to create bounded stdin file")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(Self { path })
    }
}
impl Drop for StdinFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hooray::model::{
        Asset, AssetId, AssetKind, Finding, Inventory, PolicyDecision, PolicyId, PolicyOutcome,
        PolicySummary, RunMetadata,
    };
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::TempDir;

    fn output(path: PathBuf, format: OutputFormat) -> OutputArgs {
        OutputArgs {
            format,
            output: path,
        }
    }

    fn config(temp: &TempDir) -> Config {
        Config {
            database_path: temp.path().join("history.db"),
            policy_path: temp.path().join("policy.yaml"),
            offline: true,
            ..Config::default()
        }
    }

    fn report(run_id: &str, started_at: &str, finding_ids: &[&str], denied: u64) -> ScanReport {
        let findings = finding_ids
            .iter()
            .map(|id| {
                let finding: Finding = serde_json::from_value(json!({
                    "id": id,
                    "kind": "sast",
                    "rule_id": "rule:test",
                    "severity": "high",
                    "confidence": "high",
                    "status": "open",
                    "first_seen": started_at,
                    "last_seen": started_at
                }))
                .unwrap();
                (finding.id.clone(), finding)
            })
            .collect();
        ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new(run_id).unwrap(),
                started_at: started_at.into(),
                completed_at: Some(started_at.into()),
                scanner_version: Some(env!("CARGO_PKG_VERSION").into()),
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: Asset {
                    id: AssetId::new("asset:test").unwrap(),
                    name: "test".into(),
                    kind: AssetKind::Repository,
                    version: None,
                    metadata: BTreeMap::new(),
                },
                components: BTreeMap::new(),
                locations: BTreeSet::new(),
                dependencies: BTreeSet::new(),
            },
            findings,
            policy_decisions: if denied == 0 {
                BTreeSet::new()
            } else {
                BTreeSet::from([PolicyDecision {
                    policy_id: PolicyId::new("policy:test").unwrap(),
                    finding_id: None,
                    outcome: PolicyOutcome::Deny,
                    reason: "test denial".into(),
                    exception_id: None,
                }])
            },
            policy_summary: PolicySummary {
                allowed: 0,
                warned: 0,
                denied,
            },
        }
    }

    fn save_reports(config: &Config, reports: &[ScanReport]) {
        let mut store = Store::open(&config.database_path).unwrap();
        for report in reports {
            store.save_report(report).unwrap();
        }
    }

    #[test]
    fn clap_exposes_every_enterprise_command() {
        for command in [
            vec!["hooray", "scan", "project", "."],
            vec!["hooray", "scan", "sbom", "bom.json"],
            vec!["hooray", "scan", "artifact", "app.zip"],
            vec!["hooray", "scan", "container", "image.tar"],
            vec!["hooray", "scan", "auto", "."],
            vec!["hooray", "policy", "validate", "policy.yaml"],
            vec![
                "hooray",
                "policy",
                "evaluate",
                "policy.yaml",
                "--run-id",
                "run:one",
            ],
            vec!["hooray", "inventory"],
            vec!["hooray", "history", "list"],
            vec!["hooray", "history", "show", "run:one"],
            vec!["hooray", "history", "diff", "run:one", "run:two"],
            vec!["hooray", "report", "run:one"],
            vec!["hooray", "serve"],
            vec!["hooray", "monitor", "--once"],
            vec!["hooray", "integrations", "generate", "github-actions"],
        ] {
            assert!(Cli::try_parse_from(command).is_ok());
        }
    }

    #[test]
    fn clap_rejects_legacy_flat_scan_surface() {
        assert!(Cli::try_parse_from(["hooray", "scan", "--input", "bom.json"]).is_err());
        assert!(Cli::try_parse_from(["hooray", "config", "validate"]).is_err());
    }

    #[test]
    fn stable_exit_codes_are_reserved() {
        assert_eq!(CommandOutcome::Passed.exit_status(), 0);
        assert_eq!(CommandOutcome::PolicyDenied.exit_status(), 1);
        assert_eq!(EXIT_OPERATIONAL_ERROR, 2);
    }

    #[test]
    fn policy_validate_accepts_yaml_and_rejects_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let valid = temp.path().join("valid.yaml");
        let invalid = temp.path().join("invalid.toml");
        std::fs::write(&valid, "version: 1\ndefault_outcome: allow\n").unwrap();
        std::fs::write(&invalid, "version = [").unwrap();
        assert_eq!(
            run_policy(
                &config,
                PolicyArgs {
                    command: PolicyCommand::Validate(PolicyValidateArgs { policy: valid })
                }
            )
            .unwrap(),
            CommandOutcome::Passed
        );
        assert!(
            run_policy(
                &config,
                PolicyArgs {
                    command: PolicyCommand::Validate(PolicyValidateArgs { policy: invalid })
                }
            )
            .unwrap_err()
            .to_string()
            .contains("policy is invalid")
        );
    }

    #[test]
    fn policy_evaluate_writes_summary_and_returns_deny_exit() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let stored = report(
            "run:evaluate",
            "2026-01-01T00:00:00.000Z",
            &["finding:one"],
            0,
        );
        save_reports(&config, &[stored]);
        let policy = temp.path().join("deny.yaml");
        std::fs::write(&policy, "version: 1\ndefault_outcome: deny\n").unwrap();
        let destination = temp.path().join("summary.yaml");
        let outcome = run_policy(
            &config,
            PolicyArgs {
                command: PolicyCommand::Evaluate(PolicyEvaluateArgs {
                    policy,
                    run_id: RunId::new("run:evaluate").unwrap(),
                    output: output(destination.clone(), OutputFormat::Yaml),
                }),
            },
        )
        .unwrap();
        assert_eq!(outcome, CommandOutcome::PolicyDenied);
        let value: Value = serde_yaml::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(value["denied"], 1);
    }

    #[test]
    fn history_list_show_diff_and_inventory_write_observable_results() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let first = report(
            "run:one",
            "2026-01-01T00:00:00.000Z",
            &["finding:same", "finding:old"],
            0,
        );
        let second = report(
            "run:two",
            "2026-02-01T00:00:00.000Z",
            &["finding:same", "finding:new"],
            0,
        );
        save_reports(&config, &[first, second]);

        let list = temp.path().join("list.json");
        run_history(
            &config,
            HistoryArgs {
                command: HistoryCommand::List(HistoryListArgs {
                    limit: 1,
                    offset: 0,
                    output: output(list.clone(), OutputFormat::Json),
                }),
            },
        )
        .unwrap();
        let listed: Value = serde_json::from_slice(&std::fs::read(list).unwrap()).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["run"]["id"], "run:two");

        let show = temp.path().join("show.yaml");
        run_history(
            &config,
            HistoryArgs {
                command: HistoryCommand::Show(HistoryShowArgs {
                    run_id: RunId::new("run:one").unwrap(),
                    output: output(show.clone(), OutputFormat::Yaml),
                }),
            },
        )
        .unwrap();
        let shown: Value = serde_yaml::from_slice(&std::fs::read(show).unwrap()).unwrap();
        assert_eq!(shown["run"]["id"], "run:one");

        let diff = temp.path().join("diff.json");
        run_history(
            &config,
            HistoryArgs {
                command: HistoryCommand::Diff(HistoryDiffArgs {
                    previous: RunId::new("run:one").unwrap(),
                    current: RunId::new("run:two").unwrap(),
                    output: output(diff.clone(), OutputFormat::Json),
                }),
            },
        )
        .unwrap();
        let changed: Value = serde_json::from_slice(&std::fs::read(diff).unwrap()).unwrap();
        assert_eq!(changed["introduced"], json!(["finding:new"]));
        assert_eq!(changed["resolved"], json!(["finding:old"]));
        assert_eq!(changed["unchanged"], json!(["finding:same"]));

        let inventory = temp.path().join("inventory.json");
        run_inventory(
            &config,
            InventoryArgs {
                run_id: None,
                output: output(inventory.clone(), OutputFormat::Json),
            },
        )
        .unwrap();
        let inventory_value: Value =
            serde_json::from_slice(&std::fs::read(inventory).unwrap()).unwrap();
        assert_eq!(inventory_value["asset"]["name"], "test");
    }

    #[test]
    fn report_render_preserves_deny_classification_and_missing_runs_are_operational_errors() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        save_reports(
            &config,
            &[report("run:denied", "2026-01-01T00:00:00.000Z", &[], 1)],
        );
        let destination = temp.path().join("report.html");
        let outcome = run_report(
            &config,
            ReportArgs {
                run_id: RunId::new("run:denied").unwrap(),
                output: output(destination.clone(), OutputFormat::Html),
            },
        )
        .unwrap();
        assert_eq!(outcome.exit_status(), EXIT_POLICY_DENIED);
        assert!(
            String::from_utf8(std::fs::read(destination).unwrap())
                .unwrap()
                .contains("<!doctype html>")
        );
        let error = run_report(
            &config,
            ReportArgs {
                run_id: RunId::new("run:missing").unwrap(),
                output: output(temp.path().join("missing.json"), OutputFormat::Json),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("was not found"));
    }

    #[test]
    fn integrations_generate_supported_artifacts_with_parseable_cli_commands() {
        let temp = TempDir::new().unwrap();
        for (kind, marker) in [
            (IntegrationKind::PreCommit, "repos:"),
            (
                IntegrationKind::GithubActions,
                "upload-sarif@6f5948dfacef28e207b48d0905cf90c03365536d",
            ),
            (IntegrationKind::GitlabCi, "hooray_policy:"),
            (IntegrationKind::GitlabSecurity, "sarif:"),
        ] {
            let destination = temp.path().join(format!("{kind:?}.yaml"));
            assert_eq!(
                run_integrations(IntegrationsArgs {
                    command: IntegrationsCommand::Generate(IntegrationGenerateArgs {
                        kind,
                        output: destination.clone()
                    })
                })
                .unwrap(),
                CommandOutcome::Passed
            );
            assert!(
                String::from_utf8(std::fs::read(destination).unwrap())
                    .unwrap()
                    .contains(marker)
            );
        }
        for command in [
            "hooray scan project . --format json",
            "hooray scan project . --format sarif --output hooray.sarif",
            "hooray scan auto . --policy hooray-policy.yaml --format gitlab-artifacts --output .hooray-gitlab",
            "hooray scan auto . --format gitlab-sarif --output gl-sarif-report.sarif",
            "hooray scan auto . --format gitlab-cyclonedx --output gl-sbom-hooray.cdx.json",
        ] {
            assert!(
                Cli::try_parse_from(command.split_whitespace()).is_ok(),
                "{command}"
            );
        }
        assert_eq!(
            ReportFormat::try_from(OutputFormat::GitlabSarif).unwrap(),
            ReportFormat::GitLabSarif
        );
        assert_eq!(
            ReportFormat::try_from(OutputFormat::GitlabCyclonedx).unwrap(),
            ReportFormat::GitLabCycloneDx
        );
        assert!(ReportFormat::try_from(OutputFormat::GitlabArtifacts).is_err());
    }

    #[test]
    fn input_kind_mismatch_and_unsupported_structured_output_fail_closed() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let sbom = temp.path().join("bom.cdx.json");
        std::fs::write(&sbom, r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#).unwrap();
        assert!(
            detect_input(ScanKind::Project, &sbom, &config)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        let destination = temp.path().join("unsupported.out");
        assert!(
            write_output(
                &json!({"safe": true}),
                &output(destination.clone(), OutputFormat::Html)
            )
            .unwrap_err()
            .to_string()
            .contains("only json and yaml")
        );
        assert!(!destination.exists() || std::fs::read(destination).unwrap().is_empty());
    }

    #[tokio::test]
    async fn internal_run_surfaces_invalid_config_and_bounded_serve_errors() {
        let temp = TempDir::new().unwrap();
        let invalid = temp.path().join("invalid.yaml");
        std::fs::write(&invalid, "max_concurrency: 0\n").unwrap();
        let cli =
            Cli::try_parse_from(["hooray", "--config", invalid.to_str().unwrap(), "inventory"])
                .unwrap();
        let error = run(cli).await.unwrap_err();
        assert!(error.to_string().contains("failed to load configuration"));

        let error = run_serve(config(&temp), ServeArgs { once: true })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not support --once"));
    }

    #[test]
    fn structured_output_rejects_bundle_before_opening_destination() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("unsupported.out");
        assert!(
            write_output(
                &json!({"safe": true}),
                &output(destination.clone(), OutputFormat::GitlabArtifacts)
            )
            .unwrap_err()
            .to_string()
            .contains("only json and yaml")
        );
        assert!(!destination.exists());
    }

    #[test]
    fn stored_report_bundle_dispatch_preserves_policy_outcome_and_destination_rules() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        save_reports(
            &config,
            &[report("run:bundle", "2026-01-01T00:00:00.000Z", &[], 1)],
        );
        let destination = temp.path().join("gitlab");
        let outcome = run_report(
            &config,
            ReportArgs {
                run_id: RunId::new("run:bundle").unwrap(),
                output: output(destination.clone(), OutputFormat::GitlabArtifacts),
            },
        )
        .unwrap();
        assert_eq!(outcome, CommandOutcome::PolicyDenied);
        let names: BTreeSet<_> = std::fs::read_dir(&destination)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names,
            BTreeSet::from([
                "gl-code-quality-report.json".to_owned(),
                "gl-junit-report.xml".to_owned(),
                "gl-sarif-report.sarif".to_owned(),
                "gl-sbom-hooray.cdx.json".to_owned(),
                "hooray.env".to_owned(),
            ])
        );

        std::fs::write(destination.join("sentinel"), "keep").unwrap();
        assert!(
            run_report(
                &config,
                ReportArgs {
                    run_id: RunId::new("run:bundle").unwrap(),
                    output: output(destination.clone(), OutputFormat::GitlabArtifacts),
                },
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(destination.join("sentinel")).unwrap(),
            "keep"
        );

        let missing = temp.path().join("missing").join("gitlab");
        assert!(
            run_report(
                &config,
                ReportArgs {
                    run_id: RunId::new("run:bundle").unwrap(),
                    output: output(missing.clone(), OutputFormat::GitlabArtifacts),
                },
            )
            .is_err()
        );
        assert!(!missing.exists());

        assert!(
            run_report(
                &config,
                ReportArgs {
                    run_id: RunId::new("run:bundle").unwrap(),
                    output: output(PathBuf::from("-"), OutputFormat::GitlabArtifacts),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn byte_output_reports_unwritable_destination_without_partial_parent_creation() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("missing").join("report.json");
        let error = write_bytes(b"sensitive report", &destination).unwrap_err();
        assert!(error.to_string().contains("failed to write"));
        assert!(!destination.exists());
    }

    #[test]
    fn structured_file_output_replaces_existing_contents_completely() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("result.json");
        std::fs::write(&destination, [b'x'; 4096]).unwrap();
        write_output(
            &json!({"status": "passed"}),
            &output(destination.clone(), OutputFormat::Json),
        )
        .unwrap();
        let bytes = std::fs::read(destination).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, json!({"status": "passed"}));
        assert!(!bytes.windows(2).any(|window| window == b"xx"));
    }
    #[tokio::test]
    async fn monitor_fingerprint_tracks_scanner_relevant_source_content() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='1.0.0'\n",
        )
        .unwrap();
        std::fs::write(source.join("Cargo.lock"), "version = 3\n").unwrap();
        let runner = CliMonitorRunner {
            config: config(&temp),
        };
        let mut target = hooray::monitor::MonitorTarget {
            id: "source-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        let before = runner.source_fingerprint(&target).await.unwrap();
        std::fs::write(
            source.join("src.rs"),
            "let password = \"super-secret-value-123456789\";\n",
        )
        .unwrap();
        let after = runner.source_fingerprint(&target).await.unwrap();
        assert_ne!(
            before, after,
            "source-only scanner input changes must invalidate the target"
        );
        target.source_fingerprint = Some(after);
    }

    #[tokio::test]
    async fn monitor_inputs_enforce_input_bound_during_read() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("policy.yaml"), vec![b'p'; 2048]).unwrap();
        let source = temp.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("blob.bin"), vec![b'a'; 4096]).unwrap();
        let runner = CliMonitorRunner {
            config: Config {
                max_input_bytes: 1024,
                ..config(&temp)
            },
        };
        let policy_error = runner.policy_digest().unwrap_err().to_string();
        assert!(
            policy_error.contains("policy exceeds configured input bound"),
            "{policy_error}"
        );
        let target = hooray::monitor::MonitorTarget {
            id: "bound-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        let fingerprint_error = runner
            .source_fingerprint(&target)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            fingerprint_error.contains("source fingerprint exceeds configured input bound"),
            "{fingerprint_error}"
        );
    }

    #[tokio::test]
    async fn monitor_fingerprint_rejects_file_count_truncation() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("one"), "1").unwrap();
        std::fs::write(source.join("two"), "2").unwrap();
        let runner = CliMonitorRunner {
            config: Config {
                max_archive_entries: 1,
                ..config(&temp)
            },
        };
        let target = hooray::monitor::MonitorTarget {
            id: "entry-bound-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        let error = runner
            .source_fingerprint(&target)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("configured file bound of 1"), "{error}");
    }

    #[tokio::test]
    async fn monitor_fingerprint_ignores_its_own_database_files() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("Cargo.lock"), "version = 3\n").unwrap();
        let database_path = source.join("hooray.db");
        std::fs::write(&database_path, "database-before").unwrap();
        let runner = CliMonitorRunner {
            config: Config {
                database_path: database_path.clone(),
                ..config(&temp)
            },
        };
        let target = hooray::monitor::MonitorTarget {
            id: "database-exclusion-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        let before = runner.source_fingerprint(&target).await.unwrap();
        std::fs::write(&database_path, "database-after").unwrap();
        std::fs::write(source.join("hooray.db-wal"), "wal").unwrap();
        std::fs::write(source.join("hooray.db-shm"), "shm").unwrap();
        std::fs::write(source.join("hooray.db-journal"), "journal").unwrap();
        let after = runner.source_fingerprint(&target).await.unwrap();
        assert_eq!(before, after);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn monitor_fingerprint_fails_closed_on_unreadable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let source = temp.path().join("project");
        let sealed = source.join("sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        std::fs::write(sealed.join("hidden.rs"), "fn hidden() {}\n").unwrap();
        std::fs::write(source.join("visible.rs"), "fn visible() {}\n").unwrap();
        let runner = CliMonitorRunner {
            config: config(&temp),
        };
        let target = hooray::monitor::MonitorTarget {
            id: "unreadable-dir-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        // Lock the directory only for the fingerprint call; permissions must
        // be restored so TempDir cleanup can recurse.
        std::fs::set_permissions(&sealed, PermissionsExt::from_mode(0o000)).unwrap();
        let result = runner.source_fingerprint(&target).await;
        let enforced = std::fs::File::open(&sealed).is_err();
        std::fs::set_permissions(&sealed, PermissionsExt::from_mode(0o755)).unwrap();
        if !enforced {
            // Privileged environment (e.g. root): permission bits are not
            // enforced, so the walk legitimately succeeds.
            return;
        }
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("failed to walk source"),
            "an unreadable directory must fail the cycle, got: {error}"
        );
    }

    #[test]
    fn read_bounded_never_reads_past_the_cap() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("blob.bin");
        std::fs::write(&path, vec![b'a'; 4096]).unwrap();
        let capped = read_bounded(&path, 1024).unwrap();
        assert_eq!(capped.len(), 1025, "read must stop at cap + 1 bytes");
        let exact = read_bounded(&path, 4096).unwrap();
        assert_eq!(exact.len(), 4096);
        assert!(read_bounded(&temp.path().join("missing"), 16).is_err());
    }

    #[tokio::test]
    async fn monitor_advisory_refresh_uses_conservative_periodic_state_tokens() {
        let temp = TempDir::new().unwrap();
        let runner = CliMonitorRunner {
            config: config(&temp),
        };
        let first = runner
            .refresh_advisories(&AdvisoryCursor::default())
            .await
            .unwrap();
        let second = runner.refresh_advisories(&first.cursor).await.unwrap();
        assert!(first.changed && second.changed);
        assert_eq!(first.cursor.cursor.as_deref(), Some("1"));
        assert_eq!(second.cursor.cursor.as_deref(), Some("2"));
        assert_ne!(first.cursor.digest, second.cursor.digest);
    }

    #[tokio::test]
    async fn monitor_evaluation_runs_filesystem_findings_from_full_engine_pipeline() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='1.0.0'\n",
        )
        .unwrap();
        std::fs::write(
            source.join("Cargo.lock"),
            "version = 3\n[[package]]\nname = 'demo'\nversion = '1.0.0'\n",
        )
        .unwrap();
        std::fs::write(
            source.join("app.rs"),
            format!(
                "let token = \"{}{}\";\n",
                "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
            ),
        )
        .unwrap();
        let mut cfg = config(&temp);
        std::fs::write(
            &cfg.policy_path,
            "version: 1\ndefault_outcome: allow\nrules: []\nexceptions: []\n",
        )
        .unwrap();
        cfg.offline = true;
        let runner = CliMonitorRunner { config: cfg };
        let target = hooray::monitor::MonitorTarget {
            id: "pipeline-test".into(),
            source: source.display().to_string(),
            interval_seconds: 60,
            next_due_at: 0,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        };
        let evaluation = runner.evaluate(&target).await.unwrap();
        assert!(
            !evaluation.finding_ids.is_empty(),
            "filesystem scanner findings must flow through monitor evaluation"
        );
    }

    #[test]
    fn clap_parses_monitor_targets_and_preserves_bare_monitor() {
        let parsed = Cli::try_parse_from([
            "hooray",
            "monitor",
            "targets",
            "add",
            "webapp",
            "--source",
            "repo",
            "--interval-seconds",
            "60",
        ])
        .unwrap();
        let Command::Monitor(args) = parsed.command else {
            panic!("expected monitor command");
        };
        assert!(!args.once);
        match args.command {
            Some(MonitorCommand::Targets(targets)) => match targets.command {
                MonitorTargetsCommand::Add(add) => {
                    assert_eq!(add.target_id, "webapp");
                    assert_eq!(add.source, "repo");
                    assert_eq!(add.interval_seconds, 60);
                }
                _ => panic!("expected add subcommand"),
            },
            None => panic!("expected targets subcommand"),
        }

        let bare = Cli::try_parse_from(["hooray", "monitor", "--once"]).unwrap();
        let Command::Monitor(args) = bare.command else {
            panic!("expected monitor command");
        };
        assert!(args.once && args.command.is_none());

        assert!(
            Cli::try_parse_from(["hooray", "monitor", "targets", "add", "x"]).is_err(),
            "add requires --source and --interval-seconds"
        );
    }

    #[test]
    fn clap_rejects_monitor_intervals_outside_validated_range() {
        for seconds in ["0", "86401", "100000000000"] {
            let parsed = Cli::try_parse_from([
                "hooray",
                "monitor",
                "targets",
                "add",
                "x",
                "--source",
                "repo",
                "--interval-seconds",
                seconds,
            ]);
            assert!(
                parsed.is_err(),
                "--interval-seconds {seconds} must be rejected"
            );
        }
        Cli::try_parse_from([
            "hooray",
            "monitor",
            "targets",
            "add",
            "x",
            "--source",
            "repo",
            "--interval-seconds",
            "86400",
        ])
        .unwrap();
    }

    #[test]
    fn clap_monitor_webhook_flags_parse_together() {
        let parsed = Cli::try_parse_from([
            "hooray",
            "monitor",
            "--once",
            "--webhook-url",
            "https://hooks.example/hooray",
            "--webhook-secret-env",
            "HOORAY_WEBHOOK_SECRET",
        ])
        .unwrap();
        let Command::Monitor(args) = parsed.command else {
            panic!("expected monitor command");
        };
        assert_eq!(
            args.webhook_url.as_deref(),
            Some("https://hooks.example/hooray")
        );
        assert_eq!(
            args.webhook_secret_env.as_deref(),
            Some("HOORAY_WEBHOOK_SECRET")
        );
    }

    #[tokio::test]
    async fn monitor_webhook_flags_must_come_in_pairs() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp);
        let only_url = run_monitor(
            &cfg,
            MonitorArgs {
                once: true,
                webhook_url: Some("https://hooks.example/hooray".into()),
                webhook_secret_env: None,
                command: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(only_url.contains("--webhook-secret-env"), "{only_url}");
        let only_env = run_monitor(
            &cfg,
            MonitorArgs {
                once: true,
                webhook_url: None,
                webhook_secret_env: Some("HOORAY_WEBHOOK_SECRET".into()),
                command: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(only_env.contains("--webhook-url"), "{only_env}");
    }

    #[tokio::test]
    async fn monitor_without_webhook_flags_keeps_stderr_fallback() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("policy.yaml"), "version: 1\n").unwrap();
        let outcome = run_monitor(
            &config(&temp),
            MonitorArgs {
                once: true,
                webhook_url: None,
                webhook_secret_env: None,
                command: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome, CommandOutcome::Passed);
    }

    #[test]
    fn webhook_notifier_rejects_plain_http_urls() {
        let temp = TempDir::new().unwrap();
        let error = WebhookNotifier::new(
            &config(&temp),
            "http://hooks.example/hooray",
            b"0123456789abcdef".to_vec(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTPS is required"), "{error}");
    }

    #[test]
    fn webhook_notifier_requires_resolvable_secret_env() {
        let error = WebhookNotifier::resolve_secret("HOORAY_DEFINITELY_UNSET_SECRET_VAR_XYZ")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("HOORAY_DEFINITELY_UNSET_SECRET_VAR_XYZ"),
            "{error}"
        );
    }

    #[test]
    fn webhook_notifier_rejects_undeliverable_secrets_eagerly() {
        let temp = TempDir::new().unwrap();
        let short = WebhookNotifier::new(
            &config(&temp),
            "https://hooks.example/hooray",
            b"short".to_vec(),
        )
        .unwrap_err()
        .to_string();
        assert!(short.contains("16"), "{short}");
        assert!(!short.contains("short"), "{short}");
        let oversized = WebhookNotifier::new(
            &config(&temp),
            "https://hooks.example/hooray",
            vec![b'x'; 4097],
        )
        .unwrap_err()
        .to_string();
        assert!(oversized.contains("4096"), "{oversized}");
    }

    #[test]
    fn webhook_notifier_rejects_urls_signed_webhook_would_refuse() {
        let temp = TempDir::new().unwrap();
        let secret = b"0123456789abcdef".to_vec();
        let cases: Vec<(String, &str, &str)> = vec![
            (
                "https://user:pass@hooks.example/hooray".into(),
                "credentials",
                "user:pass",
            ),
            (
                "https://hooks.example/hooray#section".into(),
                "fragment",
                "#section",
            ),
            (
                format!("https://hooks.example/{}", "a".repeat(2100)),
                "too long",
                "",
            ),
        ];
        for (url, needle, forbidden) in cases {
            let error = WebhookNotifier::new(&config(&temp), &url, secret.clone())
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{url}: {error}");
            if !forbidden.is_empty() {
                assert!(!error.contains(forbidden), "{error}");
            }
        }
    }

    #[test]
    fn webhook_notifier_signs_alert_events_with_integration_scheme() {
        use hooray::monitor::{AlertPayload, FindingDiff};

        let temp = TempDir::new().unwrap();
        let secret = b"0123456789abcdef0123456789abcdef".to_vec();
        let notifier = WebhookNotifier::new(
            &config(&temp),
            "https://hooks.example/hooray",
            secret.clone(),
        )
        .unwrap();
        let event = AlertEvent {
            id: "event-1".into(),
            dedupe_key: "dedupe-1".into(),
            target_id: "target".into(),
            payload: AlertPayload {
                target_id: "target".into(),
                evaluated_at: 1,
                source_fingerprint: "fp".into(),
                advisory_digest: "ad".into(),
                policy_digest: "pd".into(),
                diff: FindingDiff {
                    introduced: vec![],
                    resolved: vec![],
                    unchanged: vec![],
                },
            },
            created_at: 1,
            attempts: 0,
            next_attempt_at: 1,
            delivered_at: None,
            dead_lettered_at: None,
            last_error: None,
        };
        let signed = notifier.signed_request(&event).unwrap();
        assert_eq!(signed.headers["content-type"], "application/json");
        assert_eq!(signed.headers["x-hooray-event"], "alert");
        let signature = &signed.headers["x-hooray-signature-256"];
        let generator = IntegrationGenerator::new(IntegrationLimits::default()).unwrap();
        assert!(generator.verify_webhook_signature(&secret, "alert", &signed.body, signature));
        let decoded: Value = serde_json::from_slice(&signed.body).unwrap();
        assert_eq!(decoded["id"], "event-1");
        assert_eq!(decoded["payload"]["target_id"], "target");
    }

    #[tokio::test]
    async fn webhook_notifier_surfaces_unreachable_endpoints_as_errors() {
        use hooray::monitor::{AlertPayload, FindingDiff};

        let temp = TempDir::new().unwrap();
        let notifier = WebhookNotifier::new(
            &config(&temp),
            "https://127.0.0.1:9/hook",
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let event = AlertEvent {
            id: "event-1".into(),
            dedupe_key: "dedupe-1".into(),
            target_id: "target".into(),
            payload: AlertPayload {
                target_id: "target".into(),
                evaluated_at: 1,
                source_fingerprint: "fp".into(),
                advisory_digest: "ad".into(),
                policy_digest: "pd".into(),
                diff: FindingDiff {
                    introduced: vec![],
                    resolved: vec![],
                    unchanged: vec![],
                },
            },
            created_at: 1,
            attempts: 0,
            next_attempt_at: 1,
            delivered_at: None,
            dead_lettered_at: None,
            last_error: None,
        };
        let result = notifier.notify(&event).await;
        assert!(result.is_err());
    }

    #[test]
    fn monitor_targets_add_list_remove_round_trip_with_clean_failures() {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let add = |id: &str| MonitorTargetsArgs {
            command: MonitorTargetsCommand::Add(MonitorTargetAddArgs {
                target_id: id.into(),
                source: "repo".into(),
                interval_seconds: 60,
            }),
        };
        run_monitor_targets(&config, add("zeta")).unwrap();
        run_monitor_targets(&config, add("alpha")).unwrap();

        let listed = temp.path().join("targets.json");
        run_monitor_targets(
            &config,
            MonitorTargetsArgs {
                command: MonitorTargetsCommand::List(MonitorTargetsListArgs {
                    limit: 10,
                    offset: 0,
                    output: output(listed.clone(), OutputFormat::Json),
                }),
            },
        )
        .unwrap();
        let values: Value = serde_json::from_slice(&std::fs::read(&listed).unwrap()).unwrap();
        let rows = values.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["target_id"], "alpha");
        assert_eq!(rows[0]["source"], "repo");
        assert_eq!(rows[0]["interval_seconds"], 60);
        assert_eq!(rows[0]["finding_ids"], json!([]));
        assert_eq!(rows[0]["next_due_at"].as_str().unwrap().len(), 20);

        let duplicate = run_monitor_targets(&config, add("zeta")).unwrap_err();
        assert!(duplicate.to_string().contains("already exists"));

        let table = temp.path().join("targets.txt");
        run_monitor_targets(
            &config,
            MonitorTargetsArgs {
                command: MonitorTargetsCommand::List(MonitorTargetsListArgs {
                    limit: 10,
                    offset: 0,
                    output: output(table.clone(), OutputFormat::Table),
                }),
            },
        )
        .unwrap();
        let rendered = std::fs::read_to_string(&table).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "TARGET_ID  SOURCE  INTERVAL_SECONDS  NEXT_DUE_AT           UPDATED_AT"
        );
        // Encoded timestamps are 20 characters wide and widen the column.
        assert!(lines[1].contains("  60  ") && lines[2].contains("  60  "));
        assert!(lines[1].starts_with("alpha") && lines[2].starts_with("zeta"));

        let remove = |id: &str| MonitorTargetsArgs {
            command: MonitorTargetsCommand::Remove(MonitorTargetRemoveArgs {
                target_id: id.into(),
            }),
        };
        run_monitor_targets(&config, remove("alpha")).unwrap();
        let missing = run_monitor_targets(&config, remove("alpha")).unwrap_err();
        assert!(missing.to_string().contains("was not found"));

        let empty = temp.path().join("empty.json");
        run_monitor_targets(&config, remove("zeta")).unwrap();
        run_monitor_targets(
            &config,
            MonitorTargetsArgs {
                command: MonitorTargetsCommand::List(MonitorTargetsListArgs {
                    limit: 10,
                    offset: 0,
                    output: output(empty.clone(), OutputFormat::Json),
                }),
            },
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&empty).unwrap()).unwrap(),
            json!([])
        );
    }

    #[test]
    fn monitor_targets_table_renders_empty_state_and_deterministic_rows() {
        let empty = render_monitor_targets_table(&[]);
        assert_eq!(
            empty,
            "TARGET_ID  SOURCE  INTERVAL_SECONDS  NEXT_DUE_AT  UPDATED_AT\n"
        );
        let targets = vec![
            MonitorTarget {
                target_id: "a".into(),
                source: "repo".into(),
                interval_seconds: 60,
                next_due_at: "d1".into(),
                source_fingerprint: None,
                inventory: None,
                advisory_digest: None,
                policy_digest: None,
                finding_ids: Vec::new(),
                updated_at: "u1".into(),
            },
            MonitorTarget {
                target_id: "longer-id".into(),
                source: "oci".into(),
                interval_seconds: 3600,
                next_due_at: "d2".into(),
                source_fingerprint: None,
                inventory: None,
                advisory_digest: None,
                policy_digest: None,
                finding_ids: Vec::new(),
                updated_at: "u2".into(),
            },
        ];
        let rendered = render_monitor_targets_table(&targets);
        assert_eq!(rendered, render_monitor_targets_table(&targets));
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "TARGET_ID  SOURCE  INTERVAL_SECONDS  NEXT_DUE_AT  UPDATED_AT"
        );
        assert_eq!(
            lines[1],
            "a          repo    60                d1           u1"
        );
        for line in lines.iter().skip(1) {
            assert!(!line.ends_with(' '), "no trailing padding: {line}");
        }
    }

    #[test]
    fn monitor_targets_table_replaces_control_characters_in_cells() {
        let targets = vec![MonitorTarget {
            target_id: "id\u{1b}[31m".into(),
            source: "repo\ninjected".into(),
            interval_seconds: 60,
            next_due_at: "d\u{7}1".into(),
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: Vec::new(),
            updated_at: "u\t1".into(),
        }];
        let rendered = render_monitor_targets_table(&targets);
        assert!(
            rendered
                .chars()
                .filter(|character| character.is_control())
                .all(|character| character == '\n'),
            "control characters must not survive into table cells: {rendered:?}"
        );
        assert!(rendered.contains("id [31m"));
        assert!(rendered.contains("repo injected"));
        assert!(rendered.contains("d 1"));
        assert!(rendered.contains("u 1"));
    }
}
