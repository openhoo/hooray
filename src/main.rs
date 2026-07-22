use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use hooray::{
    config::Config,
    engine::{Engine, ScanRequest, load_policy},
    input::ScanInput,
    integrations::{IntegrationGenerator, IntegrationLimits},
    model::{FindingId, RunId, ScanReport},
    monitor::{
        AdvisoryCursor, AdvisoryRefresh, AlertEvent, Evaluation, MonitorConfig, MonitorError,
        MonitorFuture, MonitorRunner, MonitorService, Notifier, SystemClock,
    },
    report::{self, ReportFormat},
    store::{ReportDiff, Store},
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
    let mut store = Store::open(&config.database_path)
        .with_context(|| format!("failed to open {}", config.database_path.display()))?;
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
            write_output(&SerializableDiff::from(&diff), &args.output)?;
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
    let store = Store::open(&config.database_path)?;
    let state =
        hooray::api::ApiState::new(store, config.clone()).context("failed to initialize API")?;
    hooray::api::serve(config.api_bind, state, hooray::api::shutdown_signal()).await?;
    Ok(CommandOutcome::Passed)
}

async fn run_monitor(config: &Config, args: MonitorArgs) -> Result<CommandOutcome> {
    let store = open_store(config)?;
    let runner = Arc::new(CliMonitorRunner {
        config: config.clone(),
    });
    let notifier = Arc::new(StderrNotifier);
    let mut service = MonitorService::new(
        store,
        Arc::new(SystemClock),
        runner,
        notifier,
        MonitorConfig::default(),
    )?;
    if args.once {
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
            let digest = stable_digest(format!("osv-periodic-refresh-v1:{token}").as_bytes());
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
        let bytes = std::fs::read(&self.config.policy_path)
            .map_err(|error| MonitorError::Runner(error.to_string()))?;
        if bytes.len() as u64 > self.config.max_input_bytes {
            return Err(MonitorError::Runner(
                "policy exceeds configured input bound".into(),
            ));
        }
        Ok(stable_digest(&bytes))
    }

    fn source_fingerprint<'a>(
        &'a self,
        target: &'a hooray::monitor::MonitorTarget,
    ) -> MonitorFuture<'a, Result<String, MonitorError>> {
        Box::pin(async move {
            use sha2::{Digest, Sha256};
            use walkdir::WalkDir;

            let root = Path::new(&target.source);
            let metadata = std::fs::symlink_metadata(root)
                .map_err(|error| MonitorError::Runner(error.to_string()))?;
            let mut paths = if metadata.is_file() {
                vec![root.to_owned()]
            } else {
                WalkDir::new(root)
                    .follow_links(false)
                    .sort_by_file_name()
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_type().is_file())
                    .take(self.config.max_archive_entries)
                    .map(|entry| entry.into_path())
                    .collect::<Vec<_>>()
            };
            paths.sort();
            let mut digest = Sha256::new();
            let mut total = 0_u64;
            for path in paths {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                digest.update(relative.as_os_str().as_encoded_bytes());
                let bytes = std::fs::read(&path)
                    .map_err(|error| MonitorError::Runner(error.to_string()))?;
                total = total.saturating_add(bytes.len() as u64);
                if total > self.config.max_input_bytes {
                    return Err(MonitorError::Runner(
                        "source fingerprint exceeds configured input bound".into(),
                    ));
                }
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            Ok(format!("{:x}", digest.finalize()))
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

fn stable_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
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
    if args.output == Path::new("-") {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        match args.format {
            OutputFormat::Json => serde_json::to_writer_pretty(&mut writer, value)?,
            OutputFormat::Yaml => serde_yaml::to_writer(&mut writer, value)?,
            _ => unreachable!("format checked above"),
        }
        writer.write_all(b"\n")?;
        writer.flush()?;
    } else {
        let mut writer = File::create(&args.output)
            .with_context(|| format!("failed to create {}", args.output.display()))?;
        match args.format {
            OutputFormat::Json => serde_json::to_writer_pretty(&mut writer, value)?,
            OutputFormat::Yaml => serde_yaml::to_writer(&mut writer, value)?,
            _ => unreachable!("format checked above"),
        }
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn write_bytes(bytes: &[u8], path: &Path) -> Result<()> {
    if path == Path::new("-") {
        io::stdout().lock().write_all(bytes)?;
    } else {
        std::fs::write(path, bytes)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
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

#[derive(Serialize)]
struct SerializableDiff<'a> {
    introduced: &'a [FindingId],
    resolved: &'a [FindingId],
    unchanged: &'a [FindingId],
}
impl<'a> From<&'a ReportDiff> for SerializableDiff<'a> {
    fn from(diff: &'a ReportDiff) -> Self {
        Self {
            introduced: &diff.introduced,
            resolved: &diff.resolved,
            unchanged: &diff.unchanged,
        }
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
            (IntegrationKind::GithubActions, "upload-sarif@v3"),
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
}
