mod model;
mod osv;
mod sbom;

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use model::Severity;
use osv::OsvClient;

#[derive(Debug, Parser)]
#[command(
    name = "hooray",
    version,
    about = "Fast CycloneDX vulnerability scanner powered by OSV"
)]
struct Cli {
    /// CycloneDX JSON SBOM to scan.
    input: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Exit with status 1 when a finding reaches this severity.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    fail_on: FailOn,

    /// OSV-compatible API base URL.
    #[arg(long, default_value = "https://api.osv.dev")]
    api_url: String,

    /// Maximum concurrent vulnerability detail requests.
    #[arg(long, default_value_t = 32, value_parser = parse_concurrency)]
    concurrency: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FailOn {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    fn threshold(self) -> Option<Severity> {
        match self {
            Self::None => None,
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
        }
    }
}

fn parse_concurrency(value: &str) -> Result<usize, String> {
    let concurrency = value
        .parse::<usize>()
        .map_err(|_| "concurrency must be a positive integer".to_owned())?;
    if concurrency == 0 {
        return Err("concurrency must be at least 1".to_owned());
    }
    Ok(concurrency)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let bytes = tokio::fs::read(&cli.input)
        .await
        .with_context(|| format!("failed to read {}", cli.input.display()))?;
    let components = sbom::parse_cyclonedx(&bytes)
        .with_context(|| format!("failed to parse {}", cli.input.display()))?;

    let client = OsvClient::new(&cli.api_url, cli.concurrency)?;
    let findings = client.scan(&components).await?;

    match cli.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
        OutputFormat::Table => print_table(&findings),
    }

    let failed = cli
        .fail_on
        .threshold()
        .is_some_and(|threshold| findings.iter().any(|finding| finding.severity >= threshold));

    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_table(findings: &[model::Finding]) {
    if findings.is_empty() {
        println!("No known vulnerabilities found.");
        return;
    }

    println!("SEVERITY\tVULNERABILITY\tPACKAGE\tVERSION\tSUMMARY");
    for finding in findings {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            finding.severity,
            finding.id,
            finding.package_name,
            finding.package_version,
            finding
                .summary
                .as_deref()
                .unwrap_or("-")
                .replace(['\t', '\n'], " ")
        );
    }
    println!("\n{} finding(s)", findings.len());
}
