//! Ingest robustness guard: feeds truncated and byte-corrupted variants of
//! every committed fixture through the public offline pipeline (detect ->
//! scan -> JSON render). Any panic is a defect; typed Err results are the
//! documented fail-closed contract and are counted, not treated as failures.
//! Pristine fixtures act as positive controls proving the harness path runs
//! end to end.
//! Project files fall back to directory detection (scan project semantics).

use hooray::config::Config;
use hooray::engine::{Engine, ScanRequest};
use hooray::input::ScanInput;
use hooray::model::RunId;
use hooray::report::{ReportFormat, render_to_string};
use hooray::store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

fn mutations(bytes: &[u8], seed: u64) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if bytes.len() > 20 {
        for pct in [5usize, 25, 45, 65, 85] {
            let cut = bytes.len() * pct / 100;
            out.push((format!("trunc{pct}"), bytes[..cut].to_vec()));
        }
    }
    let mut state = seed | 1;
    for index in 0..3 {
        if bytes.is_empty() {
            break;
        }
        let position = (lcg(&mut state) as usize) % bytes.len();
        let mut copy = bytes.to_vec();
        copy[position] ^= 0xff;
        out.push((format!("flip{index}@{position}"), copy));
    }
    out
}

fn walkdir_sorted(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(entries) => entries.filter_map(|e| e.ok()).collect(),
            Err(_) => return,
        };
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// Runs one scan. `file` first (SBOM/zip/artifact shapes), then `dir`
/// fallback (project lockfile semantics), matching documented CLI behavior.
fn run_case(file: &Path, dir: Option<&Path>, policy: &Path) -> String {
    let stage = run_case_inner(file, policy);
    if stage != "rejected-at-detect" {
        return stage;
    }
    match dir {
        Some(dir) => run_case_inner(dir, policy),
        None => stage,
    }
}

fn run_case_inner(path: &Path, policy: &Path) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let config = Config {
            offline: true,
            ..Config::default()
        };
        let input = match ScanInput::detect(path, &config) {
            Ok(input) => input,
            Err(_) => return "rejected-at-detect".to_string(),
        };
        let mut store = Store::open_memory().expect("memory store");
        let mut engine = Engine::new(&config, &mut store, None);
        let mut request = ScanRequest::new(input, policy.to_path_buf());
        request.run_id = Some(RunId::new("run:probe").expect("run id"));
        let report = match engine.scan(request).await {
            Ok(report) => report,
            Err(_) => return "rejected-at-scan".to_string(),
        };
        let rendered = match render_to_string(&report, ReportFormat::Json) {
            Ok(rendered) => rendered,
            Err(_) => return "rejected-at-render".to_string(),
        };
        assert!(!rendered.is_empty());
        "accepted".to_string()
    })
}

#[test]
fn no_pipeline_panics_on_mutated_fixtures() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_root = Path::new(manifest_dir).join("tests/fixtures");
    let policy = Path::new(manifest_dir).join("tests/fixtures/parity/policy/minimal-policy.yaml");

    let mut sources = walkdir_sorted(&fixtures_root);
    sources.truncate(60);

    let mut executed = 0u32;
    let mut control_accepted = 0u32;
    let mut panics: Vec<String> = Vec::new();
    let mut stages: BTreeMap<String, u32> = BTreeMap::new();

    // Positive controls: pristine fixtures must reach the pipeline.
    for source in &sources {
        executed += 1;
        let dir = source.parent();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_case(source, dir, &policy)
        }));
        match &outcome {
            Ok(stage) if stage == "accepted" => control_accepted += 1,
            Ok(stage) => *stages.entry(format!("control:{stage}")).or_default() += 1,
            Err(_) => *stages.entry("control:PANIC".to_string()).or_default() += 1,
        }
        if let Err(ref panic) = outcome {
            let detail = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic".into());
            panics.push(format!("{source:?}/orig: PANIC {detail}"));
        }
    }

    // Mutation pass: corrupted variants must never panic.
    for source in &sources {
        let bytes = match std::fs::read(source) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let extension = source
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("txt")
            .to_string();
        let stem = source
            .file_stem()
            .and_then(|e| e.to_str())
            .unwrap_or("f")
            .to_string();

        for (label, mutated) in mutations(&bytes, stem.len() as u64 + 7) {
            executed += 1;
            let case_dir = tempfile::tempdir().unwrap();
            let case_path = case_dir.path().join(format!("{stem}.{extension}"));
            std::fs::write(&case_path, &mutated).unwrap();

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_case(&case_path, Some(case_dir.path()), &policy)
            }));

            let stage = match &outcome {
                Ok(stage) => stage.clone(),
                Err(_) => "panic".to_string(),
            };
            *stages.entry(stage).or_default() += 1;
            if let Err(ref panic) = outcome {
                let detail = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "non-string panic".into());
                panics.push(format!("{source:?}/{label}: PANIC {detail}"));
            }
        }
    }

    println!("mutation probe: {executed} cases, stages {stages:?}");
    assert!(executed >= 150, "probe iterated only {executed} cases");
    assert!(
        control_accepted >= 5,
        "only {control_accepted} pristine fixtures scanned - harness broken"
    );
    assert!(
        panics.is_empty(),
        "pipeline defects on mutated input:\n{}",
        panics.join("\n")
    );
}

/// Structure-aware mutations: parse each structured fixture into a `Value`
/// tree, apply seeded grammar-level damage (missing keys, wrong scalar types,
/// values wrapped in the wrong container), re-serialize, and run the pipeline.
/// Byte flips mostly break syntax early; these reach deep parser paths.
#[test]
fn no_pipeline_panics_on_structure_aware_mutations() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_root = Path::new(manifest_dir).join("tests/fixtures");
    let policy = Path::new(manifest_dir).join("tests/fixtures/parity/policy/minimal-policy.yaml");

    let sources: Vec<PathBuf> = walkdir_sorted(&fixtures_root)
        .into_iter()
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("json") | Some("yaml") | Some("yml") | Some("toml")
            )
        })
        .collect();
    assert!(!sources.is_empty(), "no structured fixtures found");

    let mut executed = 0u32;
    let mut accepted = 0u32;
    let mut panics: Vec<String> = Vec::new();

    for source in &sources {
        let raw = match std::fs::read_to_string(source) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let extension = source.extension().and_then(|e| e.to_str()).unwrap_or("");
        let stem = source
            .file_stem()
            .and_then(|e| e.to_str())
            .unwrap_or("f")
            .to_string();

        // Parse to the native Value tree; unparseable fixtures have no deep
        // grammar to attack and are already covered by the byte-flip guard.
        let base = match extension {
            "json" => serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .map(|v| v.to_string()),
            _ => serde_yaml::from_str::<serde_yaml::Value>(&raw)
                .ok()
                .and_then(|v| serde_yaml::to_string(&v).ok())
                .or_else(|| raw.parse::<toml::Table>().ok().map(|v| v.to_string())),
        };
        let Some(base) = base else {
            continue;
        };

        let mut state = stem.len() as u64 | 1;
        for round in 0..6 {
            let mutated = if extension == "json" {
                mutate_json(&base, &mut state)
            } else {
                mutate_lines(&base, &mut state, round)
            };
            executed += 1;
            let case_dir = tempfile::tempdir().unwrap();
            let case_path = case_dir.path().join(format!("{stem}.{extension}"));
            std::fs::write(&case_path, &mutated).unwrap();

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_case(&case_path, Some(case_dir.path()), &policy)
            }));

            match &outcome {
                Ok(stage) if stage == "accepted" => accepted += 1,
                Ok(_) => {}
                Err(panic) => {
                    let detail = panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "non-string panic".into());
                    panics.push(format!("{source:?}/struct{round}: PANIC {detail}"));
                }
            }
        }
    }

    println!("structure-aware probe: {executed} cases, {accepted} accepted");
    assert!(executed >= 40, "probe iterated only {executed} cases");
    assert!(
        panics.is_empty(),
        "pipeline defects on structure-mutated input:\n{}",
        panics.join("\n")
    );
}

fn mutate_json(base: &str, state: &mut u64) -> String {
    let mut value: serde_json::Value = serde_json::from_str(base).expect("base parses");
    damage_json(&mut value, state);
    value.to_string()
}

fn damage_json(value: &mut serde_json::Value, state: &mut u64) {
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            if keys.is_empty() {
                return;
            }
            let key = keys[(lcg(state) as usize) % keys.len()].clone();
            match lcg(state) % 4 {
                0 => {
                    map.remove(&key);
                }
                1 => {
                    if let Some(entry) = map.get_mut(&key) {
                        damage_json(entry, state);
                    }
                }
                2 => {
                    map.insert(
                        key.clone(),
                        serde_json::Value::Bool(lcg(state).is_multiple_of(2)),
                    );
                }
                _ => {
                    if let Some(entry) = map.get_mut(&key) {
                        *entry = serde_json::Value::Array(vec![entry.take()]);
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            if let Some(first) = items.first_mut() {
                damage_json(first, state);
            }
        }
        _ => {}
    }
}

fn mutate_lines(base: &str, state: &mut u64, round: usize) -> String {
    // YAML/TOML share line-oriented damage here: drop a key's value, append
    // a stray token, or duplicate a line - each a realistic hand-edit shape.
    let mut lines: Vec<String> = base.lines().map(str::to_owned).collect();
    let candidates: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (!line.trim_start().starts_with('#') && !line.trim().is_empty()).then_some(index)
        })
        .collect();
    if !candidates.is_empty() {
        let pick = candidates[(lcg(state) as usize) % candidates.len()];
        match round % 3 {
            0 => lines[pick] = lines[pick].trim_end_matches(':').to_string() + ":",
            1 => lines[pick] = format!("{} extra", lines[pick]),
            _ => lines.insert(pick, lines[pick].clone()),
        }
    }
    lines.join("\n")
}
