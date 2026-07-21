use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    time::{Duration, Instant},
};

use hooray::{
    analysis::{
        ApplicabilityAnalyzer, ApplicabilityInput, OsvAffectedRange, OsvEvent, OsvRangeType,
    },
    graph::DependencyGraph,
    model::{
        Asset, AssetId, AssetKind, Component, ComponentId, Confidence, DependencyEdge, Evidence,
        Finding, FindingId, FindingKind, FindingStatus, Inventory, PackageEcosystem, PolicySummary,
        RuleId, RunId, RunMetadata, ScanReport, Scope, Severity,
    },
    remediation::nearest_fixed_version,
    report::{ReportFormat, render},
    scanners::{MalwareSignatures, ScannerConfig, analyze_bytes},
    store::Store,
};

const SAMPLE_TIME: Duration = Duration::from_millis(750);

fn component_id(value: impl Into<String>) -> ComponentId {
    ComponentId::new(value.into()).expect("benchmark component id")
}

fn edge(from: &ComponentId, to: &ComponentId) -> DependencyEdge {
    DependencyEdge {
        from: from.clone(),
        to: to.clone(),
        scope: Scope::Runtime,
        optional: false,
    }
}

fn measure(mut operation: impl FnMut()) -> (u64, Duration) {
    for _ in 0..3 {
        operation();
    }
    let started = Instant::now();
    let mut iterations = 0_u64;
    while started.elapsed() < SAMPLE_TIME {
        operation();
        iterations += 1;
    }
    (iterations, started.elapsed())
}

fn report(name: &str, iterations: u64, elapsed: Duration) {
    let nanos = elapsed.as_nanos() as f64 / iterations as f64;
    println!("{name}\t{nanos:.0} ns/iter\t{iterations} iterations");
}

fn graph_fixture() -> (DependencyGraph, Vec<ComponentId>, ComponentId) {
    const LAYERS: usize = 18;
    const WIDTH: usize = 6;
    let root = component_id("root");
    let target = component_id("target");
    let layers: Vec<Vec<ComponentId>> = (0..LAYERS)
        .map(|layer| {
            (0..WIDTH)
                .map(|column| component_id(format!("layer-{layer:02}-{column:02}")))
                .collect()
        })
        .collect();
    let mut nodes = BTreeSet::from([root.clone(), target.clone()]);
    nodes.extend(layers.iter().flatten().cloned());
    let mut edges = BTreeSet::new();
    for node in &layers[0] {
        edges.insert(edge(&root, node));
    }
    for adjacent in layers.windows(2) {
        for from in &adjacent[0] {
            for to in &adjacent[1] {
                edges.insert(edge(from, to));
            }
        }
    }
    for node in layers.last().expect("layers") {
        edges.insert(edge(node, &target));
    }
    let graph = DependencyGraph::new(nodes, &edges).expect("acyclic fixture");
    let components = layers.into_iter().flatten().collect();
    (graph, components, target)
}

fn scanner_fixture() -> String {
    let mut source = String::with_capacity(512 * 1024);
    for index in 0..8_000 {
        source.push_str("fn handler(input: &str) {\n");
        source.push_str("    let query = format!(\"SELECT * FROM users WHERE id = {}\", input);\n");
        source.push_str("    std::process::Command::new(\"sh\").arg(\"-c\").arg(input);\n");
        source.push_str(&format!(
            "    let safe_{index} = \"ordinary source text\";\n"
        ));
        source.push_str("}\n");
    }
    source
}

fn remediation_fixture() -> Vec<String> {
    (0..5_000)
        .map(|patch| format!("2.{}.{}", patch / 100, patch % 100))
        .chain((0..5_000).map(|patch| format!("3.{}.{}", patch / 100, patch % 100)))
        .rev()
        .collect()
}

fn report_fixture(component_count: usize, findings_per_component: usize) -> ScanReport {
    let asset_id = AssetId::new("asset:performance").expect("asset id");
    let root_id = component_id("component:root");
    let mut components = BTreeMap::new();
    components.insert(
        root_id.clone(),
        Component {
            identity: root_id.clone(),
            name: "benchmark-root".into(),
            version: "1.0.0".into(),
            purl: "pkg:cargo/benchmark-root@1.0.0".into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        },
    );
    let mut dependencies = BTreeSet::new();
    let mut findings = BTreeMap::new();
    let mut parent = root_id;
    for index in 0..component_count {
        let component_id = component_id(format!("component:benchmark-{index:04}"));
        components.insert(
            component_id.clone(),
            Component {
                identity: component_id.clone(),
                name: format!("benchmark-{index:04}"),
                version: "1.2.3".into(),
                purl: format!("pkg:cargo/benchmark-{index:04}@1.2.3"),
                scope: Scope::Runtime,
                provenance: BTreeSet::new(),
                licenses: BTreeSet::new(),
                locations: BTreeSet::new(),
            },
        );
        dependencies.insert(edge(&parent, &component_id));
        parent = component_id.clone();
        for finding_index in 0..findings_per_component {
            let id = FindingId::new(format!("finding:benchmark-{index:04}-{finding_index:02}"))
                .expect("finding id");
            let finding = Finding {
                id: id.clone(),
                kind: FindingKind::Sast,
                rule_id: RuleId::new("sast.benchmark").expect("rule id"),
                advisory_id: None,
                component_id: Some(component_id.clone()),
                location_id: None,
                aliases: BTreeSet::new(),
                summary: Some("Synthetic benchmark finding".into()),
                details: Some("Representative report and persistence payload".into()),
                severity: Severity::High,
                confidence: Confidence::High,
                evidence: BTreeSet::from([Evidence {
                    description: "Synthetic redacted benchmark evidence".into(),
                    locations: BTreeSet::new(),
                    references: BTreeSet::new(),
                    properties: BTreeMap::from([(
                        "benchmark.category".into(),
                        "performance".into(),
                    )]),
                    redacted: true,
                }]),
                applicability: None,
                remediation: None,
                risk: None,
                first_seen: None,
                last_seen: None,
                modified: None,
                status: FindingStatus::Open,
            };
            findings.insert(id, finding);
        }
    }
    ScanReport {
        schema_version: "1".into(),
        run: RunMetadata {
            id: RunId::new("run:performance").expect("run id"),
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:00:01Z".into()),
            scanner_version: Some("benchmark".into()),
            metadata: BTreeMap::new(),
        },
        inventory: Inventory {
            asset: Asset {
                id: asset_id,
                name: "performance".into(),
                kind: AssetKind::Repository,
                version: Some("1.0.0".into()),
                metadata: BTreeMap::new(),
            },
            components,
            dependencies,
        },
        findings,
        policy_decisions: BTreeSet::new(),
        policy_summary: PolicySummary::default(),
    }
}

fn affected_ranges_fixture() -> Vec<OsvAffectedRange> {
    (0..200)
        .map(|range| OsvAffectedRange {
            range_type: OsvRangeType::Semver,
            ecosystem: Some("cargo".into()),
            events: (0..10)
                .flat_map(|interval| {
                    let introduced = format!("{}.{}.0", range + 1, interval * 2);
                    let fixed = format!("{}.{}.0", range + 1, interval * 2 + 1);
                    [
                        OsvEvent {
                            introduced: Some(introduced),
                            ..OsvEvent::default()
                        },
                        OsvEvent {
                            fixed: Some(fixed),
                            ..OsvEvent::default()
                        },
                    ]
                })
                .collect(),
        })
        .collect()
}

fn main() {
    let (graph, components, target) = graph_fixture();
    let (iterations, elapsed) = measure(|| {
        for component in &components {
            black_box(
                graph
                    .classify(black_box(component))
                    .expect("classification"),
            );
        }
    });
    report("graph_classify_108", iterations, elapsed);

    let (iterations, elapsed) = measure(|| {
        black_box(
            graph
                .all_paths(black_box(&target), 128, 32)
                .expect("bounded paths"),
        );
    });
    report("graph_all_paths_dense", iterations, elapsed);

    let source = scanner_fixture();
    let asset = AssetId::new("asset:benchmark").expect("asset id");
    let scanner_config = ScannerConfig::default();
    let signatures = MalwareSignatures::default();
    let (iterations, elapsed) = measure(|| {
        black_box(analyze_bytes(
            "src/benchmark.rs",
            black_box(source.as_bytes()),
            &asset,
            &scanner_config,
            &signatures,
        ));
    });
    report("scanner_rust_1mb", iterations, elapsed);

    let versions = remediation_fixture();
    let (iterations, elapsed) = measure(|| {
        black_box(nearest_fixed_version(
            PackageEcosystem::Cargo,
            "2.10.50",
            versions.iter().map(String::as_str),
        ));
    });
    report("nearest_fixed_10000", iterations, elapsed);

    let analysis_component = Component {
        identity: component_id("component:analysis"),
        name: "analysis".into(),
        version: "100.10.5".into(),
        purl: "pkg:cargo/analysis@100.10.5".into(),
        scope: Scope::Runtime,
        provenance: BTreeSet::new(),
        licenses: BTreeSet::new(),
        locations: BTreeSet::new(),
    };
    let ranges = affected_ranges_fixture();
    let evidence = BTreeSet::new();
    let (iterations, elapsed) = measure(|| {
        black_box(ApplicabilityAnalyzer::analyze(ApplicabilityInput {
            component: black_box(&analysis_component),
            inventory: None,
            evidence: &evidence,
            affected_ranges: black_box(&ranges),
        }));
    });
    report("applicability_4000_events", iterations, elapsed);

    let large_report = report_fixture(250, 2);
    let (iterations, elapsed) = measure(|| {
        black_box(render(black_box(&large_report), ReportFormat::Sarif).expect("SARIF report"));
    });
    report("report_sarif_500", iterations, elapsed);

    for (name, format) in [
        ("report_table_500", ReportFormat::Table),
        ("report_junit_500", ReportFormat::Junit),
        ("report_html_500", ReportFormat::Html),
        ("report_cdx_500", ReportFormat::CycloneDxVex),
        ("report_spdx_500", ReportFormat::Spdx),
        ("report_gitlab_500", ReportFormat::GitLabCodeQuality),
        ("report_jsonl_500", ReportFormat::JsonLines),
    ] {
        let (iterations, elapsed) = measure(|| {
            black_box(render(black_box(&large_report), format).expect("report"));
        });
        report(name, iterations, elapsed);
    }

    let (iterations, elapsed) = measure(|| {
        let mut store = Store::open_memory().expect("memory store");
        store
            .save_report(black_box(&large_report))
            .expect("save report");
        black_box(store);
    });
    report("store_save_250_500", iterations, elapsed);
}
