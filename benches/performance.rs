use std::{
    collections::BTreeSet,
    hint::black_box,
    time::{Duration, Instant},
};

use hooray::{
    graph::DependencyGraph,
    model::{AssetId, ComponentId, DependencyEdge, PackageEcosystem, Scope},
    remediation::nearest_fixed_version,
    scanners::{MalwareSignatures, ScannerConfig, analyze_bytes},
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
}
