#![cfg(feature = "parity")]

use hooray::parity::{
    compare::scorecard,
    package_cve::PackageCveStatus,
    xray::{XrayArtifacts, build_xray_canonical},
};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

const CVE1: &str = "CVE-2026-1001";
const CVE2: &str = "CVE-2026-1002";

fn sbom() -> Value {
    json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
        {"name":"alpha","version":"1","purl":"pkg:cargo/alpha@1"},
        {"name":"alpha","version":"2","purl":"pkg:cargo/alpha@2"}]})
}

fn audit(a: &str, b: &str) -> Value {
    json!({"vulnerabilities":[
        {"issue_id":"XRAY-1","cves":[{"cve":CVE1}],"components":{a:{}}},
        {"issue_id":"XRAY-1","cves":[{"cve":CVE2}],"components":{b:{}}}]})
}

fn canonical(audit: Option<Value>, sbom: Option<Value>) -> hooray::parity::model::CanonicalReport {
    let audit = audit.map(|v| v.to_string());
    let sbom = sbom.map(|v| v.to_string());
    build_xray_canonical(
        "tiny",
        None,
        &XrayArtifacts {
            audit_json: audit.as_deref(),
            sbom_json: sbom.as_deref(),
        },
    )
    .unwrap()
    .0
}

#[test]
fn version_swaps_cannot_hide_behind_a_matching_inventory_and_cve_set() {
    let expected = canonical(Some(audit("alpha:1", "alpha:2")), Some(sbom()));
    let swapped = canonical(Some(audit("alpha:2", "alpha:1")), Some(sbom()));
    let card = scorecard(&swapped, &expected);
    assert_eq!((card.purl_recall, card.cve_jaccard), (1.0, 1.0));
    assert_eq!(card.package_cves.status, PackageCveStatus::Mismatch);
    assert_eq!(card.package_cves.matched, 0);
    assert_eq!(card.package_cves.missing_in_hooray.len(), 2);
    assert_eq!(
        card.package_cves.missing_in_hooray[0].purl,
        "pkg:cargo/alpha@1"
    );
    assert_eq!(card.package_cves.missing_in_hooray[0].cve, CVE1);
    assert_eq!(card.package_cves.extra_in_hooray[0].cve, CVE2);
}

#[test]
fn package_swaps_and_cve_aliases_are_measured_at_the_source() {
    let mut inventory = sbom();
    inventory["components"][1] = json!({"name":"beta","version":"1","purl":"pkg:cargo/beta@1"});
    let expected = canonical(Some(audit("alpha:1", "beta:1")), Some(inventory.clone()));
    let swapped = canonical(Some(audit("beta:1", "alpha:1")), Some(inventory.clone()));
    let card = scorecard(&swapped, &expected);
    assert_eq!((card.purl_recall, card.cve_jaccard), (1.0, 1.0));
    assert_eq!(card.package_cves.status, PackageCveStatus::Mismatch);
    let other_ids = json!({"vulnerabilities":[
        {"issue_id":"XRAY-99","aliases":[{"alias":"cve-2026-1002"}],"components":{"beta:1":{}}},
        {"issue_id":CVE1,"components":{"alpha:1":{}}},
        {"issue_id":"GHSA-non-cve","components":{"alpha:1":{}}}
    ]});
    let alternate = canonical(Some(other_ids), Some(inventory));
    let card = scorecard(&alternate, &expected);
    assert_eq!(card.package_cves.status, PackageCveStatus::Match);
    assert_eq!(card.package_cves.matched, 2);
}

#[test]
fn missing_ambiguous_and_unversioned_packages_are_unknown_not_equal() {
    let audit = audit("alpha:1", "alpha:2");
    let mut unversioned = sbom();
    unversioned["components"][0]["purl"] = json!("pkg:cargo/alpha");
    let mut ambiguous = sbom();
    ambiguous["components"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"alpha","version":"1","purl":"pkg:npm/alpha@1"}));
    let mut conflicting = sbom();
    conflicting["components"][0]["purl"] = json!("pkg:cargo/alpha@2");
    let mut placeholders = sbom();
    placeholders["components"][0] =
        json!({"name":"alpha","version":"unknown","purl":"pkg:cargo/alpha@unknown"});
    let mut variants = sbom();
    variants["components"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"alpha","version":"1","purl":"pkg:cargo/alpha@1?variant=2"}));
    let mut missing_ref = audit.clone();
    missing_ref["vulnerabilities"][0]["components"] = json!([{"name":"alpha","version":"1"},{}]);
    for report in [
        canonical(Some(audit.clone()), None),
        canonical(Some(audit.clone()), Some(unversioned)),
        canonical(Some(audit.clone()), Some(ambiguous)),
        canonical(Some(audit.clone()), Some(variants)),
        canonical(Some(audit.clone()), Some(conflicting)),
        canonical(
            Some(self::audit("alpha:unknown", "alpha:2")),
            Some(placeholders),
        ),
        canonical(Some(missing_ref), Some(sbom())),
        canonical(None, Some(sbom())),
        canonical(
            Some(json!({"vulnerabilities":[],"errors":["scan failed"]})),
            Some(sbom()),
        ),
        canonical(
            Some(json!({"vulnerabilities":[{"issue_id":"XRAY-1","cves":[{"bad_shape":CVE1}]}]})),
            Some(sbom()),
        ),
        canonical(
            Some(json!({"errors":["audit not available"]})),
            Some(sbom()),
        ),
    ] {
        let result = scorecard(&report, &report).package_cves;
        assert_eq!(result.status, PackageCveStatus::Indeterminate);
        assert!(!result.reasons.is_empty());
    }
    let expected = canonical(Some(audit), Some(sbom()));
    let mut offline = expected.clone();
    offline.scan_mode = "offline".into();
    assert_eq!(
        scorecard(&offline, &expected).package_cves.status,
        PackageCveStatus::Indeterminate
    );
    let mut incomplete = expected.clone();
    incomplete
        .package_cve_evidence
        .as_mut()
        .unwrap()
        .pairs
        .clear();
    let partial = scorecard(&incomplete, &expected).package_cves;
    assert_eq!(partial.status, PackageCveStatus::Indeterminate);
    assert!(partial.missing_in_hooray.is_empty());
    let negative = canonical(Some(json!({"vulnerabilities":[]})), Some(sbom()));
    assert_eq!(
        scorecard(&negative, &negative).package_cves.status,
        PackageCveStatus::Match
    );
}

fn check(corpus: &Path, recordings: &Path, strict: bool) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hooray-parity"));
    command
        .args(["check", "--corpus"])
        .arg(corpus)
        .arg("--recordings")
        .arg(recordings)
        .args(["--format", "json"]);
    if strict {
        command.arg("--require-package-cve-parity");
    }
    let out = command.output().unwrap();
    let status = out.status.code().unwrap();
    assert_ne!(status, 2, "{}", String::from_utf8_lossy(&out.stderr));
    (status, serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn package_gate_rejects_missing_legacy_and_mismatched_recordings_only_when_requested() {
    let root = tempfile::tempdir().unwrap();
    let corpus = root.path().join("corpus");
    let recordings = root.path().join("recordings");
    let case = corpus.join("tiny");
    fs::create_dir_all(&case).unwrap();
    fs::create_dir(&recordings).unwrap();
    fs::write(
        corpus.join("manifest.json"),
        json!({"cases":[{"case_id":"tiny","kind":"cyclonedx-sbom","min_components":2}]})
            .to_string(),
    )
    .unwrap();
    let sbom_path = case.join("tiny.cdx.json");
    fs::write(&sbom_path, sbom().to_string()).unwrap();
    let path = recordings.join("tiny.recording.json");
    assert_eq!(check(&corpus, &recordings, true).0, 1);
    let captured = Command::new(env!("CARGO_BIN_EXE_hooray-parity"))
        .args(["record", "--offline", "--case"])
        .arg(&case)
        .arg("--xray-sbom")
        .arg(&sbom_path)
        .arg("--out")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        captured.status.success(),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    let mut rec: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(check(&corpus, &recordings, false).0, 0);
    let (code, rows) = check(&corpus, &recordings, true);
    assert_eq!(code, 1);
    assert_eq!(
        rows[0]["scorecard"]["package_cves"]["status"],
        "indeterminate"
    );
    // Model an explicitly labelled synthetic provider replay; leave the
    // Hooray inventory from the offline scan intact for the drift guard.
    let x =
        serde_json::to_value(canonical(Some(audit("alpha:1", "alpha:2")), Some(sbom()))).unwrap();
    rec["xray"] = x;
    rec["hooray"]["scan_mode"] = json!("provider-replay");
    rec["hooray"]["vulnerabilities"] = rec["xray"]["vulnerabilities"].clone();
    rec["hooray"]["package_cve_evidence"] = rec["xray"]["package_cve_evidence"].clone();
    fs::write(&path, rec.to_string()).unwrap();
    assert_eq!(check(&corpus, &recordings, true).0, 0);
    rec["hooray"]["package_cve_evidence"]["pairs"][0]["purl"] = json!("pkg:cargo/alpha@2");
    fs::write(&path, rec.to_string()).unwrap();
    assert_eq!(check(&corpus, &recordings, false).0, 0);
    let (code, rows) = check(&corpus, &recordings, true);
    assert_eq!(code, 1);
    assert_eq!(rows[0]["scorecard"]["cve_jaccard"], 1.0);
    assert_eq!(rows[0]["scorecard"]["package_cves"]["status"], "mismatch");
    rec["hooray"]
        .as_object_mut()
        .unwrap()
        .remove("package_cve_evidence");
    fs::write(&path, rec.to_string()).unwrap();
    assert_eq!(
        check(&corpus, &recordings, true).1[0]["scorecard"]["package_cves"]["status"],
        "indeterminate"
    );
}
