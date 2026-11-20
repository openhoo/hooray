//! Real regression coordinates from the November 20 ZIP maintainer comparison.
//! Advisory IDs, package metadata and ranges only; no vulnerable fixtures.
use hooray::model::{
    Asset, AssetId, AssetKind, Component, Finding, FindingId, FindingKind, Inventory, RuleId,
    Scope, Severity, stable_component_id, stable_finding_id,
};
use hooray::publisher::{PublisherCoverage as Coverage, augment, classify, metadata};
use std::collections::{BTreeMap, BTreeSet};

const MISSING: &str = "GHSA-2582-27w5-xw4j GHSA-2fwm-pm8w-697g GHSA-2qf6-h4q7-hxf8 GHSA-2vxq-ffpp-66cq GHSA-4963-ggxm-v64x GHSA-5qh5-c9fp-66jm GHSA-66qv-gmq4-qcqj GHSA-6pf3-pgfg-wg27 GHSA-7r34-rm5p-4wjv GHSA-83cq-wjh8-gm47 GHSA-8p9w-4prr-vvqh GHSA-9fw6-6jvx-cj63 GHSA-c9rm-qm35-rhqf GHSA-cm63-4mhh-887h GHSA-f6gf-fx5m-vx4x GHSA-gfq6-89vx-q4j7 GHSA-gmfj-vffv-32pw GHSA-h5xf-qc2v-94w6 GHSA-p7m8-p9m4-xg4c GHSA-v59p-pxfc-8xvf GHSA-v5q5-f6gq-jfp6 GHSA-wjr6-mhvj-cjvm GHSA-x2cq-c87r-5mfx GHSA-xf64-xmq3-82hg";
const KNOWN: &str = "GHSA-4684-h2q9-2vcp GHSA-4v9h-p7m9-rh26 GHSA-8hxf-qr8p-62x4 GHSA-9hj8-73fh-9963 GHSA-hjqx-j4rw-g7xv GHSA-m665-v7pm-7grj GHSA-q7v9-x93c-xqv3 GHSA-vv5m-jxxh-4627";

fn component(name: &str, version: &str, purl: &str) -> Component {
    Component {
        identity: stable_component_id(purl).unwrap(),
        name: name.into(),
        version: version.into(),
        purl: purl.into(),
        scope: Scope::Runtime,
        provenance: Default::default(),
        licenses: Default::default(),
        locations: Default::default(),
    }
}
fn zip(ver: &str) -> Component {
    component("zip", ver, &format!("pkg:cargo/zip@{ver}"))
}
fn inventory(cs: Vec<Component>) -> Inventory {
    Inventory {
        asset: Asset {
            id: AssetId::new("asset:publisher-test").unwrap(),
            name: "test".into(),
            kind: AssetKind::Package,
            version: None,
            metadata: Default::default(),
        },
        components: cs.into_iter().map(|c| (c.identity.clone(), c)).collect(),
        locations: Default::default(),
        dependencies: Default::default(),
    }
}
fn from_provider(c: &Component, id: &str, alias: &str) -> Finding {
    let rule_id = RuleId::new(format!("osv:{id}")).unwrap();
    let kind = FindingKind::Vulnerability;
    let fid = stable_finding_id(kind, &rule_id, Some(&c.identity), None);
    Finding {
        id: fid,
        kind,
        rule_id,
        advisory_id: Some(id.into()),
        component_id: Some(c.identity.clone()),
        location_id: None,
        aliases: BTreeSet::from([alias.into()]),
        summary: None,
        details: None,
        severity: Severity::High,
        confidence: Default::default(),
        evidence: Default::default(),
        applicability: None,
        remediation: None,
        risk: None,
        first_seen: None,
        last_seen: None,
        modified: None,
        status: Default::default(),
    }
}

#[test]
fn fills_all_24_missing_ids_and_preserves_decisions_on_preexisting_aliases() {
    let old = zip("8.6.0");
    let fixed = zip("9.8.1");
    let snapshot = inventory(vec![fixed.clone(), old.clone()]);
    let mut findings = BTreeMap::<FindingId, Finding>::new();
    for id in KNOWN.split_whitespace() {
        let f = if id == "GHSA-m665-v7pm-7grj" {
            from_provider(&old, "RUSTSEC-2026-0548", "CVE-2026-115905")
        } else {
            from_provider(&old, id, "other-alias")
        };
        findings.insert(f.id.clone(), f);
    }
    // Both provider findings already exist on the same package. Neither
    // should be erased, regraded, nor turned into a third policy decision.
    let duplicate = from_provider(&old, "GHSA-m665-v7pm-7grj", "CVE-2026-115905");
    findings.insert(duplicate.id.clone(), duplicate);
    // A different package with an alias matching a missing ZIP advisory must
    // never swallow the actual ZIP finding.
    let unrelated = component("other", "1.0.0", "pkg:cargo/other@1.0.0");
    let other = from_provider(
        &unrelated,
        "other-package",
        MISSING.split_whitespace().next().unwrap(),
    );
    let other_id = other.id.clone();
    findings.insert(other_id.clone(), other);
    let before = findings.clone();
    let originals: BTreeSet<_> = findings.keys().cloned().collect();
    augment(&snapshot, &mut findings).unwrap();
    let created: BTreeSet<_> = findings
        .iter()
        .filter(|(id, _)| !originals.contains(id))
        .map(|(_, f)| {
            assert_eq!(f.severity, Severity::Unknown);
            assert_eq!(f.component_id.as_ref(), Some(&old.identity));
            let evidence = f.evidence.first().unwrap();
            assert_eq!(
                evidence.properties["publisher.snapshot_sha256"],
                metadata().sha256
            );
            assert_eq!(evidence.references.len(), 1);
            assert!(f.details.is_none());
            f.advisory_id.as_deref().unwrap()
        })
        .collect();
    assert_eq!(created, MISSING.split_whitespace().collect());
    assert_eq!(findings.len(), originals.len() + 24);
    for id in &originals {
        let f = &findings[id];
        let mut unchanged = f.clone();
        unchanged.evidence = before[id].evidence.clone();
        assert_eq!(unchanged, before[id]);
        assert_eq!(f.severity, Severity::High);
        assert!(f.remediation.is_none());
        assert_eq!(f.evidence.len(), usize::from(*id != other_id));
    }
    assert!(
        !findings
            .values()
            .any(|f| f.component_id.as_ref() == Some(&fixed.identity))
    );
    let first = findings.clone();
    augment(&snapshot, &mut findings).unwrap();
    assert_eq!(first, findings);
}

#[test]
fn authenticates_the_snapshot_and_evaluates_only_compatible_coordinates() {
    let bytes = include_bytes!("../docs/verification/zip-maintainer-coordinates.tsv");
    assert_eq!(hooray::util::sha256_hex(bytes), metadata().sha256);
    assert_eq!(
        metadata().revision,
        "3ab0c95f1afc850b8f37c04087b5998c7776b1a1"
    );
    let mut report = BTreeMap::new();
    let eligible = inventory(vec![zip("8.6.0"), zip("9.8.1")]);
    augment(&eligible, &mut report).unwrap();
    let expected: BTreeSet<_> = MISSING
        .split_whitespace()
        .chain(KNOWN.split_whitespace())
        .collect();
    assert_eq!(
        report
            .values()
            .map(|f| f.advisory_id.as_deref().unwrap())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        classify(&zip("8.6.0")).unwrap(),
        Coverage::Evaluated {
            matched_advisories: 32
        }
    );
    assert_eq!(
        classify(&zip("9.8.1")).unwrap(),
        Coverage::Evaluated {
            matched_advisories: 0
        }
    );
    for v in ["*", "8.6", "8.06.0", "8.6.0-01", "invalid"] {
        assert_eq!(classify(&zip(v)).unwrap(), Coverage::Unclassifiable);
    }
    for c in [
        component("zip", "8.6.0", "pkg:cargo/zip"),
        component("zip", "9.8.1", "pkg:cargo/zip@8.6.0"),
        component(
            "zip",
            "8.6.0",
            "pkg:cargo/zip@8.6.0?repository_url=elsewhere",
        ),
        component("zip", "8.6.0", "pkg:cargo/zip@8.6.0#subfile"),
        component("not-zip", "8.6.0", "pkg:cargo/zip@8.6.0"),
    ] {
        assert_eq!(classify(&c).unwrap(), Coverage::Unclassifiable);
    }
    for c in [
        component("zip", "8.6.0", "pkg:npm/zip@8.6.0"),
        component("zipper", "8.6.0", "pkg:cargo/zipper@8.6.0"),
    ] {
        assert_eq!(classify(&c).unwrap(), Coverage::OutOfScope);
    }
}

#[test]
fn matches_affected_versions_individually_and_preserves_source_fix_disagreement() {
    let both = inventory(vec![zip("8.6.0"), zip("9.0.0"), zip("9.0.1")]);
    let mut findings = BTreeMap::new();
    augment(&both, &mut findings).unwrap();
    let versions: BTreeSet<_> = findings
        .values()
        .filter(|f| f.advisory_id.as_deref() == Some("GHSA-4684-h2q9-2vcp"))
        .map(|f| {
            assert_eq!(
                f.remediation.as_ref().unwrap().fixed_versions,
                BTreeSet::from(["9.0.1".into()])
            );
            both.components[f.component_id.as_ref().unwrap()]
                .version
                .as_str()
        })
        .collect();
    assert_eq!(versions, BTreeSet::from(["8.6.0", "9.0.0"]));
}

#[test]
fn refuses_to_overwrite_an_unrelated_finding_when_its_identity_slot_is_occupied() {
    let c = zip("8.6.0");
    let rule = RuleId::new("publisher:zip-rs/zip2:GHSA-2582-27w5-xw4j").unwrap();
    let slot = stable_finding_id(FindingKind::Vulnerability, &rule, Some(&c.identity), None);
    let mut other = from_provider(&c, "provider-unrelated", "no-overlap");
    other.id = slot.clone();
    let mut findings = BTreeMap::from([(slot.clone(), other.clone())]);
    assert!(matches!(
        augment(&inventory(vec![c]), &mut findings),
        Err(hooray::publisher::PublisherError::IdentityConflict)
    ));
    assert_eq!(findings[&slot], other);
}
