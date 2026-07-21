use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    Asset, AssetId, AssetKind, Component, ComponentId, DependencyEdge, Inventory, License,
    Location, ModelInvariantError, Scope, Source, SourceKind, stable_component_id,
    stable_location_id,
};

const MAX_SBOM_BYTES: usize = 100 * 1024 * 1024;
const MAX_COMPONENTS: usize = 1_000_000;
const MAX_COMPONENT_DEPTH: usize = 256;

#[derive(Debug, Error)]
pub enum SbomError {
    #[error("SBOM is empty")]
    Empty,
    #[error("SBOM size {actual} exceeds maximum {maximum} bytes")]
    TooLarge { actual: usize, maximum: usize },
    #[error("failed to parse CycloneDX JSON: {0}")]
    MalformedJson(#[from] serde_json::Error),
    #[error("document is not a CycloneDX SBOM")]
    InvalidFormat,
    #[error("CycloneDX SBOM contains no components")]
    NoComponents,
    #[error("component nesting exceeds maximum depth {MAX_COMPONENT_DEPTH}")]
    TooDeep,
    #[error("component count exceeds maximum {MAX_COMPONENTS}")]
    TooManyComponents,
    #[error("component at {path} has invalid {field}")]
    InvalidComponent { path: String, field: &'static str },
    #[error("duplicate bom-ref '{0}'")]
    DuplicateBomRef(String),
    #[error("duplicate package URL '{0}' has conflicting component data")]
    ConflictingComponent(String),
    #[error("dependency '{from}' references unknown component '{to}'")]
    UnknownDependency { from: String, to: String },
    #[error("invalid inventory: {0}")]
    InvalidInventory(#[from] ModelInvariantError),
}

pub fn parse_cyclonedx(input: &[u8]) -> Result<Inventory, SbomError> {
    if input.is_empty() {
        return Err(SbomError::Empty);
    }
    if input.len() > MAX_SBOM_BYTES {
        return Err(SbomError::TooLarge {
            actual: input.len(),
            maximum: MAX_SBOM_BYTES,
        });
    }

    let sbom: CycloneDxSbom = serde_json::from_slice(input)?;
    if sbom.bom_format.as_deref() != Some("CycloneDX") {
        return Err(SbomError::InvalidFormat);
    }
    if sbom.components.is_empty() {
        return Err(SbomError::NoComponents);
    }

    let asset_id = stable_asset_id(&sbom, input)?;
    let asset = Asset {
        id: asset_id.clone(),
        name: asset_name(&sbom),
        kind: AssetKind::Sbom,
        version: sbom.metadata.as_ref().and_then(|metadata| {
            metadata
                .component
                .as_ref()
                .and_then(|component| component.version.clone())
        }),
        metadata: asset_metadata(&sbom),
    };
    let source = Source {
        kind: SourceKind::Sbom,
        locator: sbom
            .serial_number
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("sha256:{}", hex_digest(input))),
        digest: Some(format!("sha256:{}", hex_digest(input))),
    };
    let mut state = ParseState {
        asset_id: &asset_id,
        source: &source,
        components: BTreeMap::new(),
        dependencies: BTreeSet::new(),
        refs: BTreeMap::new(),
        count: 0,
    };
    collect_components(&sbom.components, None, 0, "components", &mut state)?;
    collect_declared_dependencies(
        &sbom.dependencies,
        &state.refs,
        sbom.metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .and_then(|component| component.bom_ref.as_deref())
            .map(str::trim)
            .filter(|reference| !reference.is_empty()),
        &mut state.dependencies,
    )?;

    let inventory = Inventory {
        asset,
        components: state.components,
        dependencies: state.dependencies,
    };
    inventory.validate()?;
    Ok(inventory)
}

struct ParseState<'a> {
    asset_id: &'a AssetId,
    source: &'a Source,
    components: BTreeMap<ComponentId, Component>,
    dependencies: BTreeSet<DependencyEdge>,
    refs: BTreeMap<String, ComponentId>,
    count: usize,
}

fn collect_components(
    source: &[CycloneDxComponent],
    parent: Option<&ComponentId>,
    depth: usize,
    path: &str,
    state: &mut ParseState<'_>,
) -> Result<(), SbomError> {
    if depth > MAX_COMPONENT_DEPTH {
        return Err(SbomError::TooDeep);
    }
    for (index, wire) in source.iter().enumerate() {
        state.count += 1;
        if state.count > MAX_COMPONENTS {
            return Err(SbomError::TooManyComponents);
        }
        let component_path = format!("{path}[{index}]");
        let name = required(&wire.name, "name", &component_path)?;
        let version = required(&wire.version, "version", &component_path)?;
        let purl = required(&wire.purl, "purl", &component_path)?;
        if !is_versioned_purl(purl) {
            return Err(SbomError::InvalidComponent {
                path: component_path,
                field: "purl",
            });
        }
        let identity = stable_component_id(purl).map_err(|_| SbomError::InvalidComponent {
            path: component_path.clone(),
            field: "purl",
        })?;
        let location_path = wire
            .bom_ref
            .as_deref()
            .map(|value| format!("bom-ref:{value}"))
            .unwrap_or_else(|| format!("purl:{purl}"));
        let location_id =
            stable_location_id(state.asset_id, &location_path, None).map_err(|_| {
                SbomError::InvalidComponent {
                    path: component_path.clone(),
                    field: "bom-ref",
                }
            })?;
        let scope = parse_scope(wire.scope.as_deref());
        let component = Component {
            identity: identity.clone(),
            name: name.to_owned(),
            version: version.to_owned(),
            purl: purl.to_owned(),
            scope,
            provenance: BTreeSet::from([state.source.clone()]),
            licenses: parse_licenses(&wire.licenses),
            locations: BTreeSet::from([Location {
                id: location_id,
                asset_id: state.asset_id.clone(),
                path: location_path,
                start: None,
                end: None,
            }]),
        };
        if let Some(existing) = state.components.get_mut(&identity) {
            if existing.name != component.name || existing.version != component.version {
                return Err(SbomError::ConflictingComponent(purl.to_owned()));
            }
            existing.provenance.extend(component.provenance);
            existing.licenses.extend(component.licenses);
            existing.locations.extend(component.locations);
        } else {
            state.components.insert(identity.clone(), component);
        }
        if let Some(reference) = wire.bom_ref.as_deref() {
            let reference = required_value(reference, "bom-ref", &component_path)?;
            if state
                .refs
                .insert(reference.to_owned(), identity.clone())
                .is_some()
            {
                return Err(SbomError::DuplicateBomRef(reference.to_owned()));
            }
        }
        if let Some(parent) = parent
            && parent != &identity
        {
            state.dependencies.insert(DependencyEdge {
                from: parent.clone(),
                to: identity.clone(),
                scope,
                optional: scope == Scope::Optional,
            });
        }
        collect_components(
            &wire.components,
            Some(&identity),
            depth + 1,
            &format!("{component_path}.components"),
            state,
        )?;
    }
    Ok(())
}

fn collect_declared_dependencies(
    dependencies: &[CycloneDxDependency],
    refs: &BTreeMap<String, ComponentId>,
    root_ref: Option<&str>,
    output: &mut BTreeSet<DependencyEdge>,
) -> Result<(), SbomError> {
    for dependency in dependencies {
        let from_is_root = root_ref == Some(dependency.reference.as_str());
        let from = (!from_is_root)
            .then(|| refs.get(&dependency.reference))
            .flatten();
        if from.is_none() && !from_is_root {
            return Err(SbomError::UnknownDependency {
                from: dependency.reference.clone(),
                to: dependency.reference.clone(),
            });
        }
        for target in &dependency.depends_on {
            let to_is_root = root_ref == Some(target.as_str());
            let to = (!to_is_root).then(|| refs.get(target)).flatten();
            if to.is_none() && !to_is_root {
                return Err(SbomError::UnknownDependency {
                    from: dependency.reference.clone(),
                    to: target.clone(),
                });
            }
            if let (Some(from), Some(to)) = (from, to)
                && from != to
            {
                output.insert(DependencyEdge {
                    from: from.clone(),
                    to: to.clone(),
                    scope: Scope::Unknown,
                    optional: false,
                });
            }
        }
    }
    Ok(())
}

fn parse_licenses(choices: &[CycloneDxLicenseChoice]) -> BTreeSet<License> {
    choices
        .iter()
        .filter_map(|choice| {
            if let Some(expression) = trimmed(choice.expression.as_deref()) {
                return Some(License {
                    expression: Some(expression.to_owned()),
                    name: None,
                    url: None,
                });
            }
            let license = choice.license.as_ref()?;
            let expression = trimmed(license.id.as_deref()).map(str::to_owned);
            let name = trimmed(license.name.as_deref()).map(str::to_owned);
            let url = trimmed(license.url.as_deref()).map(str::to_owned);
            (expression.is_some() || name.is_some() || url.is_some()).then_some(License {
                expression,
                name,
                url,
            })
        })
        .collect()
}

fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn required<'a>(
    value: &'a Option<String>,
    field: &'static str,
    path: &str,
) -> Result<&'a str, SbomError> {
    value
        .as_deref()
        .and_then(|value| (!value.trim().is_empty()).then_some(value.trim()))
        .ok_or_else(|| SbomError::InvalidComponent {
            path: path.to_owned(),
            field,
        })
}

fn required_value<'a>(
    value: &'a str,
    field: &'static str,
    path: &str,
) -> Result<&'a str, SbomError> {
    (!value.trim().is_empty())
        .then_some(value.trim())
        .ok_or_else(|| SbomError::InvalidComponent {
            path: path.to_owned(),
            field,
        })
}

fn is_versioned_purl(purl: &str) -> bool {
    let Some(package) = purl.strip_prefix("pkg:") else {
        return false;
    };
    let package = package.split(['?', '#']).next().unwrap_or(package);
    package
        .rsplit_once('@')
        .is_some_and(|(name, version)| !name.is_empty() && !version.is_empty())
}

fn parse_scope(scope: Option<&str>) -> Scope {
    match scope {
        Some("required") => Scope::Runtime,
        Some("optional") => Scope::Optional,
        Some("excluded") => Scope::Development,
        _ => Scope::Unknown,
    }
}

fn stable_asset_id(sbom: &CycloneDxSbom, input: &[u8]) -> Result<AssetId, SbomError> {
    let key = sbom
        .serial_number
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sha256:{}", hex_digest(input)));
    AssetId::new(format!("sbom:{key}")).map_err(|_| SbomError::InvalidFormat)
}

fn asset_name(sbom: &CycloneDxSbom) -> String {
    sbom.metadata
        .as_ref()
        .and_then(|metadata| metadata.component.as_ref())
        .and_then(|component| component.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            sbom.serial_number
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_owned)
        .unwrap_or_else(|| "CycloneDX SBOM".to_owned())
}

fn asset_metadata(sbom: &CycloneDxSbom) -> BTreeMap<String, Value> {
    let mut metadata = BTreeMap::new();
    if let Some(version) = &sbom.spec_version {
        metadata.insert(
            "cyclonedx.specVersion".to_owned(),
            Value::String(version.clone()),
        );
    }
    if let Some(serial) = &sbom.serial_number {
        metadata.insert(
            "cyclonedx.serialNumber".to_owned(),
            Value::String(serial.clone()),
        );
    }
    if let Some(version) = sbom.version {
        metadata.insert("cyclonedx.version".to_owned(), Value::from(version));
    }
    metadata
}

fn hex_digest(input: &[u8]) -> String {
    format!("{:x}", Sha256::digest(input))
}

#[derive(Debug, Deserialize)]
struct CycloneDxSbom {
    #[serde(rename = "bomFormat")]
    bom_format: Option<String>,
    #[serde(rename = "specVersion")]
    spec_version: Option<String>,
    #[serde(rename = "serialNumber")]
    serial_number: Option<String>,
    version: Option<u64>,
    metadata: Option<CycloneDxMetadata>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
    #[serde(default)]
    dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxMetadata {
    component: Option<CycloneDxComponent>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxComponent {
    #[serde(rename = "bom-ref")]
    bom_ref: Option<String>,
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    scope: Option<String>,
    #[serde(default)]
    licenses: Vec<CycloneDxLicenseChoice>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxLicenseChoice {
    expression: Option<String>,
    license: Option<CycloneDxLicense>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxLicense {
    id: Option<String>,
    name: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default, rename = "dependsOn")]
    depends_on: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_inventory_with_nested_and_declared_dependencies() {
        let input = br#"{
          "bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:test","version":1,
          "metadata":{"component":{"name":"service","version":"4"}},
          "components":[{
            "bom-ref":"parent","name":"parent","version":"1","purl":"pkg:cargo/parent@1",
            "components":[{"bom-ref":"child","name":"child","version":"2","purl":"pkg:cargo/child@2"}]
          },{"bom-ref":"other","name":"other","version":"3","purl":"pkg:cargo/other@3"}],
          "dependencies":[{"ref":"child","dependsOn":["other"]}]
        }"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert_eq!(inventory.asset.id.as_str(), "sbom:urn:uuid:test");
        assert_eq!(inventory.asset.name, "service");
        assert_eq!(inventory.components.len(), 3);
        assert_eq!(inventory.dependencies.len(), 2);
        assert!(inventory.components.values().all(|component| {
            component.identity == stable_component_id(&component.purl).unwrap()
                && component.locations.len() == 1
        }));
        inventory.validate().unwrap();
    }

    #[test]
    fn produces_stable_ids() {
        let input = br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1"}]}"#;
        let first = parse_cyclonedx(input).unwrap();
        let second = parse_cyclonedx(input).unwrap();
        assert_eq!(first.asset.id, second.asset.id);
        assert_eq!(first.components, second.components);
    }

    #[test]
    fn rejects_invalid_data_and_relationships() {
        assert!(matches!(parse_cyclonedx(b""), Err(SbomError::Empty)));
        assert!(matches!(
            parse_cyclonedx(br#"{}"#),
            Err(SbomError::InvalidFormat)
        ));
        assert!(matches!(
            parse_cyclonedx(
                br#"{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1"}]}"#
            ),
            Err(SbomError::InvalidComponent { field: "purl", .. })
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1"}],"dependencies":[{"ref":"a","dependsOn":["missing"]}]}"#),
            Err(SbomError::UnknownDependency { .. })
        ));
    }

    #[test]
    fn rejects_oversized_input_before_decoding() {
        let input = vec![b' '; MAX_SBOM_BYTES + 1];
        assert!(matches!(
            parse_cyclonedx(&input),
            Err(SbomError::TooLarge { .. })
        ));
    }

    #[test]
    fn maps_scopes_optional_fields_and_metadata() {
        let input = br#"{
          "bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:meta","version":7,
          "metadata":{"component":{"name":"root-app","version":"9","purl":"pkg:cargo/root-app@9","properties":[{"name":"team","value":"security"}]}},
          "components":[
            {"name":"runtime","version":"1","purl":"pkg:cargo/runtime@1","scope":"required","properties":[{"name":"ignored","value":"safe"}]},
            {"name":"optional","version":"2","purl":"pkg:cargo/optional@2","scope":"optional"},
            {"name":"dev","version":"3","purl":"pkg:cargo/dev@3","scope":"excluded"},
            {"name":"mystery","version":"4","purl":"pkg:cargo/mystery@4","scope":"future"}
          ]
        }"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert_eq!(inventory.asset.name, "root-app");
        assert_eq!(inventory.asset.version.as_deref(), Some("9"));
        assert_eq!(inventory.asset.metadata["cyclonedx.specVersion"], "1.5");
        assert_eq!(
            inventory.asset.metadata["cyclonedx.serialNumber"],
            "urn:uuid:meta"
        );
        assert_eq!(inventory.asset.metadata["cyclonedx.version"], 7);
        let scopes = inventory
            .components
            .values()
            .map(|component| (component.name.as_str(), component.scope))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(scopes["runtime"], Scope::Runtime);
        assert_eq!(scopes["optional"], Scope::Optional);
        assert_eq!(scopes["dev"], Scope::Development);
        assert_eq!(scopes["mystery"], Scope::Unknown);
    }

    #[test]
    fn preserves_component_licenses_and_merges_duplicate_purl_licenses() {
        let inventory = parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[
          {"bom-ref":"first","name":"same","version":"1","purl":"pkg:cargo/same@1","licenses":[{"expression":"MIT OR Apache-2.0"},{"license":{"id":"BSD-3-Clause"}},{"license":{"name":"Custom License","url":"https://licenses.example/custom"}}]},
          {"bom-ref":"second","name":"same","version":"1","purl":"pkg:cargo/same@1","licenses":[{"license":{"id":"ISC","name":"ISC License","url":"https://spdx.org/licenses/ISC.html"}},{"expression":"MIT OR Apache-2.0"}]}
        ]}"#).unwrap();
        let component = inventory.components.values().next().unwrap();
        assert_eq!(component.licenses.len(), 4);
        assert!(component.licenses.contains(&License {
            expression: Some("MIT OR Apache-2.0".into()),
            name: None,
            url: None
        }));
        assert!(component.licenses.contains(&License {
            expression: Some("BSD-3-Clause".into()),
            name: None,
            url: None
        }));
        assert!(component.licenses.contains(&License {
            expression: None,
            name: Some("Custom License".into()),
            url: Some("https://licenses.example/custom".into())
        }));
        assert!(component.licenses.contains(&License {
            expression: Some("ISC".into()),
            name: Some("ISC License".into()),
            url: Some("https://spdx.org/licenses/ISC.html".into())
        }));
    }

    #[test]
    fn accepts_metadata_component_as_dependency_root_without_materializing_root_edges() {
        let inventory = parse_cyclonedx(br#"{"bomFormat":"CycloneDX","metadata":{"component":{"bom-ref":"app","name":"app","version":"1","purl":"pkg:cargo/app@1"}},"components":[
          {"bom-ref":"direct","name":"direct","version":"1","purl":"pkg:cargo/direct@1"},
          {"bom-ref":"transitive","name":"transitive","version":"1","purl":"pkg:cargo/transitive@1"}
        ],"dependencies":[{"ref":"app","dependsOn":["direct"]},{"ref":"direct","dependsOn":["transitive"]}]}"#).unwrap();
        assert_eq!(inventory.components.len(), 2);
        assert_eq!(inventory.dependencies.len(), 1);
        let edge = inventory.dependencies.iter().next().unwrap();
        assert_eq!(inventory.components[&edge.from].name, "direct");
        assert_eq!(inventory.components[&edge.to].name, "transitive");
    }

    #[test]
    fn nested_edges_point_from_parent_to_child_and_preserve_child_scope() {
        let input = br#"{"bomFormat":"CycloneDX","components":[
          {"bom-ref":"parent","name":"parent","version":"1","purl":"pkg:cargo/parent@1","components":[
            {"bom-ref":"child","name":"child","version":"2","purl":"pkg:cargo/child@2","scope":"optional"}
          ]},
          {"bom-ref":"target","name":"target","version":"3","purl":"pkg:cargo/target@3"}
        ],"dependencies":[{"ref":"child","dependsOn":["target"]}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        let ids = inventory
            .components
            .values()
            .map(|component| (component.name.as_str(), component.identity.clone()))
            .collect::<BTreeMap<_, _>>();
        assert!(inventory.dependencies.contains(&DependencyEdge {
            from: ids["parent"].clone(),
            to: ids["child"].clone(),
            scope: Scope::Optional,
            optional: true,
        }));
        assert!(inventory.dependencies.contains(&DependencyEdge {
            from: ids["child"].clone(),
            to: ids["target"].clone(),
            scope: Scope::Unknown,
            optional: false,
        }));
        assert!(
            !inventory
                .dependencies
                .iter()
                .any(|edge| edge.from == ids["target"] && edge.to == ids["child"])
        );
    }

    #[test]
    fn merges_duplicate_purl_locations_but_rejects_conflicts_and_duplicate_refs() {
        let merged = parse_cyclonedx(
            br#"{"bomFormat":"CycloneDX","components":[
          {"bom-ref":"first","name":"same","version":"1","purl":"pkg:cargo/same@1"},
          {"bom-ref":"second","name":"same","version":"1","purl":"pkg:cargo/same@1"}
        ]}"#,
        )
        .unwrap();
        assert_eq!(merged.components.len(), 1);
        assert_eq!(
            merged.components.values().next().unwrap().locations.len(),
            2
        );

        assert!(matches!(
            parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[
              {"name":"flat","version":"1","purl":"pkg:cargo/same@1"},
              {"name":"parent","version":"1","purl":"pkg:cargo/parent@1","components":[
                {"name":"nested-conflict","version":"1","purl":"pkg:cargo/same@1"}
              ]}
            ]}"#),
            Err(SbomError::ConflictingComponent(purl)) if purl == "pkg:cargo/same@1"
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[
              {"bom-ref":"dup","name":"a","version":"1","purl":"pkg:cargo/a@1"},
              {"bom-ref":"dup","name":"b","version":"1","purl":"pkg:cargo/b@1"}
            ]}"#),
            Err(SbomError::DuplicateBomRef(reference)) if reference == "dup"
        ));
    }

    #[test]
    fn rejects_missing_blank_and_malformed_component_identity_fields() {
        for (field, component) in [
            ("name", r#"{"version":"1","purl":"pkg:cargo/a@1"}"#),
            ("version", r#"{"name":"a","purl":"pkg:cargo/a@1"}"#),
            ("purl", r#"{"name":"a","version":"1","purl":"   "}"#),
        ] {
            let input = format!(r#"{{"bomFormat":"CycloneDX","components":[{component}]}}"#);
            assert!(
                matches!(parse_cyclonedx(input.as_bytes()), Err(SbomError::InvalidComponent { field: actual, .. }) if actual == field)
            );
        }
        for purl in ["cargo/a@1", "pkg:cargo/a", "pkg:@1", "pkg:cargo/a@"] {
            let input = format!(
                r#"{{"bomFormat":"CycloneDX","components":[{{"name":"a","version":"1","purl":"{purl}"}}]}}"#
            );
            assert!(
                matches!(
                    parse_cyclonedx(input.as_bytes()),
                    Err(SbomError::InvalidComponent { field: "purl", .. })
                ),
                "accepted {purl}"
            );
        }
    }
    #[test]
    fn rejects_blank_bom_ref_and_reports_unknown_dependency_source() {
        assert!(matches!(
            parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":" ","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#),
            Err(SbomError::InvalidComponent { field: "bom-ref", .. })
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"a","version":"1","purl":"pkg:cargo/a@1"}],"dependencies":[{"ref":"missing","dependsOn":[]}]}"#),
            Err(SbomError::UnknownDependency { from, to }) if from == "missing" && to == "missing"
        ));
    }

    #[test]
    fn self_dependencies_are_ignored() {
        let inventory = parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"a","version":"1","purl":"pkg:cargo/a@1"}],"dependencies":[{"ref":"a","dependsOn":["a"]}]}"#).unwrap();
        assert!(inventory.dependencies.is_empty());
    }

    #[test]
    fn asset_fallbacks_are_deterministic_and_blank_serial_is_not_used_as_id() {
        let input = br#"{"bomFormat":"CycloneDX","serialNumber":" ","metadata":{"component":{"name":" "}},"components":[{"name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert_eq!(inventory.asset.name, "CycloneDX SBOM");
        assert!(inventory.asset.id.as_str().starts_with("sbom:sha256:"));
        assert_eq!(inventory.asset.metadata["cyclonedx.serialNumber"], " ");
        assert!(
            inventory
                .components
                .values()
                .next()
                .unwrap()
                .provenance
                .iter()
                .next()
                .unwrap()
                .locator
                .starts_with("sha256:")
        );
        assert_eq!(
            inventory
                .components
                .values()
                .next()
                .unwrap()
                .locations
                .iter()
                .next()
                .unwrap()
                .path,
            "purl:pkg:cargo/a@1"
        );
    }

    fn wire_component() -> CycloneDxComponent {
        CycloneDxComponent {
            bom_ref: Some("a".into()),
            name: Some("a".into()),
            version: Some("1".into()),
            purl: Some("pkg:cargo/a@1".into()),
            scope: None,
            licenses: Vec::new(),
            components: Vec::new(),
        }
    }

    fn parse_state<'a>(asset_id: &'a AssetId, source: &'a Source) -> ParseState<'a> {
        ParseState {
            asset_id,
            source,
            components: BTreeMap::new(),
            dependencies: BTreeSet::new(),
            refs: BTreeMap::new(),
            count: 0,
        }
    }

    #[test]
    fn enforces_depth_and_component_count_at_exact_boundaries() {
        let asset_id = AssetId::new("asset:test").unwrap();
        let source = Source {
            kind: SourceKind::Sbom,
            locator: "fixture".into(),
            digest: None,
        };
        let mut depth_state = parse_state(&asset_id, &source);
        assert!(matches!(
            collect_components(
                &[wire_component()],
                None,
                MAX_COMPONENT_DEPTH + 1,
                "components",
                &mut depth_state
            ),
            Err(SbomError::TooDeep)
        ));

        let mut count_state = parse_state(&asset_id, &source);
        count_state.count = MAX_COMPONENTS;
        assert!(matches!(
            collect_components(&[wire_component()], None, 0, "components", &mut count_state),
            Err(SbomError::TooManyComponents)
        ));
    }
}
