use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    Asset, AssetId, AssetKind, Component, ComponentId, DependencyEdge, Inventory, License,
    Location, ModelInvariantError, Scope, Source, SourceKind, stable_component_id,
    stable_location_id,
};
use crate::util::{parse_purl_body, sha256_hex};

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
    #[error("failed to parse SPDX JSON: {0}")]
    SpdxMalformedJson(String),
    #[error("unsupported SPDX version '{found}'; expected SPDX-2.x")]
    UnsupportedSpdxVersion { found: String },
    #[error("duplicate SPDXID '{0}'")]
    DuplicateSpdxId(String),
    #[error("invalid inventory: {0}")]
    InvalidInventory(#[from] ModelInvariantError),
}

/// Parses an SBOM document, auto-detecting SPDX 2.x JSON via the `spdxVersion`
/// key and otherwise applying the CycloneDX JSON flow.
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

    if looks_like_spdx(input) {
        return parse_spdx(input);
    }

    let sbom: CycloneDxSbom = serde_json::from_slice(input)?;
    if sbom.bom_format.as_deref() != Some("CycloneDX") {
        return Err(SbomError::InvalidFormat);
    }
    if sbom.components.is_empty() {
        return Err(SbomError::NoComponents);
    }

    let digest = sha256_hex(input);
    let asset_id = stable_asset_id(&sbom, &digest)?;
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
            .unwrap_or_else(|| format!("sha256:{digest}")),
        digest: Some(format!("sha256:{digest}")),
    };
    let mut state = sbom_state(&asset_id, &source);
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
        locations: BTreeSet::new(),
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

impl ParseState<'_> {
    /// Merges a parsed component into the state: repeated identities extend
    /// provenance, licenses, and locations, while conflicting name/version
    /// pairs for the same identity are rejected.
    fn upsert_component(
        &mut self,
        identity: &ComponentId,
        component: Component,
        purl: String,
    ) -> Result<(), SbomError> {
        if let Some(existing) = self.components.get_mut(identity) {
            if existing.name != component.name || existing.version != component.version {
                return Err(SbomError::ConflictingComponent(purl));
            }
            existing.provenance.extend(component.provenance);
            existing.licenses.extend(component.licenses);
            existing.locations.extend(component.locations);
        } else {
            self.components.insert(identity.clone(), component);
        }
        Ok(())
    }
}

/// Fresh parse state collecting components for one SBOM document.
fn sbom_state<'a>(asset_id: &'a AssetId, source: &'a Source) -> ParseState<'a> {
    ParseState {
        asset_id,
        source,
        components: BTreeMap::new(),
        dependencies: BTreeSet::new(),
        refs: BTreeMap::new(),
        count: 0,
    }
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
        state.upsert_component(&identity, component, purl.to_owned())?;
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

/// Version embedded in a purl, parsed by the shared strict grammar so that
/// scoped names (`pkg:npm/@babel/core`) are never mistaken for `name@version`.
fn purl_version(purl: &str) -> Option<&str> {
    parse_purl_body(purl)?.version()
}

fn is_versioned_purl(purl: &str) -> bool {
    purl_version(purl).is_some()
}

fn parse_scope(scope: Option<&str>) -> Scope {
    match scope {
        Some("required") => Scope::Runtime,
        Some("optional") => Scope::Optional,
        Some("excluded") => Scope::Development,
        _ => Scope::Unknown,
    }
}

fn stable_asset_id(sbom: &CycloneDxSbom, digest: &str) -> Result<AssetId, SbomError> {
    let key = sbom
        .serial_number
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sha256:{digest}"));
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

fn parse_spdx(input: &[u8]) -> Result<Inventory, SbomError> {
    let document: SpdxDocument = serde_json::from_slice(input)
        .map_err(|error| SbomError::SpdxMalformedJson(error.to_string()))?;
    if !document.spdx_version.trim().starts_with("SPDX-2.") {
        return Err(SbomError::UnsupportedSpdxVersion {
            found: document.spdx_version.trim().to_owned(),
        });
    }
    if document.packages.is_empty() {
        return Err(SbomError::NoComponents);
    }
    let digest = sha256_hex(input);
    let asset_id =
        AssetId::new(format!("sbom:sha256:{digest}")).map_err(|_| SbomError::InvalidFormat)?;
    let asset = Asset {
        id: asset_id.clone(),
        name: trimmed(document.name.as_deref())
            .map(str::to_owned)
            .unwrap_or_else(|| "SPDX SBOM".to_owned()),
        kind: AssetKind::Sbom,
        version: None,
        metadata: spdx_asset_metadata(&document),
    };
    let source = Source {
        kind: SourceKind::Sbom,
        locator: format!("sha256:{digest}"),
        digest: Some(format!("sha256:{digest}")),
    };
    let mut state = sbom_state(&asset_id, &source);
    collect_spdx_packages(&document.packages, &mut state)?;
    collect_spdx_relationships(
        &document.relationships,
        &state.refs,
        &mut state.dependencies,
    )?;
    let inventory = Inventory {
        asset,
        components: state.components,
        locations: BTreeSet::new(),
        dependencies: state.dependencies,
    };
    inventory.validate()?;
    Ok(inventory)
}

fn collect_spdx_packages(
    packages: &[SpdxPackage],
    state: &mut ParseState<'_>,
) -> Result<(), SbomError> {
    for (index, package) in packages.iter().enumerate() {
        state.count += 1;
        if state.count > MAX_COMPONENTS {
            return Err(SbomError::TooManyComponents);
        }
        let package_path = format!("packages[{index}]");
        let spdx_id = required(&package.spdx_id, "SPDXID", &package_path)?;
        let name = required(&package.name, "name", &package_path)?;
        let referenced_purl = spdx_package_purl(package);
        // SPDX 2.x marks versionInfo optional (0:1). Recover the version from
        // a versioned externalRefs purl before failing closed; the tradeoff is
        // that the raw (possibly percent-encoded) purl version is accepted
        // where a literal versionInfo field is absent.
        let version = match required(&package.version_info, "versionInfo", &package_path) {
            Ok(version) => version,
            Err(error) => referenced_purl
                .as_deref()
                .and_then(purl_version)
                .ok_or(error)?,
        };
        let purl = match referenced_purl.as_deref() {
            Some(purl) => {
                if !is_versioned_purl(purl) {
                    return Err(SbomError::InvalidComponent {
                        path: package_path.clone(),
                        field: "purl",
                    });
                }
                purl.to_owned()
            }
            None => format!("{name}@{version}"),
        };
        let identity = stable_component_id(&purl).map_err(|_| SbomError::InvalidComponent {
            path: package_path.clone(),
            field: "purl",
        })?;
        let location_path = format!("spdx-id:{spdx_id}");
        let location_id =
            stable_location_id(state.asset_id, &location_path, None).map_err(|_| {
                SbomError::InvalidComponent {
                    path: package_path.clone(),
                    field: "SPDXID",
                }
            })?;
        let component = Component {
            identity: identity.clone(),
            name: name.to_owned(),
            version: version.to_owned(),
            purl: purl.clone(),
            scope: Scope::Unknown,
            provenance: BTreeSet::from([state.source.clone()]),
            licenses: parse_spdx_licenses(package.license_concluded.as_deref()),
            locations: BTreeSet::from([Location {
                id: location_id,
                asset_id: state.asset_id.clone(),
                path: location_path,
                start: None,
                end: None,
            }]),
        };
        state.upsert_component(&identity, component, purl)?;
        if state.refs.insert(spdx_id.to_owned(), identity).is_some() {
            return Err(SbomError::DuplicateSpdxId(spdx_id.to_owned()));
        }
    }
    Ok(())
}

fn spdx_package_purl(package: &SpdxPackage) -> Option<String> {
    package
        .external_refs
        .iter()
        .filter(|reference| trimmed(reference.reference_type.as_deref()) == Some("purl"))
        .find_map(|reference| trimmed(reference.reference_locator.as_deref()))
        .map(str::to_owned)
}

fn collect_spdx_relationships(
    relationships: &[SpdxRelationship],
    refs: &BTreeMap<String, ComponentId>,
    output: &mut BTreeSet<DependencyEdge>,
) -> Result<(), SbomError> {
    for relationship in relationships {
        // Only dependency-carrying relationship types become edges. CONTAINS
        // is deliberately left unmapped: containment is packaging structure,
        // not a dependency, and edges derived from it would distort graph
        // classify/reachability results.
        let (source, target, scope) = match relationship.relationship_type.trim() {
            "DEPENDS_ON" => (
                relationship.spdx_element_id.as_str(),
                relationship.related_spdx_element.as_str(),
                Scope::Unknown,
            ),
            // "A DEPENDENCY_OF B" states that B depends on A; invert the pair
            // so edges keep pointing from the dependent side to its dependency.
            "DEPENDENCY_OF" => (
                relationship.related_spdx_element.as_str(),
                relationship.spdx_element_id.as_str(),
                Scope::Unknown,
            ),
            // "A BUILD_DEPENDENCY_OF B" states that A is a build dependency
            // of B, i.e. B builds against A; keep the forward pair and tag
            // the edge with build scope.
            "BUILD_DEPENDENCY_OF" => (
                relationship.spdx_element_id.as_str(),
                relationship.related_spdx_element.as_str(),
                Scope::Build,
            ),
            _ => continue,
        };
        let Some(from) = refs.get(source) else {
            return Err(SbomError::UnknownDependency {
                from: source.to_owned(),
                to: target.to_owned(),
            });
        };
        let Some(to) = refs.get(target) else {
            return Err(SbomError::UnknownDependency {
                from: source.to_owned(),
                to: target.to_owned(),
            });
        };
        if from != to {
            output.insert(DependencyEdge {
                from: from.clone(),
                to: to.clone(),
                scope,
                optional: false,
            });
        }
    }
    Ok(())
}

fn parse_spdx_licenses(value: Option<&str>) -> BTreeSet<License> {
    let Some(expression) = trimmed(value) else {
        return BTreeSet::new();
    };
    if expression == "NOASSERTION" || expression == "NONE" {
        return BTreeSet::new();
    }
    BTreeSet::from([License {
        expression: Some(expression.to_owned()),
        name: None,
        url: None,
    }])
}

pub(crate) fn looks_like_spdx(input: &[u8]) -> bool {
    const KEY: &[u8] = b"\"spdxVersion\"";
    let mut offset = 0;
    while let Some(index) = input[offset..]
        .windows(KEY.len())
        .position(|window| window == KEY)
    {
        let key_start = offset + index;
        let after = key_start + KEY.len();
        let colon = input[after..]
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        if input.get(after + colon) != Some(&b':') {
            offset = after;
            continue;
        }
        let before = input[..key_start]
            .iter()
            .rev()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        let preceded = key_start
            .checked_sub(before + 1)
            .is_some_and(|index| matches!(input[index], b'{' | b','));
        if preceded {
            return true;
        }
        offset = after;
    }
    false
}

fn spdx_asset_metadata(document: &SpdxDocument) -> BTreeMap<String, Value> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "spdx.spdxVersion".to_owned(),
        Value::String(document.spdx_version.clone()),
    );
    let mut checksums = BTreeSet::new();
    for package in &document.packages {
        let Some(spdx_id) = trimmed(package.spdx_id.as_deref()) else {
            continue;
        };
        for checksum in &package.checksums {
            let Some(algorithm) = trimmed(checksum.algorithm.as_deref()) else {
                continue;
            };
            let Some(value) = trimmed(checksum.checksum_value.as_deref()) else {
                continue;
            };
            checksums.insert(format!("{spdx_id} {algorithm}:{value}"));
        }
    }
    if !checksums.is_empty() {
        metadata.insert(
            "spdx.packageChecksums".to_owned(),
            Value::Array(checksums.into_iter().map(Value::String).collect()),
        );
    }
    metadata
}

#[derive(Debug, Deserialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    name: Option<String>,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
    #[serde(default)]
    relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Deserialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: Option<String>,
    name: Option<String>,
    #[serde(rename = "versionInfo")]
    version_info: Option<String>,
    #[serde(rename = "licenseConcluded")]
    license_concluded: Option<String>,
    #[serde(default)]
    checksums: Vec<SpdxChecksum>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Debug, Deserialize)]
struct SpdxChecksum {
    algorithm: Option<String>,
    #[serde(rename = "checksumValue")]
    checksum_value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpdxExternalRef {
    #[serde(rename = "referenceType")]
    reference_type: Option<String>,
    #[serde(rename = "referenceLocator")]
    reference_locator: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    spdx_element_id: String,
    #[serde(rename = "relationshipType")]
    relationship_type: String,
    #[serde(rename = "relatedSpdxElement")]
    related_spdx_element: String,
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

    #[test]
    fn builds_inventory_from_minimal_spdx_document() {
        let input = br#"{
          "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"spdx-service",
          "documentDescribes":["SPDXRef-Package-app"],
          "packages":[
            {"SPDXID":"SPDXRef-Package-app","name":"app","versionInfo":"1.0.0",
             "licenseConcluded":"MIT OR Apache-2.0",
             "checksums":[{"algorithm":"SHA256","checksumValue":"aa11"}],
             "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:cargo/app@1.0.0"}]},
            {"SPDXID":"SPDXRef-Package-lib","name":"lib","versionInfo":"2.1.0",
             "licenseConcluded":"NOASSERTION",
             "checksums":[{"algorithm":"SHA1","checksumValue":"bb22"},{"algorithm":"SHA256","checksumValue":"cc33"}],
             "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:cargo/lib@2.1.0"}]}
          ],
          "relationships":[
            {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Package-app"},
            {"spdxElementId":"SPDXRef-Package-app","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-Package-lib"}
          ]
        }"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert_eq!(inventory.asset.name, "spdx-service");
        assert!(inventory.asset.id.as_str().starts_with("sbom:sha256:"));
        assert_eq!(inventory.asset.metadata["spdx.spdxVersion"], "SPDX-2.3");
        assert_eq!(inventory.components.len(), 2);
        let ids = inventory
            .components
            .values()
            .map(|component| (component.name.as_str(), component.identity.clone()))
            .collect::<BTreeMap<_, _>>();
        let app = &inventory.components[&ids["app"]];
        assert_eq!(app.purl, "pkg:cargo/app@1.0.0");
        assert_eq!(app.version, "1.0.0");
        assert!(app.licenses.contains(&License {
            expression: Some("MIT OR Apache-2.0".into()),
            name: None,
            url: None,
        }));
        assert_eq!(
            app.locations.iter().next().unwrap().path,
            "spdx-id:SPDXRef-Package-app"
        );
        let lib = &inventory.components[&ids["lib"]];
        assert!(lib.licenses.is_empty());
        assert!(inventory.dependencies.contains(&DependencyEdge {
            from: ids["app"].clone(),
            to: ids["lib"].clone(),
            scope: Scope::Unknown,
            optional: false,
        }));
        assert_eq!(inventory.dependencies.len(), 1);
        assert_eq!(
            inventory.asset.metadata["spdx.packageChecksums"],
            Value::Array(vec![
                Value::String("SPDXRef-Package-app SHA256:aa11".into()),
                Value::String("SPDXRef-Package-lib SHA1:bb22".into()),
                Value::String("SPDXRef-Package-lib SHA256:cc33".into()),
            ])
        );
        inventory.validate().unwrap();
    }

    #[test]
    fn routes_spdx_by_key_shape_and_keeps_cyclonedx_flow_unchanged() {
        let spdx = br#"{"spdxVersion":"SPDX-2.2","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"}]}"#;
        let spdx_inventory = parse_cyclonedx(spdx).unwrap();
        assert_eq!(spdx_inventory.components.len(), 1);
        let spdx_component = spdx_inventory.components.values().next().unwrap();
        assert_eq!(spdx_component.name, "a");
        let cyclonedx = br#"{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","purl":"pkg:cargo/a@1","licenses":[{"expression":"mentions \"spdxVersion\" handling"}]}]}"#;
        let inventory = parse_cyclonedx(cyclonedx).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(matches!(
            parse_cyclonedx(br#"{}"#),
            Err(SbomError::InvalidFormat)
        ));
    }

    #[test]
    fn classifies_scoped_purls_strictly_instead_of_misparsing_namespaces() {
        // A naive rsplit_once('@') reads pkg:npm/@scope/pkg as name "npm/"
        // with version "scope/pkg", bypassing the versioned-purl gates and
        // fabricating SPDX versionInfo. The strict grammar must classify
        // these unversioned.
        assert!(!is_versioned_purl("pkg:npm/@scope/pkg"));
        assert_eq!(purl_version("pkg:npm/@scope/pkg"), None);
        assert_eq!(purl_version("pkg:npm/@scope/pkg@1.0.0"), Some("1.0.0"));
        assert_eq!(purl_version("pkg:npm/@babel/core@7.0.0"), Some("7.0.0"));
        assert_eq!(
            purl_version("pkg:golang/github.com/foo/bar@v1.2.3"),
            Some("v1.2.3")
        );
    }

    #[test]
    fn unversioned_scoped_purls_fail_closed_at_both_gates() {
        // CycloneDX gate: only fully versioned purls may enter.
        assert!(matches!(
            parse_cyclonedx(
                br#"{"bomFormat":"CycloneDX","components":[{"name":"s","version":"1","purl":"pkg:npm/@scope/pkg"}]}"#
            ),
            Err(SbomError::InvalidComponent { field: "purl", .. })
        ));
        // SPDX recovery: a scoped unversioned purl must not be misread as a
        // version substitute for a missing versionInfo.
        assert!(matches!(
            parse_cyclonedx(
                br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-s","name":"s","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/@scope/pkg"}]}]}"#
            ),
            Err(SbomError::InvalidComponent {
                field: "versionInfo",
                ..
            })
        ));
    }

    #[test]
    fn falls_back_to_name_and_version_without_fabricating_purl() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"openssl","versionInfo":"3.2.1"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        let component = inventory.components.values().next().unwrap();
        assert_eq!(component.purl, "openssl@3.2.1");
        assert!(!component.purl.starts_with("pkg:"));
        assert_eq!(
            component.identity,
            stable_component_id("openssl@3.2.1").unwrap()
        );
        inventory.validate().unwrap();
    }

    #[test]
    fn recovers_spdx_version_from_versioned_purl_when_version_info_missing() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/a@1.2.3"}]}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        let component = inventory.components.values().next().unwrap();
        assert_eq!(component.purl, "pkg:cargo/a@1.2.3");
        assert_eq!(component.version, "1.2.3");
        inventory.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_spdx_documents() {
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-3.0","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"}]}"#),
            Err(SbomError::UnsupportedSpdxVersion { found }) if found == "SPDX-3.0"
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","pack x"#),
            Err(SbomError::SpdxMalformedJson(_))
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","versionInfo":"1"}]}"#),
            Err(SbomError::InvalidComponent { field: "name", .. })
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a"}]}"#),
            Err(SbomError::InvalidComponent { field: "versionInfo", .. })
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"},{"SPDXID":"SPDXRef-a","name":"b","versionInfo":"2"}]}"#),
            Err(SbomError::DuplicateSpdxId(id)) if id == "SPDXRef-a"
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"}],"relationships":[{"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-missing"}]}"#),
            Err(SbomError::UnknownDependency { from, to }) if from == "SPDXRef-a" && to == "SPDXRef-missing"
        ));
        assert!(matches!(
            parse_cyclonedx(br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/a"}]}]}"#),
            Err(SbomError::InvalidComponent { field: "purl", .. })
        ));
    }

    #[test]
    fn ignores_spdx_self_dependencies_and_other_relationship_types() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"}],"relationships":[{"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-a"},{"spdxElementId":"SPDXRef-a","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-a"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert!(inventory.dependencies.is_empty());
    }

    #[test]
    fn inverts_spdx_dependency_of_edge_direction() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-lib","name":"lib","versionInfo":"1"},{"SPDXID":"SPDXRef-app","name":"app","versionInfo":"2"}],"relationships":[{"spdxElementId":"SPDXRef-lib","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-app"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        let lib = stable_component_id("lib@1").unwrap();
        let app = stable_component_id("app@2").unwrap();
        assert_eq!(inventory.dependencies.len(), 1);
        let edge = inventory.dependencies.iter().next().unwrap();
        assert_eq!(edge.from, app, "the dependent package must own the edge");
        assert_eq!(edge.to, lib);
        assert_eq!(edge.scope, Scope::Unknown);
    }

    #[test]
    fn maps_spdx_build_dependency_of_forward_with_build_scope() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-tool","name":"tool","versionInfo":"1"},{"SPDXID":"SPDXRef-lib","name":"lib","versionInfo":"2"}],"relationships":[{"spdxElementId":"SPDXRef-tool","relationshipType":"BUILD_DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-lib"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        let tool = stable_component_id("tool@1").unwrap();
        let lib = stable_component_id("lib@2").unwrap();
        assert_eq!(inventory.dependencies.len(), 1);
        let edge = inventory.dependencies.iter().next().unwrap();
        // "tool BUILD_DEPENDENCY_OF lib" means tool builds against lib.
        assert_eq!(edge.from, tool);
        assert_eq!(edge.to, lib);
        assert_eq!(edge.scope, Scope::Build);
    }

    #[test]
    fn leaves_spdx_contains_relationships_unmapped() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1"},{"SPDXID":"SPDXRef-b","name":"b","versionInfo":"2"}],"relationships":[{"spdxElementId":"SPDXRef-a","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-b"}]}"#;
        let inventory = parse_cyclonedx(input).unwrap();
        assert!(inventory.dependencies.is_empty());
    }

    #[test]
    fn names_related_element_when_spdx_dependency_source_is_unknown() {
        let input = br#"{"spdxVersion":"SPDX-2.3","name":"doc","packages":[{"SPDXID":"SPDXRef-b","name":"b","versionInfo":"1"}],"relationships":[{"spdxElementId":"SPDXRef-missing","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-b"}]}"#;
        let error = parse_cyclonedx(input).expect_err("unknown element must fail closed");
        let message = error.to_string();
        assert!(matches!(
            error,
            SbomError::UnknownDependency { from, to } if from == "SPDXRef-missing" && to == "SPDXRef-b"
        ));
        assert!(
            message.contains("SPDXRef-b"),
            "error must name the related element, got: {message}"
        );
    }

    #[test]
    fn rejects_oversized_spdx_input_before_decoding() {
        let mut input = br#"{"spdxVersion":"SPDX-2.3"}"#.to_vec();
        input.resize(MAX_SBOM_BYTES + 1, b' ');
        assert!(matches!(
            parse_cyclonedx(&input),
            Err(SbomError::TooLarge { .. })
        ));
    }

    #[test]
    fn enforces_spdx_component_count_boundary() {
        let asset_id = AssetId::new("asset:test").unwrap();
        let source = Source {
            kind: SourceKind::Sbom,
            locator: "fixture".into(),
            digest: None,
        };
        let mut state = parse_state(&asset_id, &source);
        state.count = MAX_COMPONENTS;
        let packages = [SpdxPackage {
            spdx_id: Some("SPDXRef-a".into()),
            name: Some("a".into()),
            version_info: Some("1".into()),
            license_concluded: None,
            checksums: Vec::new(),
            external_refs: Vec::new(),
        }];
        assert!(matches!(
            collect_spdx_packages(&packages, &mut state),
            Err(SbomError::TooManyComponents)
        ));
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
