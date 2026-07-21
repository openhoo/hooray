use std::collections::HashSet;

use serde::Deserialize;
use thiserror::Error;

use crate::model::Component;

/// Errors returned while extracting scannable components from a CycloneDX SBOM.
#[derive(Debug, Error)]
pub enum SbomError {
    #[error("failed to parse CycloneDX JSON: {0}")]
    MalformedJson(#[from] serde_json::Error),

    #[error("SBOM contains no usable components with name, version, and versioned purl")]
    NoUsableComponents,
}

/// Parses CycloneDX JSON and returns unique, scannable components.
///
/// Components may occur at any nesting depth. Entries missing a name, version,
/// or package URL are ignored. The first entry for each versioned package URL is
/// retained, preserving the SBOM's traversal order.
pub fn parse_cyclonedx(input: &[u8]) -> Result<Vec<Component>, SbomError> {
    let sbom: CycloneDxSbom = serde_json::from_slice(input)?;
    let mut components = Vec::new();
    let mut seen_purls = HashSet::new();

    collect_components(sbom.components, &mut seen_purls, &mut components);

    if components.is_empty() {
        Err(SbomError::NoUsableComponents)
    } else {
        Ok(components)
    }
}

fn collect_components(
    source: Vec<CycloneDxComponent>,
    seen_purls: &mut HashSet<String>,
    output: &mut Vec<Component>,
) {
    for component in source {
        let CycloneDxComponent {
            name,
            version,
            purl,
            components,
        } = component;

        if let (Some(name), Some(version), Some(purl)) = (name, version, purl)
            && is_nonempty(&name)
            && is_nonempty(&version)
            && is_versioned_purl(&purl)
            && seen_purls.insert(purl.clone())
        {
            output.push(Component {
                name,
                version,
                purl,
            });
        }

        collect_components(components, seen_purls, output);
    }
}

fn is_nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn is_versioned_purl(purl: &str) -> bool {
    let Some(package) = purl.strip_prefix("pkg:") else {
        return false;
    };
    let package = package.split(['?', '#']).next().unwrap_or(package);
    let Some((name, version)) = package.rsplit_once('@') else {
        return false;
    };

    !name.is_empty() && !version.is_empty()
}

#[derive(Debug, Deserialize)]
struct CycloneDxSbom {
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxComponent {
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[cfg(test)]
mod tests {
    use super::{SbomError, parse_cyclonedx};

    #[test]
    fn parses_nested_components_in_traversal_order() {
        let input = br#"
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "components": [
            {
              "type": "application",
              "name": "parent",
              "version": "1.0.0",
              "purl": "pkg:cargo/parent@1.0.0",
              "components": [
                {
                  "type": "library",
                  "name": "child",
                  "version": "2.0.0",
                  "purl": "pkg:cargo/child@2.0.0"
                }
              ]
            }
          ]
        }
        "#;

        let components = parse_cyclonedx(input).unwrap();

        assert_eq!(components.len(), 2);
        assert_eq!(components[0].name, "parent");
        assert_eq!(components[0].version, "1.0.0");
        assert_eq!(components[0].purl, "pkg:cargo/parent@1.0.0");
        assert_eq!(components[1].name, "child");
        assert_eq!(components[1].purl, "pkg:cargo/child@2.0.0");
    }

    #[test]
    fn deduplicates_components_by_versioned_purl() {
        let input = br#"
        {
          "components": [
            {"name":"first","version":"1","purl":"pkg:npm/shared@1"},
            {"name":"duplicate","version":"1","purl":"pkg:npm/shared@1"},
            {"name":"other-version","version":"2","purl":"pkg:npm/shared@2"}
          ]
        }
        "#;

        let components = parse_cyclonedx(input).unwrap();

        assert_eq!(components.len(), 2);
        assert_eq!(components[0].name, "first");
        assert_eq!(components[1].name, "other-version");
    }

    #[test]
    fn skips_incomplete_and_unversioned_components() {
        let input = br#"
        {
          "components": [
            {"version":"1","purl":"pkg:cargo/no-name@1"},
            {"name":"no-version","purl":"pkg:cargo/no-version@1"},
            {"name":"no-purl","version":"1"},
            {"name":"blank","version":" ","purl":"pkg:cargo/blank@1"},
            {"name":"unversioned","version":"1","purl":"pkg:cargo/unversioned"},
            {"name":"usable","version":"3","purl":"pkg:cargo/usable@3"}
          ]
        }
        "#;

        let components = parse_cyclonedx(input).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "usable");
    }

    #[test]
    fn rejects_malformed_json() {
        let error = parse_cyclonedx(br#"{"components":["#).unwrap_err();

        assert!(matches!(error, SbomError::MalformedJson(_)));
        assert!(
            error
                .to_string()
                .starts_with("failed to parse CycloneDX JSON:")
        );
    }

    #[test]
    fn rejects_sbom_without_usable_components() {
        let error = parse_cyclonedx(br#"{"components":[{"name":"incomplete"}]}"#).unwrap_err();

        assert!(matches!(error, SbomError::NoUsableComponents));
        assert_eq!(
            error.to_string(),
            "SBOM contains no usable components with name, version, and versioned purl"
        );
    }
}
