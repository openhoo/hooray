use std::collections::BTreeSet;

use serde_json::Value;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed, malformed_msg, utf8};
use crate::model::Scope;

use super::{LockComponents, resolve_lock_component};

/// Parses an MSBuild/NuGet XML document, tolerating a UTF-8 byte-order mark
/// (Visual Studio writes BOM-prefixed project files) and failing closed on
/// any malformed XML.
fn xml_doc<'a>(
    text: &'a str,
    path: &str,
    format: &'static str,
) -> Result<roxmltree::Document<'a>, InputError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    roxmltree::Document::parse(text).map_err(|e| malformed(path, format, e))
}

/// Text of the first direct child element named `name`, trimmed; `None`
/// when absent, empty, or mixed-content.
fn child_text<'a>(node: &roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// Normalizes a NuGet version attribute: `[x]`/`[x]`-style exact-version
/// range notation collapses to the bare `x` so the purl carries a concrete
/// version rather than a specifier.
fn nuget_version(version: &str) -> &str {
    version
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .filter(|v| !v.contains(','))
        .unwrap_or(version)
}

/// Parses `Directory.Packages.props`, the Central Package Management
/// manifest: every `<PackageVersion Include|Update="id" Version="x"/>`
/// (attribute or `<Version>` child element) pins one `pkg:nuget/<id>@<x>`
/// component.
pub(crate) fn parse_directory_packages_props(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    const FORMAT: &str = "Directory.Packages.props";
    let doc = xml_doc(utf8(bytes, path, FORMAT)?, path, FORMAT)?;
    if doc.root_element().tag_name().name() != "Project" {
        return Err(malformed_msg(path, FORMAT, "root element is not Project"));
    }
    let mut entries = 0_usize;
    for node in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "PackageVersion")
    {
        entries += 1;
        entry_bound(entries, path, FORMAT)?;
        let Some(id) = node
            .attribute("Include")
            .or_else(|| node.attribute("Update"))
            .filter(|id| !id.is_empty())
        else {
            return Err(malformed_msg(
                path,
                FORMAT,
                "PackageVersion entry has no Include or Update",
            ));
        };
        let Some(version) = node
            .attribute("Version")
            .or_else(|| child_text(&node, "Version"))
            .filter(|version| !version.is_empty())
        else {
            return Err(malformed_msg(
                path,
                FORMAT,
                "PackageVersion entry has no Version",
            ));
        };
        out.add(
            "nuget",
            &id.to_ascii_lowercase(),
            nuget_version(version),
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

/// Parses a `*.csproj` project file: `<PackageReference>` items with an
/// inline `Version`/`VersionOverride` attribute or `<Version>` child element
/// become `pkg:nuget/<id>@<x>` components. Versionless references (Central
/// Package Management) are skipped — their versions live in
/// `Directory.Packages.props`.
pub(crate) fn parse_csproj(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    const FORMAT: &str = "csproj";
    let doc = xml_doc(utf8(bytes, path, FORMAT)?, path, FORMAT)?;
    if doc.root_element().tag_name().name() != "Project" {
        return Err(malformed_msg(path, FORMAT, "root element is not Project"));
    }
    let mut entries = 0_usize;
    for node in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "PackageReference")
    {
        entries += 1;
        entry_bound(entries, path, FORMAT)?;
        let Some(id) = node
            .attribute("Include")
            .or_else(|| node.attribute("Update"))
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let Some(version) = node
            .attribute("Version")
            .or_else(|| node.attribute("VersionOverride"))
            .or_else(|| child_text(&node, "Version"))
            .filter(|version| !version.is_empty())
        else {
            continue;
        };
        out.add(
            "nuget",
            &id.to_ascii_lowercase(),
            nuget_version(version),
            Scope::Runtime,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

/// Parses a legacy `packages.config`: `<package id="…" version="…"/>`
/// entries become `pkg:nuget/<id>@<x>` components; `developmentDependency`
/// marks the development scope.
pub(crate) fn parse_packages_config(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    const FORMAT: &str = "packages.config";
    let doc = xml_doc(utf8(bytes, path, FORMAT)?, path, FORMAT)?;
    if doc.root_element().tag_name().name() != "packages" {
        return Err(malformed_msg(path, FORMAT, "root element is not packages"));
    }
    let mut entries = 0_usize;
    for node in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "package")
    {
        entries += 1;
        entry_bound(entries, path, FORMAT)?;
        let Some(id) = node.attribute("id").filter(|id| !id.is_empty()) else {
            return Err(malformed_msg(path, FORMAT, "package entry has no id"));
        };
        let Some(version) = node.attribute("version").filter(|v| !v.is_empty()) else {
            return Err(malformed_msg(path, FORMAT, "package entry has no version"));
        };
        let scope = if node
            .attribute("developmentDependency")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            Scope::Development
        } else {
            Scope::Runtime
        };
        out.add(
            "nuget",
            &id.to_ascii_lowercase(),
            nuget_version(version),
            scope,
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

pub(crate) fn parse_nuget_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| malformed(path, "packages.lock.json", e))?;
    let frameworks = value
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed_msg(path, "packages.lock.json", "missing dependencies object"))?;
    let mut ids = LockComponents::new();
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    malformed_msg(
                        path,
                        "packages.lock.json",
                        "package missing resolved version",
                    )
                })?;
            let scope = match package.get("type").and_then(Value::as_str) {
                Some("Direct") => Scope::Runtime,
                Some("Transitive") => Scope::Runtime,
                _ => Scope::Unknown,
            };
            let id = out.add(
                "nuget",
                &name.to_ascii_lowercase(),
                version,
                scope,
                path,
                BTreeSet::new(),
            )?;
            ids.entry(name.to_ascii_lowercase())
                .or_default()
                .insert(version.to_owned(), id);
        }
    }
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name_lower = name.to_ascii_lowercase();
            let Some(from) = ids
                .get(&name_lower)
                .and_then(|versions| versions.get(version))
            else {
                continue;
            };
            for (dependency, constraint) in package
                .get("dependencies")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let requested = constraint.as_str().unwrap_or_default();
                let target = ids
                    .get(&dependency.to_ascii_lowercase())
                    .and_then(|versions| resolve_lock_component(versions, Some(requested)));
                if let Some(to) = target {
                    out.edge(from, &to, Scope::Runtime, false);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use crate::model::Scope;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn directory_packages_props_produces_nuget_components() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Directory.Packages.props"),
            concat!(
                "<Project>\n",
                "  <ItemGroup>\n",
                "    <PackageVersion Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n",
                "    <PackageVersion Update=\"Dapper\" Version=\"2.1.66\" />\n",
                "    <PackageVersion Include=\"Serilog\">\n",
                "      <Version>4.0.2</Version>\n",
                "    </PackageVersion>\n",
                "  </ItemGroup>\n",
                "</Project>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let purl_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.purl.clone())
        };
        assert_eq!(
            purl_of("newtonsoft.json").as_deref(),
            Some("pkg:nuget/newtonsoft.json@13.0.3")
        );
        assert_eq!(
            purl_of("dapper").as_deref(),
            Some("pkg:nuget/dapper@2.1.66")
        );
        assert_eq!(
            purl_of("serilog").as_deref(),
            Some("pkg:nuget/serilog@4.0.2")
        );
        assert_eq!(inventory.components.len(), 3);
    }

    #[test]
    fn csproj_package_reference_versions_become_components() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("App.csproj"),
            concat!(
                "<Project Sdk=\"Microsoft.NET.Sdk\">\n",
                "  <ItemGroup>\n",
                "    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n",
                "    <PackageReference Include=\"Dapper\">\n",
                "      <Version>2.1.66</Version>\n",
                "    </PackageReference>\n",
                "    <PackageReference Include=\"Versionless\" />\n",
                "    <PackageReference Include=\"Overridden\" VersionOverride=\"9.9.9\" />\n",
                "  </ItemGroup>\n",
                "</Project>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let version_of = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .map(|c| c.version.clone())
        };
        assert_eq!(version_of("newtonsoft.json").as_deref(), Some("13.0.3"));
        assert_eq!(version_of("dapper").as_deref(), Some("2.1.66"));
        assert_eq!(version_of("overridden").as_deref(), Some("9.9.9"));
        // Versionless CPM references are not inventoried here.
        assert_eq!(inventory.components.len(), 3);
    }

    #[test]
    fn packages_config_produces_components_with_dev_scope() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("packages.config"),
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<packages>\n",
                "  <package id=\"Newtonsoft.Json\" version=\"13.0.3\" targetFramework=\"net48\" />\n",
                "  <package id=\"xunit\" version=\"2.9.0\" developmentDependency=\"true\" />\n",
                "</packages>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap()
        };
        assert_eq!(component("newtonsoft.json").version, "13.0.3");
        assert_eq!(component("newtonsoft.json").scope, Scope::Runtime);
        assert_eq!(component("xunit").version, "2.9.0");
        assert_eq!(component("xunit").scope, Scope::Development);
        assert_eq!(inventory.components.len(), 2);
    }

    #[test]
    fn nuget_xml_inputs_fail_closed_on_malformed_content() {
        let cases = [
            (
                "Directory.Packages.props",
                "<Project>",
                "Directory.Packages.props",
            ),
            (
                "Directory.Packages.props",
                "<NotProject/>",
                "Directory.Packages.props",
            ),
            ("App.csproj", "<Project", "csproj"),
            ("App.csproj", "<NotProject/>", "csproj"),
            ("packages.config", "<packages>", "packages.config"),
            ("packages.config", "<notpackages/>", "packages.config"),
        ];
        for (name, contents, expected_format) in cases {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), contents).unwrap();
            let error = scan_path(dir.path(), &config()).unwrap_err();
            assert!(
                matches!(
                    &error,
                    InputError::Malformed { format, .. } if *format == expected_format
                ),
                "unexpected error for {name}: {error}"
            );
        }
    }

    #[test]
    fn nuget_xml_entries_missing_required_fields_fail_closed() {
        let cases = [
            (
                "Directory.Packages.props",
                "<Project><ItemGroup><PackageVersion Version=\"1.0\" /></ItemGroup></Project>",
            ),
            (
                "Directory.Packages.props",
                "<Project><ItemGroup><PackageVersion Include=\"A\" /></ItemGroup></Project>",
            ),
            (
                "packages.config",
                "<packages><package version=\"1.0\" /></packages>",
            ),
            (
                "packages.config",
                "<packages><package id=\"A\" /></packages>",
            ),
        ];
        for (name, contents) in cases {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join(name), contents).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { .. })
                ),
                "expected malformed for {name}: {contents}"
            );
        }
    }

    #[test]
    fn csproj_with_utf8_bom_parses() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("App.csproj"),
            "\u{feff}<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageReference Include=\"A\" Version=\"1.0\" /></ItemGroup></Project>",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
    }
}
