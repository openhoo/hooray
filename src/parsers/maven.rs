use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;

use super::{child_text, xml_doc};

const FORMAT: &str = "pom.xml";

/// One `<dependency>` or `<dependencyManagement>` entry with its raw
/// (uninterpolated) field text. `scope`/`optional` stay `Option`s so a
/// `<dependencyManagement>` default can be distinguished from an explicit
/// value on the dependency itself.
#[derive(Default, Clone)]
struct RawDependency {
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
    /// Maven `type` (packaging of the referenced artifact, default `jar`)
    /// and `classifier`: both participate in dependency identity, so
    /// `junit:junit` jar and `junit:junit:test-jar:tests` are distinct.
    type_: Option<String>,
    classifier: Option<String>,
    scope: Option<String>,
    optional: Option<bool>,
}

/// The parts of a POM this parser consumes: the project coordinates, the
/// `<parent>` declaration, `<properties>`, direct `<dependencies>`, and
/// `<dependencyManagement>` entries. Profile-conditional sections are
/// deliberately ignored — they are not statically resolvable.
struct PomModel {
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
    parent: Option<RawDependency>,
    /// `relativePath` verbatim; `Some("")` disables local lookup, `None`
    /// means Maven's default `../pom.xml`.
    parent_relative_path: Option<String>,
    properties: BTreeMap<String, String>,
    dependencies: Vec<RawDependency>,
    managed: Vec<RawDependency>,
}

/// Reads one `<dependency>`/`<parent>` element into a `RawDependency`.
fn raw_dependency(node: &roxmltree::Node<'_, '_>) -> RawDependency {
    RawDependency {
        group_id: child_text(node, "groupId").map(str::to_owned),
        artifact_id: child_text(node, "artifactId").map(str::to_owned),
        version: child_text(node, "version").map(str::to_owned),
        type_: child_text(node, "type").map(str::to_owned),
        classifier: child_text(node, "classifier").map(str::to_owned),
        scope: child_text(node, "scope").map(str::to_owned),
        optional: child_text(node, "optional").map(|value| value == "true"),
    }
}

/// Extracts the model from one POM document. Only direct children of the
/// root `<project>` element are read so `<profiles>`/`<build>`-nested
/// dependency sections do not leak into the inventory.
fn pom_model(text: &str, path: &str) -> Result<PomModel, InputError> {
    let doc = xml_doc(text, path, FORMAT)?;
    let root = doc.root_element();
    if root.tag_name().name() != "project" {
        return Err(malformed_msg(path, FORMAT, "root element is not project"));
    }
    let mut model = PomModel {
        group_id: child_text(&root, "groupId").map(str::to_owned),
        artifact_id: child_text(&root, "artifactId").map(str::to_owned),
        version: child_text(&root, "version").map(str::to_owned),
        parent: None,
        parent_relative_path: None,
        properties: BTreeMap::new(),
        dependencies: Vec::new(),
        managed: Vec::new(),
    };
    for child in root.children().filter(|node| node.is_element()) {
        match child.tag_name().name() {
            "parent" => {
                model.parent = Some(raw_dependency(&child));
                model.parent_relative_path = child
                    .children()
                    .find(|node| node.is_element() && node.tag_name().name() == "relativePath")
                    .map(|node| node.text().unwrap_or_default().trim().to_owned());
            }
            "properties" => {
                for property in child.children().filter(|node| node.is_element()) {
                    if let Some(value) = property.text().map(str::trim) {
                        model
                            .properties
                            .insert(property.tag_name().name().to_owned(), value.to_owned());
                    }
                }
            }
            "dependencies" => {
                for dependency in child.children().filter(|node| node.is_element()) {
                    if dependency.tag_name().name() == "dependency" {
                        model.dependencies.push(raw_dependency(&dependency));
                    }
                }
            }
            "dependencyManagement" => {
                for section in child.children().filter(|node| node.is_element()) {
                    if section.tag_name().name() != "dependencies" {
                        continue;
                    }
                    for dependency in section.children().filter(|node| node.is_element()) {
                        if dependency.tag_name().name() == "dependency" {
                            model.managed.push(raw_dependency(&dependency));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(model)
}

/// Resolves `relativePath` against the directory of `path` inside the
/// scanned file set. `..` segments may not escape the scan root; a resolved
/// directory falls back to its `pom.xml`, matching Maven's treatment of
/// `relativePath` as a project location rather than strictly a file.
fn resolve_relative_path(path: &str, relative: &str) -> Option<String> {
    let mut segments: Vec<&str> = path.split('/').collect();
    segments.pop();
    for segment in relative.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            _ => segments.push(segment),
        }
    }
    let resolved = segments.join("/");
    Some(if resolved.is_empty() {
        "pom.xml".to_owned()
    } else {
        resolved
    })
}

/// Builds the chain of POM models from `path` upward through in-tree
/// `<parent>` references, leaf first. A parent only joins the chain when
/// its file exists inside the scanned tree and its coordinates match the
/// `<parent>` declaration; anything else (missing file, empty
/// `relativePath`, coordinate mismatch, cycle) ends the chain honestly.
fn pom_chain(
    path: &str,
    bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<PomModel>, InputError> {
    let mut chain = vec![pom_model(utf8(bytes, path, FORMAT)?, path)?];
    let mut current_path = path.to_owned();
    loop {
        let model = chain.last().expect("chain starts non-empty");
        let Some(parent) = &model.parent else {
            break;
        };
        if parent.artifact_id.is_none() {
            return Err(malformed_msg(
                &current_path,
                FORMAT,
                "parent declaration has no artifactId",
            ));
        }
        if chain.len() >= 32 {
            // A parent cycle or an unreasonably deep hierarchy: stop
            // resolving rather than walking forever.
            break;
        }
        let relative = model
            .parent_relative_path
            .as_deref()
            .unwrap_or("../pom.xml");
        let parent_path = if relative.is_empty() {
            None
        } else {
            resolve_relative_path(&current_path, relative).and_then(|resolved| {
                if files.contains_key(&resolved) {
                    Some(resolved)
                } else {
                    let as_dir = format!("{resolved}/pom.xml");
                    files.contains_key(&as_dir).then_some(as_dir)
                }
            })
        };
        let Some(parent_path) = parent_path else {
            break;
        };
        // The referenced file must actually be the declared parent:
        // artifactId always, groupId/version whenever both sides state them.
        let parent_bytes = files.get(&parent_path).expect("checked above");
        let parent_model = pom_model(utf8(parent_bytes, &parent_path, FORMAT)?, &parent_path)?;
        let declared = parent;
        let coordinates_match = parent_model.artifact_id == declared.artifact_id
            && declared
                .group_id
                .as_ref()
                .is_none_or(|group| parent_model.group_id.as_ref() == Some(group))
            && declared
                .version
                .as_ref()
                .is_none_or(|version| parent_model.version.as_ref() == Some(version));
        if !coordinates_match {
            break;
        }
        chain.push(parent_model);
        current_path = parent_path;
    }
    Ok(chain)
}

/// Expands `${name}` references against `properties`, iterating so nested
/// values resolve; returns `None` when a reference cannot be resolved or
/// expansion does not converge.
fn interpolate(value: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let mut result = value.to_owned();
    for _ in 0..16 {
        let Some(start) = result.find("${") else {
            return Some(result);
        };
        let end = result[start + 2..].find('}')?;
        let name = &result[start + 2..start + 2 + end];
        let replacement = properties.get(name)?.clone();
        result.replace_range(start..start + 2 + end + 1, &replacement);
    }
    (!result.contains("${")).then_some(result)
}

/// Resource-filtered and mustache templates are not concrete versions, even
/// when `${...}` interpolation itself succeeds. Match paired delimiters, not
/// arbitrary punctuation in otherwise valid Maven versions.
fn resolved_version(value: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let value = interpolate(value, properties)?;
    let filtered = value
        .find('@')
        .is_some_and(|start| value[start + 1..].contains('@'));
    let mustache = value
        .find("{{")
        .is_some_and(|start| value[start + 2..].contains("}}"));
    (!value.is_empty() && !filtered && !mustache).then_some(value)
}

/// Maps a resolved Maven scope to a dependency scope. `compile`/`runtime`
/// ship with the artifact; `test` is development-only; `provided`/`system`
/// are compile-time inputs supplied by the runtime environment (build
/// scope). Unknown scopes stay honest instead of guessing runtime.
fn maven_scope(scope: Option<&str>, optional: bool) -> Scope {
    match scope {
        Some("test") => Scope::Development,
        Some("provided") | Some("system") => Scope::Build,
        Some("compile") | Some("runtime") | Some("") | None => {
            if optional {
                Scope::Optional
            } else {
                Scope::Runtime
            }
        }
        Some(_) => Scope::Unknown,
    }
}

/// `group:artifact:type:classifier` merge key for dependency and
/// dependencyManagement entries; `None` when either coordinate is absent.
/// Type defaults to `jar` and classifier to empty, matching Maven's
/// management-key semantics so a managed `jar` entry applies to a
/// dependency that omits `<type>`.
fn dependency_key(dependency: &RawDependency) -> Option<String> {
    Some(format!(
        "{}:{}:{}:{}",
        dependency.group_id.as_deref()?,
        dependency.artifact_id.as_deref()?,
        dependency.type_.as_deref().unwrap_or("jar"),
        dependency.classifier.as_deref().unwrap_or_default(),
    ))
}

/// The `dependency_key` of a raw entry after `${property}` interpolation:
/// `None` when any coordinate cannot be statically resolved.
fn interpolated_dependency_key(
    dependency: &RawDependency,
    properties: &BTreeMap<String, String>,
) -> Option<String> {
    dependency_key(&RawDependency {
        group_id: dependency
            .group_id
            .as_deref()
            .and_then(|value| interpolate(value, properties)),
        artifact_id: dependency
            .artifact_id
            .as_deref()
            .and_then(|value| interpolate(value, properties)),
        type_: dependency
            .type_
            .as_deref()
            .and_then(|value| interpolate(value, properties)),
        classifier: dependency
            .classifier
            .as_deref()
            .and_then(|value| interpolate(value, properties)),
        ..RawDependency::default()
    })
}

/// `pkg:maven/<group>/<artifact>@<version>` with `type`/`classifier`
/// qualifiers when the artifact is not a plain jar — a test-jar or pom
/// artifact must not collapse into the jar component's identity.
fn maven_purl(group: &str, artifact: &str, version: &str, dependency: &RawDependency) -> String {
    let mut purl = crate::input::package_url("maven", &format!("{group}/{artifact}"), version);
    let mut qualifiers = String::new();
    if let Some(type_) = dependency.type_.as_deref().filter(|type_| *type_ != "jar") {
        qualifiers.push_str(&format!(
            "?type={}",
            crate::util::percent_encode(type_, crate::util::is_purl_byte)
        ));
    }
    if let Some(classifier) = dependency
        .classifier
        .as_deref()
        .filter(|classifier| !classifier.is_empty())
    {
        let separator = if qualifiers.is_empty() { '?' } else { '&' };
        qualifiers.push_str(&format!(
            "{separator}classifier={}",
            crate::util::percent_encode(classifier, crate::util::is_purl_byte)
        ));
    }
    purl.push_str(&qualifiers);
    purl
}

/// Parses a Maven `pom.xml`: direct `<dependencies>` become
/// `pkg:maven/<group>/<artifact>@<version>` components. Versions resolve
/// from the dependency itself, then `<dependencyManagement>` (nearest POM
/// first), with `${property}` interpolation against merged `<properties>`
/// (child wins over in-tree parents). Dependencies whose version cannot be
/// statically resolved — external parents, repository BOM imports — are
/// recorded in per-POM asset metadata rather than inventoried with a fabricated
/// version. Imported BOMs are not followed and are recorded as unresolved sources.
pub(crate) fn parse_pom_xml(
    path: &str,
    bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let chain = pom_chain(path, bytes, files)?;

    // Merge outward-in so nearer POMs override: properties, managed
    // entries, and inherited dependencies all prefer the child.
    let mut properties = BTreeMap::new();
    let mut managed: BTreeMap<String, RawDependency> = BTreeMap::new();
    let mut dependencies: BTreeMap<String, RawDependency> = BTreeMap::new();
    for model in chain.iter().rev() {
        properties.extend(
            model
                .properties
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        for dependency in &model.managed {
            if let Some(key) = dependency_key(dependency) {
                managed.insert(key, dependency.clone());
            }
        }
        for dependency in &model.dependencies {
            if let Some(key) = dependency_key(dependency) {
                dependencies.insert(key, dependency.clone());
            }
        }
    }

    let leaf = &chain[0];
    // Effective project coordinates: an absent groupId/version inherits the
    // *declared* parent coordinates (Maven semantics — the `<parent>`
    // element is authoritative even when the parent POM is not in the
    // scanned tree), then the nearest in-tree ancestor.
    let group_id = leaf.group_id.clone().or_else(|| {
        leaf.parent
            .as_ref()
            .and_then(|parent| parent.group_id.clone())
            .or_else(|| {
                chain
                    .iter()
                    .skip(1)
                    .find_map(|model| model.group_id.clone())
            })
    });
    let version = leaf.version.clone().or_else(|| {
        leaf.parent
            .as_ref()
            .and_then(|parent| parent.version.clone())
            .or_else(|| chain.iter().skip(1).find_map(|model| model.version.clone()))
    });
    let artifact_id = leaf
        .artifact_id
        .clone()
        .ok_or_else(|| malformed_msg(path, FORMAT, "project has no artifactId"))?;

    // Maven's predefined project.* properties participate in interpolation
    // and always reflect the effective coordinates.
    if let Some(group) = &group_id {
        for key in ["project.groupId", "project.parent.groupId", "pom.groupId"] {
            properties.insert(key.to_owned(), group.clone());
        }
    }
    if let Some(version) = &version {
        for key in ["project.version", "project.parent.version", "pom.version"] {
            properties.insert(key.to_owned(), version.clone());
        }
        // `revision` defaults to the project version only when the version
        // is concrete; a literal `${revision}` version must not seed a
        // self-referential property.
        if !version.contains("${revision}") {
            properties
                .entry("revision".to_owned())
                .or_insert_with(|| version.clone());
        }
    }
    // Maven's CI-friendly `sha1`/`changelist` variables default to empty
    // strings, so `${revision}${sha1}${changelist}` resolves to `revision`.
    properties.entry("sha1".to_owned()).or_default();
    properties.entry("changelist".to_owned()).or_default();
    properties.insert("project.artifactId".to_owned(), artifact_id.clone());
    properties.insert("pom.artifactId".to_owned(), artifact_id.clone());

    // #134: dependencyManagement lookups key by *interpolated* coordinates
    // — a managed `${project.groupId}` entry must match a literal `com.x`
    // dependency. Re-key nearest-first so the child still wins when two raw
    // keys interpolate to the same effective key.
    let mut managed_lookup: BTreeMap<String, &RawDependency> = BTreeMap::new();
    for model in chain.iter().rev() {
        for dependency in &model.managed {
            let Some(key) = interpolated_dependency_key(dependency, &properties) else {
                continue;
            };
            managed_lookup.insert(key, dependency);
        }
    }

    let asset_version = version
        .as_deref()
        .and_then(|value| resolved_version(value, &properties));
    let unresolved_asset_version = version.as_ref().filter(|_| asset_version.is_none());
    out.claim_asset_identity(
        path,
        Some(match &group_id {
            Some(group) => format!("{group}:{artifact_id}"),
            None => artifact_id.clone(),
        }),
        asset_version,
    );

    let mut unresolved = Vec::new();
    let mut inventoried = 0usize;
    let mut imported_boms = Vec::new();
    for dependency in managed.values() {
        if dependency
            .scope
            .as_deref()
            .and_then(|value| interpolate(value, &properties))
            .as_deref()
            == Some("import")
        {
            imported_boms.push(json!({
                "identity": dependency_key(dependency),
                "declaredVersion": dependency.version,
                "reason": "imported BOM not followed",
            }));
        }
    }

    entry_bound(dependencies.len(), path, FORMAT)?;
    for (identity, dependency) in &dependencies {
        let Some(group) = dependency
            .group_id
            .as_deref()
            .and_then(|value| interpolate(value, &properties))
        else {
            unresolved.push(json!({
                "identity": identity,
                "declaredVersion": dependency.version,
                "reason": "groupId cannot be statically resolved",
            }));
            continue;
        };
        let Some(artifact) = dependency
            .artifact_id
            .as_deref()
            .and_then(|value| interpolate(value, &properties))
        else {
            unresolved.push(json!({
                "identity": identity,
                "declaredVersion": dependency.version,
                "reason": "artifactId cannot be statically resolved",
            }));
            continue;
        };
        let managed_key = interpolated_dependency_key(
            &RawDependency {
                group_id: Some(group.clone()),
                artifact_id: Some(artifact.clone()),
                type_: dependency
                    .type_
                    .as_deref()
                    .and_then(|value| interpolate(value, &properties)),
                classifier: dependency
                    .classifier
                    .as_deref()
                    .and_then(|value| interpolate(value, &properties)),
                ..RawDependency::default()
            },
            &properties,
        );
        let managed_entry = managed_key.as_ref().and_then(|key| managed_lookup.get(key));
        // `import`-scope entries only exist inside dependencyManagement and
        // are BOM references, not dependencies; skip defensively.
        let scope = dependency
            .scope
            .as_deref()
            .or_else(|| managed_entry.and_then(|entry| entry.scope.as_deref()))
            .and_then(|value| interpolate(value, &properties));
        if scope.as_deref() == Some("import") {
            let diagnostic = json!({
                "identity": format!("{group}:{artifact}"),
                "declaredVersion": dependency.version,
                "reason": "imported BOM not followed",
            });
            imported_boms.push(diagnostic.clone());
            unresolved.push(diagnostic);
            continue;
        }
        // An explicitly declared version wins; otherwise the nearest
        // dependencyManagement entry supplies it. Unresolved declarations
        // remain visible in metadata, never as components sent to OSV.
        let declared_version = dependency
            .version
            .as_deref()
            .or_else(|| managed_entry.and_then(|entry| entry.version.as_deref()));
        let Some(version) = declared_version.and_then(|value| resolved_version(value, &properties))
        else {
            unresolved.push(json!({
                "identity": format!("{group}:{artifact}"),
                "declaredVersion": declared_version,
                "reason": "version cannot be statically resolved",
            }));
            continue;
        };
        let optional = dependency
            .optional
            .or_else(|| managed_entry.and_then(|entry| entry.optional))
            .unwrap_or(false);
        let purl = maven_purl(&group, &artifact, &version, dependency);
        out.add_with_purl(
            &format!("{group}/{artifact}"),
            &version,
            purl,
            maven_scope(scope.as_deref(), optional),
            path,
            BTreeSet::new(),
        )?;
        inventoried += 1;
    }
    let diagnostic = json!({
        "path": path,
        // Counts describe effective declarations after parent/child merging,
        // not globally deduplicated components across the scanned tree.
        "declared": dependencies.len(),
        "inventoried": inventoried,
        "unresolved": unresolved.len(),
        "unresolvedDependencies": unresolved,
        "unresolvedManagedSources": imported_boms,
        "unresolvedAssetVersion": unresolved_asset_version,
    });
    out.asset
        .metadata
        .entry("maven.poms".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("maven.poms is an array")
        .push(diagnostic);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use crate::model::Scope;
    use std::fs;
    use tempfile::tempdir;

    /// Real excerpt of apache/commons-lang `pom.xml` (commit 01a66dd2):
    /// property-interpolated and parent-managed versions, test scopes.
    const COMMONS_LANG_EXCERPT: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n",
        "  <parent>\n",
        "    <groupId>org.apache.commons</groupId>\n",
        "    <artifactId>commons-parent</artifactId>\n",
        "    <version>105</version>\n",
        "  </parent>\n",
        "  <modelVersion>4.0.0</modelVersion>\n",
        "  <artifactId>commons-lang3</artifactId>\n",
        "  <version>3.21.0-SNAPSHOT</version>\n",
        "  <dependencies>\n",
        "    <dependency>\n",
        "      <groupId>org.junit.jupiter</groupId>\n",
        "      <artifactId>junit-jupiter</artifactId>\n",
        "      <scope>test</scope>\n",
        "    </dependency>\n",
        "    <dependency><groupId>org.junit-pioneer</groupId><artifactId>junit-pioneer</artifactId><scope>test</scope></dependency>\n",
        "    <dependency><groupId>org.mockito</groupId><artifactId>mockito-inline</artifactId><scope>test</scope></dependency>\n",
        "    <dependency>\n",
        "      <groupId>org.easymock</groupId>\n",
        "      <artifactId>easymock</artifactId>\n",
        "      <version>5.6.0</version>\n",
        "      <scope>test</scope>\n",
        "    </dependency>\n",
        "    <dependency>\n",
        "      <groupId>org.apache.commons</groupId>\n",
        "      <artifactId>commons-text</artifactId>\n",
        "      <version>${commons.text.version}</version>\n",
        "      <scope>test</scope>\n",
        "    </dependency>\n",
        "    <dependency>\n",
        "      <groupId>org.openjdk.jmh</groupId>\n",
        "      <artifactId>jmh-core</artifactId>\n",
        "      <version>${commons.jmh.version}</version>\n",
        "      <scope>test</scope>\n",
        "    </dependency>\n",
        "    <dependency><groupId>org.openjdk.jmh</groupId><artifactId>jmh-generator-annprocess</artifactId><version>${commons.jmh.version}</version><scope>test</scope></dependency>\n",
        "  </dependencies>\n",
        "  <properties>\n",
        "    <commons.text.version>1.15.0</commons.text.version>\n",
        "  </properties>\n",
        "</project>\n",
    );

    #[test]
    fn pom_xml_inventories_dependencies_with_resolved_versions() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pom.xml"), COMMONS_LANG_EXCERPT).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        let easymock = component("org.easymock/easymock");
        assert_eq!(easymock.version, "5.6.0");
        assert_eq!(easymock.purl, "pkg:maven/org.easymock/easymock@5.6.0");
        assert_eq!(easymock.scope, Scope::Development);
        // ${commons.text.version} resolves from <properties>.
        assert_eq!(
            component("org.apache.commons/commons-text").version,
            "1.15.0"
        );
        // The external parent cannot supply three managed versions and two
        // property-interpolated JMH versions. All five remain visible.
        assert_eq!(inventory.components.len(), 2);
        // The project itself is asset identity, never a component.
        assert_eq!(inventory.asset.name, "org.apache.commons:commons-lang3");
        assert_eq!(inventory.asset.version.as_deref(), Some("3.21.0-SNAPSHOT"));
        let pom = &inventory.asset.metadata["maven.poms"][0];
        assert_eq!(pom["path"], "pom.xml");
        assert_eq!(pom["declared"], 7);
        assert_eq!(pom["inventoried"], 2);
        assert_eq!(pom["unresolved"], 5);
        let identities: Vec<_> = pom["unresolvedDependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["identity"].as_str().unwrap())
            .collect();
        assert_eq!(
            identities,
            vec![
                "org.junit-pioneer:junit-pioneer",
                "org.junit.jupiter:junit-jupiter",
                "org.mockito:mockito-inline",
                "org.openjdk.jmh:jmh-core",
                "org.openjdk.jmh:jmh-generator-annprocess",
            ]
        );
    }

    #[test]
    fn pom_xml_resolves_versions_from_in_tree_parent() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            concat!(
                "<project>\n",
                "  <modelVersion>4.0.0</modelVersion>\n",
                "  <groupId>com.example</groupId>\n",
                "  <artifactId>root</artifactId>\n",
                "  <version>1.0.0</version>\n",
                "  <packaging>pom</packaging>\n",
                "  <modules><module>app</module></modules>\n",
                "  <properties><dep.version>2.1</dep.version></properties>\n",
                "  <dependencyManagement>\n",
                "    <dependencies>\n",
                "      <dependency>\n",
                "        <groupId>com.acme</groupId>\n",
                "        <artifactId>managed-lib</artifactId>\n",
                "        <version>3.0</version>\n",
                "      </dependency>\n",
                "    </dependencies>\n",
                "  </dependencyManagement>\n",
                "</project>\n",
            ),
        )
        .unwrap();
        fs::create_dir(dir.path().join("app")).unwrap();
        fs::write(
            dir.path().join("app/pom.xml"),
            concat!(
                "<project>\n",
                "  <modelVersion>4.0.0</modelVersion>\n",
                "  <parent>\n",
                "    <groupId>com.example</groupId>\n",
                "    <artifactId>root</artifactId>\n",
                "    <version>1.0.0</version>\n",
                "  </parent>\n",
                "  <artifactId>app</artifactId>\n",
                "  <dependencies>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>managed-lib</artifactId>\n",
                "    </dependency>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>prop-lib</artifactId>\n",
                "      <version>${dep.version}</version>\n",
                "    </dependency>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>provided-lib</artifactId>\n",
                "      <version>1.0</version>\n",
                "      <scope>provided</scope>\n",
                "    </dependency>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>optional-lib</artifactId>\n",
                "      <version>1.0</version>\n",
                "      <optional>true</optional>\n",
                "    </dependency>\n",
                "  </dependencies>\n",
                "</project>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = |name: &str| {
            inventory
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing component {name}"))
        };
        // dependencyManagement from the in-tree parent supplies the version.
        assert_eq!(component("com.acme/managed-lib").version, "3.0");
        // Parent <properties> resolve in the child.
        assert_eq!(component("com.acme/prop-lib").version, "2.1");
        assert_eq!(component("com.acme/provided-lib").scope, Scope::Build);
        assert_eq!(component("com.acme/optional-lib").scope, Scope::Optional);
        // The root project does not become a phantom self-dependency.
        assert!(
            !inventory
                .components
                .values()
                .any(|c| c.name == "com.example/root" || c.name == "com.example/app")
        );
        assert_eq!(inventory.components.len(), 4);
    }

    #[test]
    fn pom_xml_skips_dependencies_with_unresolvable_versions() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            concat!(
                "<project>\n",
                "  <modelVersion>4.0.0</modelVersion>\n",
                "  <artifactId>app</artifactId>\n",
                "  <version>1.0</version>\n",
                "  <dependencies>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>unmanaged</artifactId>\n",
                "    </dependency>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>unresolved-prop</artifactId>\n",
                "      <version>${missing.version}</version>\n",
                "    </dependency>\n",
                "    <dependency>\n",
                "      <groupId>com.acme</groupId>\n",
                "      <artifactId>resolved</artifactId>\n",
                "      <version>4.2</version>\n",
                "    </dependency>\n",
                "  </dependencies>\n",
                "</project>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert_eq!(
            inventory.components.values().next().unwrap().purl,
            "pkg:maven/com.acme/resolved@4.2"
        );
    }

    #[test]
    fn pom_xml_templates_are_diagnostics_not_component_or_asset_versions() {
        for template in [
            "@project.version@",
            "{{version}}",
            "${missing}",
            "1-@revision@",
            "1-{{revision}}",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("pom.xml"), format!(r#"
                <project><groupId>g</groupId><artifactId>app</artifactId>
                <version>{template}</version>
                <properties><filtered>{template}</filtered><literal>5.0.5.RELEASE</literal></properties>
                <dependencyManagement><dependencies>
                  <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>${{filtered}}</version></dependency>
                </dependencies></dependencyManagement>
                <dependencies>
                  <dependency><groupId>g</groupId><artifactId>direct</artifactId><version>{template}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
                  <dependency><groupId>g</groupId><artifactId>resolved</artifactId><version>${{literal}}</version><scope>test</scope></dependency>
                </dependencies></project>"#)).unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert_eq!(inventory.asset.version, None, "{template}");
            assert_eq!(inventory.components.len(), 1, "{template}");
            let resolved = inventory.components.values().next().unwrap();
            assert_eq!(resolved.purl, "pkg:maven/g/resolved@5.0.5.RELEASE");
            assert_eq!(resolved.scope, Scope::Development);
            let pom = &inventory.asset.metadata["maven.poms"][0];
            assert_eq!(pom["declared"], 3);
            assert_eq!(pom["inventoried"], 1);
            assert_eq!(pom["unresolved"], 2);
            assert_eq!(pom["unresolvedAssetVersion"], template);
            assert_eq!(pom["unresolvedDependencies"][0]["identity"], "g:direct");
            assert_eq!(pom["unresolvedDependencies"][1]["identity"], "g:managed");
            // Rejecting a shallow placeholder must leave the identity field
            // available to a deeper, concrete declarer.
            fs::create_dir(dir.path().join("child")).unwrap();
            fs::write(dir.path().join("child/pom.xml"),
                "<project><artifactId>child</artifactId><properties><release>1.0-SNAPSHOT</release></properties><version>${release}</version></project>").unwrap();
            let inventory = scan_path(dir.path(), &config()).unwrap();
            assert_eq!(inventory.asset.version.as_deref(), Some("1.0-SNAPSHOT"));
        }
    }

    #[test]
    fn pom_xml_records_unfollowed_boms_and_preserves_resolved_management() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pom.xml"), r#"
            <project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>
            <properties><bom.scope>import</bom.scope><lib.version>2.1</lib.version></properties>
            <dependencyManagement><dependencies>
              <dependency><groupId>g</groupId><artifactId>bom</artifactId><version>[1,2)</version><type>pom</type><scope>${bom.scope}</scope></dependency>
              <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>${lib.version}</version><scope>provided</scope></dependency>
            </dependencies></dependencyManagement>
            <dependencies>
              <dependency><groupId>g</groupId><artifactId>external</artifactId></dependency>
              <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
              <dependency><groupId>g</groupId><artifactId>explicit</artifactId><version>3</version><optional>true</optional></dependency>
            </dependencies></project>"#).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 2);
        let managed = inventory
            .components
            .values()
            .find(|c| c.name == "g/managed")
            .unwrap();
        assert_eq!(managed.version, "2.1");
        assert_eq!(managed.scope, Scope::Build);
        let explicit = inventory
            .components
            .values()
            .find(|c| c.name == "g/explicit")
            .unwrap();
        assert_eq!(explicit.scope, Scope::Optional);
        let pom = &inventory.asset.metadata["maven.poms"][0];
        assert_eq!(pom["declared"], 3);
        assert_eq!(pom["inventoried"], 2);
        assert_eq!(pom["unresolved"], 1);
        assert_eq!(pom["unresolvedDependencies"][0]["identity"], "g:external");
        assert_eq!(pom["unresolvedManagedSources"].as_array().unwrap().len(), 1);
        assert_eq!(pom["unresolvedManagedSources"][0]["identity"], "g:bom:pom:");
        assert_eq!(
            pom["unresolvedManagedSources"][0]["declaredVersion"],
            "[1,2)"
        );
    }

    #[test]
    fn pom_xml_fails_closed_on_malformed_documents() {
        for contents in [
            "<project>",
            "<notproject/>",
            "<project><artifactId></project>",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("pom.xml"), contents).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { format, .. }) if format == "pom.xml"
                ),
                "expected malformed for: {contents}"
            );
        }
    }

    #[test]
    fn pom_xml_parent_coordinate_mismatch_stops_resolution() {
        let dir = tempdir().unwrap();
        // A pom.xml exists at the default relativePath but is not the
        // declared parent → the chain stops and contributes nothing.
        fs::write(
            dir.path().join("pom.xml"),
            "<project><artifactId>other</artifactId><version>9.9</version></project>",
        )
        .unwrap();
        fs::create_dir(dir.path().join("mod")).unwrap();
        fs::write(
            dir.path().join("mod/pom.xml"),
            concat!(
                "<project>\n",
                "  <parent><artifactId>root</artifactId><version>1.0</version></parent>\n",
                "  <artifactId>mod</artifactId>\n",
                "  <dependencies>\n",
                "    <dependency>\n",
                "      <groupId>g</groupId><artifactId>a</artifactId><version>1</version>\n",
                "    </dependency>\n",
                "  </dependencies>\n",
                "</project>\n",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        // The mismatched parent contributes nothing; the module's own
        // dependency still inventories.
        assert_eq!(inventory.components.len(), 1);
        assert_eq!(inventory.components.values().next().unwrap().name, "g/a");
    }

    #[test]
    fn pom_managed_property_coordinates_match_literal_dependencies() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            concat!(
                "<project>
",
                "  <modelVersion>4.0.0</modelVersion>
",
                "  <groupId>com.x</groupId>
",
                "  <artifactId>app</artifactId>
",
                "  <version>1.0.0</version>
",
                "  <dependencyManagement>
",
                "    <dependencies>
",
                "      <dependency>
",
                "        <groupId>${project.groupId}</groupId>
",
                "        <artifactId>lib</artifactId>
",
                "        <version>1.2.3</version>
",
                "      </dependency>
",
                "    </dependencies>
",
                "  </dependencyManagement>
",
                "  <dependencies>
",
                "    <dependency>
",
                "      <groupId>com.x</groupId>
",
                "      <artifactId>lib</artifactId>
",
                "    </dependency>
",
                "  </dependencies>
",
                "</project>
",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "com.x/lib" && c.version == "1.2.3"),
            "managed ${{project.groupId}} entry must resolve the literal dependency"
        );
    }

    #[test]
    fn pom_type_and_classifier_distinguish_dependencies() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            concat!(
                "<project>
",
                "  <modelVersion>4.0.0</modelVersion>
",
                "  <groupId>com.x</groupId>
",
                "  <artifactId>app</artifactId>
",
                "  <version>1.0.0</version>
",
                "  <dependencies>
",
                "    <dependency>
",
                "      <groupId>junit</groupId>
",
                "      <artifactId>junit</artifactId>
",
                "      <version>4.13.2</version>
",
                "    </dependency>
",
                "    <dependency>
",
                "      <groupId>junit</groupId>
",
                "      <artifactId>junit</artifactId>
",
                "      <version>4.13.2</version>
",
                "      <type>test-jar</type>
",
                "      <classifier>tests</classifier>
",
                "    </dependency>
",
                "  </dependencies>
",
                "</project>
",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let purls: Vec<_> = inventory
            .components
            .values()
            .map(|c| c.purl.as_str())
            .collect();
        assert_eq!(purls.len(), 2, "jar and test-jar must both survive");
        assert!(purls.contains(&"pkg:maven/junit/junit@4.13.2"));
        assert!(
            purls
                .iter()
                .any(|p| p.contains("type=test-jar") && p.contains("classifier=tests"))
        );
    }

    #[test]
    fn pom_ci_friendly_sha1_changelist_resolve() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            concat!(
                "<project>
",
                "  <modelVersion>4.0.0</modelVersion>
",
                "  <groupId>com.x</groupId>
",
                "  <artifactId>app</artifactId>
",
                "  <version>${revision}${sha1}${changelist}</version>
",
                "  <properties>
",
                "    <revision>1.2.3</revision>
",
                "  </properties>
",
                "  <dependencies>
",
                "    <dependency>
",
                "      <groupId>com.x</groupId>
",
                "      <artifactId>lib</artifactId>
",
                "      <version>${revision}</version>
",
                "    </dependency>
",
                "  </dependencies>
",
                "</project>
",
            ),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.name == "com.x/lib" && c.version == "1.2.3"),
            "CI-friendly ${{revision}}${{sha1}}${{changelist}} must resolve"
        );
    }
}
