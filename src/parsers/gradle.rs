use std::collections::BTreeSet;

use crate::input::{InputError, InventoryBuilder, entry_bound, malformed_msg, utf8};
use crate::model::Scope;

/// Maps the Gradle configurations a locked entry participates in to a
/// dependency scope. Any production configuration wins over test-only and
/// buildscript ones; `classpath` alone marks buildscript/plugin classpath
/// entries (build tooling, not shipped code).
fn gradle_scope(configurations: &str) -> Scope {
    let mut saw_test = false;
    let mut saw_classpath = false;
    for configuration in configurations.split(',') {
        let configuration = configuration.trim();
        if configuration == "classpath" {
            saw_classpath = true;
        } else if configuration.to_ascii_lowercase().contains("test") {
            saw_test = true;
        } else {
            return Scope::Runtime;
        }
    }
    if saw_test {
        Scope::Development
    } else if saw_classpath {
        Scope::Build
    } else {
        // Only reachable for an empty configuration list, which the caller
        // rejects; kept total so the mapping stays honest if that changes.
        Scope::Unknown
    }
}

/// Parses a Gradle dependency lockfile (`*.lockfile`, Gradle 7+ `gradle
/// lockfile`/`--write-locks` output). Each record is one line of
/// `group:artifact:version=conf1,conf2`; `#` lines are comments and the
/// `empty=<confs>` marker records configurations that resolved to no
/// dependencies. Entries become `pkg:maven/<group>/<artifact>@<version>`
/// components.
pub(crate) fn parse_gradle_lockfile(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    const FORMAT: &str = "gradle.lockfile";
    let mut entries = 0_usize;
    for raw in utf8(bytes, path, FORMAT)?.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((coordinates, configurations)) = line.split_once('=') else {
            return Err(malformed_msg(
                path,
                FORMAT,
                format!("line is not a group:artifact:version=configurations record: {line}"),
            ));
        };
        if coordinates == "empty" {
            // `empty=conf1,conf2` records configurations that locked to no
            // dependencies; there is nothing to inventory.
            continue;
        }
        let parts: Vec<&str> = coordinates.split(':').collect();
        if parts.len() != 3 {
            return Err(malformed_msg(
                path,
                FORMAT,
                format!("lock entry is not a group:artifact:version coordinate: {coordinates}"),
            ));
        }
        let (group, artifact, version) = (parts[0], parts[1], parts[2]);
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            return Err(malformed_msg(
                path,
                FORMAT,
                format!("lock entry has an empty coordinate part: {coordinates}"),
            ));
        }
        if configurations
            .split(',')
            .any(|configuration| configuration.trim().is_empty())
        {
            return Err(malformed_msg(
                path,
                FORMAT,
                format!("lock entry has an empty configuration: {line}"),
            ));
        }
        entries += 1;
        entry_bound(entries, path, FORMAT)?;
        out.add(
            "maven",
            &format!("{group}/{artifact}"),
            version,
            gradle_scope(configurations),
            path,
            BTreeSet::new(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use crate::model::Scope;
    use std::fs;
    use tempfile::tempdir;

    /// Real excerpt of flutter/flutter `examples/hello_world/android/
    /// buildscript-gradle.lockfile` (commit 9ead586c), trimmed.
    const BUILDSCRIPT_EXCERPT: &str = concat!(
        "# This is a Gradle generated file for dependency locking.\n",
        "# Manual edits can break the build and are not advised.\n",
        "# This file is expected to be part of source control.\n",
        "androidx.databinding:databinding-common:9.1.0=classpath\n",
        "com.android.tools.build:gradle:9.1.0=classpath\n",
        "org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.0=classpath\n",
        "empty=annotationProcessor\n",
    );

    #[test]
    fn gradle_lockfile_produces_maven_components() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("project-app.lockfile"),
            concat!(
                "# This is a Gradle generated file for dependency locking.\n",
                "commons-lang:commons-lang:2.6=compileClasspath,runtimeClasspath\n",
                "org.jdom:jdom2:2.0.6=runtimeClasspath\n",
                "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n",
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
        assert_eq!(
            component("commons-lang/commons-lang").purl,
            "pkg:maven/commons-lang/commons-lang@2.6"
        );
        assert_eq!(component("commons-lang/commons-lang").scope, Scope::Runtime);
        assert_eq!(component("org.jdom/jdom2").version, "2.0.6");
        assert_eq!(component("junit/junit").scope, Scope::Development);
        assert_eq!(inventory.components.len(), 3);
    }

    #[test]
    fn gradle_buildscript_lockfile_maps_classpath_to_build_scope() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("buildscript-gradle.lockfile"),
            BUILDSCRIPT_EXCERPT,
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.len(), 3);
        let plugin = inventory
            .components
            .values()
            .find(|c| c.name == "org.jetbrains.kotlin/kotlin-gradle-plugin")
            .unwrap();
        assert_eq!(plugin.version, "2.4.0");
        assert_eq!(plugin.scope, Scope::Build);
    }

    #[test]
    fn gradle_lockfile_mixed_configurations_prefer_runtime_scope() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("gradle.lockfile"),
            "a:b:1.0=testCompileClasspath,runtimeClasspath\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let component = inventory.components.values().next().unwrap();
        assert_eq!(component.scope, Scope::Runtime);
    }

    #[test]
    fn gradle_lockfile_fails_closed_on_malformed_lines() {
        for contents in [
            "not-a-lock-record\n",
            "group:artifact=classpath\n",
            "group:artifact:1.0\n",
            "group::1.0=classpath\n",
            "group:artifact:1.0=\n",
            "group:artifact:1.0=classpath,\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("gradle.lockfile"), contents).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { format, .. }) if format == "gradle.lockfile"
                ),
                "expected malformed for: {contents}"
            );
        }
    }
}
