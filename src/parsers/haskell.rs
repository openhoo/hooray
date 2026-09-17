use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::input::{
    InputError, InventoryBuilder, entry_bound, malformed_msg, package_url, sibling, utf8,
};
use crate::model::Scope;

const CABAL: &str = "cabal";
const FREEZE: &str = "cabal.project.freeze";
const MAX_NESTING: usize = 64;

struct Field {
    name: String,
    value: String,
    indent: usize,
    scope: Scope,
}

// Cabal's layout grammar: only whole-line -- comments are comments. In
// particular, an inline -- must not silently truncate a dependency field.
// Explicit-brace stanza layout is deliberately refused rather than misread.
fn fields(text: &str, path: &str, format: &'static str) -> Result<Vec<Field>, InputError> {
    let mut result: Vec<Field> = Vec::new();
    let mut sections: Vec<(usize, Scope)> = Vec::new();
    let mut active = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("--") {
            continue;
        }
        if raw.chars().any(|c| c.is_control() && c != '\t') {
            return Err(malformed_msg(path, format, "control character in document"));
        }
        let indent = raw
            .bytes()
            .take_while(|c| matches!(c, b' ' | b'\t'))
            .count();
        if raw[..indent].contains('\t') {
            return Err(malformed_msg(
                path,
                format,
                "tab indentation is unsupported",
            ));
        }
        if active
            && let Some(field) = result.last_mut()
            && indent > field.indent
        {
            field.value.push(' ');
            field.value.push_str(line);
            continue;
        }
        active = false;
        while sections.last().is_some_and(|(level, _)| *level >= indent) {
            sections.pop();
        }
        let scope = sections.last().map_or(Scope::Runtime, |(_, scope)| *scope);
        if let Some((name, value)) = line.split_once(':')
            && !name.is_empty()
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            result.push(Field {
                name: name.to_ascii_lowercase(),
                value: value.trim().to_owned(),
                indent,
                scope,
            });
            entry_bound(result.len(), path, format)?;
            active = true;
            continue;
        }
        let (keyword, argument) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let scope = match keyword {
            "library" => Scope::Runtime,
            "executable" if !argument.trim().is_empty() => Scope::Runtime,
            "test-suite" | "benchmark" if !argument.trim().is_empty() => Scope::Test,
            "custom-setup" if argument.is_empty() => Scope::Build,
            "common" | "flag" | "source-repository" if !argument.trim().is_empty() => scope,
            "if" | "elif" if !argument.trim().is_empty() => scope,
            "else" if argument.is_empty() => scope,
            _ => {
                return Err(malformed_msg(
                    path,
                    format,
                    "expected a field or supported layout stanza",
                ));
            }
        };
        if line.contains(['{', '}', ';']) || format == FREEZE {
            return Err(malformed_msg(
                path,
                format,
                "explicit-brace or project stanza syntax is unsupported",
            ));
        }
        if sections.len() >= MAX_NESTING {
            return Err(malformed_msg(path, format, "stanza nesting limit exceeded"));
        }
        sections.push((indent, scope));
    }
    Ok(result)
}

fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|part| {
            !part.is_empty()
                && part.bytes().all(|c| c.is_ascii_alphanumeric())
                && part.bytes().any(|c| c.is_ascii_alphabetic())
        })
}

fn version(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|c| c.is_ascii_digit())
                && part.parse::<u32>().is_ok_and(|n| n <= i32::MAX as u32)
        })
}

// Split only at top-level commas: both sublibrary selectors and version sets
// contain commas. Count input entries before deduplication.
fn entries<'a>(
    value: &'a str,
    path: &str,
    format: &'static str,
    edge_comma: bool,
) -> Result<Vec<&'a str>, InputError> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut stack = Vec::new();
    let mut result = Vec::new();
    let mut start = 0;
    for (offset, ch) in value.char_indices() {
        match ch {
            '(' | '{' => {
                if stack.len() >= MAX_NESTING {
                    return Err(malformed_msg(
                        path,
                        format,
                        "dependency nesting limit exceeded",
                    ));
                }
                stack.push(ch);
            }
            ')' | '}' => {
                if stack.pop() != Some(if ch == ')' { '(' } else { '{' }) {
                    return Err(malformed_msg(
                        path,
                        format,
                        "unbalanced dependency delimiters",
                    ));
                }
            }
            ',' if stack.is_empty() => {
                result.push(value[start..offset].trim());
                entry_bound(result.len(), path, format)?;
                start = offset + 1;
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(malformed_msg(path, format, "unclosed dependency delimiter"));
    }
    result.push(value[start..].trim());
    entry_bound(result.len(), path, format)?;
    if edge_comma {
        if result.first() == Some(&"") {
            result.remove(0);
        }
        if result.last() == Some(&"") {
            result.pop();
        }
    }
    if result.is_empty() || result.contains(&"") {
        return Err(malformed_msg(
            path,
            format,
            "empty dependency between commas",
        ));
    }
    Ok(result)
}

struct Range<'a> {
    rest: &'a str,
    spec: (u32, u32),
}

impl<'a> Range<'a> {
    fn take(&mut self, token: &str) -> bool {
        self.rest = self.rest.trim_start();
        if let Some(rest) = self.rest.strip_prefix(token) {
            self.rest = rest;
            true
        } else {
            false
        }
    }

    fn expression(&mut self, depth: usize) -> bool {
        if depth >= MAX_NESTING || !self.atom(depth) {
            return false;
        }
        while self.take("&&") || self.take("||") {
            if !self.atom(depth) {
                return false;
            }
        }
        true
    }

    fn atom(&mut self, depth: usize) -> bool {
        if self.take("(") {
            return self.expression(depth + 1) && self.take(")");
        }
        if self.take("-any") {
            return self.spec < (3, 4);
        }
        if self.take("-none") {
            return self.spec >= (1, 22) && self.spec < (3, 4);
        }
        let Some(op) = ["^>=", "==", ">=", "<=", ">", "<"]
            .into_iter()
            .find(|op| self.take(op))
        else {
            return false;
        };
        if op == "^>=" && self.spec < (2, 0) {
            return false;
        }
        if self.take("{") {
            if self.spec < (3, 0) || !matches!(op, "==" | "^>=") {
                return false;
            }
            loop {
                if !self.number(false) {
                    return false;
                }
                if self.take("}") {
                    return true;
                }
                if !self.take(",") {
                    return false;
                }
            }
        }
        self.number(op == "==")
    }

    fn number(&mut self, wildcard: bool) -> bool {
        self.rest = self.rest.trim_start();
        let end = self
            .rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(self.rest.len());
        let number = &self.rest[..end];
        self.rest = &self.rest[end..];
        if let Some(prefix) = number.strip_suffix('.')
            && self.rest.starts_with('*')
        {
            self.rest = &self.rest[1..];
            return wildcard && version(prefix);
        }
        version(number)
    }
}

fn dependency<'a>(
    entry: &'a str,
    spec: (u32, u32),
    path: &str,
    format: &'static str,
) -> Result<(&'a str, &'a str), InputError> {
    let fail = || malformed_msg(path, format, format!("invalid dependency: {entry}"));
    let end = entry
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .unwrap_or(entry.len());
    let name = &entry[..end];
    if !package_name(name) {
        return Err(fail());
    }
    let mut rest = &entry[end..];
    if let Some(selector) = rest.strip_prefix(':') {
        if spec < (3, 0) {
            return Err(fail());
        }
        if let Some(set) = selector.strip_prefix('{') {
            let Some((libraries, tail)) = set.split_once('}') else {
                return Err(fail());
            };
            if !libraries.split(',').all(|name| package_name(name.trim())) {
                return Err(fail());
            }
            rest = tail;
        } else {
            let end = selector
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .unwrap_or(selector.len());
            if !package_name(&selector[..end]) {
                return Err(fail());
            }
            rest = &selector[end..];
        }
    }
    let constraint = rest.trim();
    if constraint.is_empty() {
        return Ok((name, ""));
    }
    let mut range = Range {
        rest: constraint,
        spec,
    };
    if !range.expression(0) || !range.rest.trim().is_empty() {
        return Err(fail());
    }
    // Only an unambiguous equality is a pin; all other ranges stay raw.
    if let Some(pin) = constraint.strip_prefix("==").map(str::trim)
        && version(pin)
    {
        return Ok((name, pin));
    }
    Ok((name, constraint))
}

fn cabal_spec(fields: &[Field], path: &str) -> Result<(u32, u32), InputError> {
    let Some(field) = fields
        .iter()
        .find(|f| f.name == "cabal-version" && f.indent == 0)
    else {
        return Ok((1, 0));
    };
    let value = field
        .value
        .strip_prefix(">=")
        .unwrap_or(&field.value)
        .trim();
    if !version(value) {
        return Err(malformed_msg(path, CABAL, "invalid cabal-version"));
    }
    let mut parts = value.split('.');
    Ok((
        parts.next().unwrap_or("1").parse().unwrap_or(1),
        parts.next().unwrap_or("0").parse().unwrap_or(0),
    ))
}

struct Frozen<'a> {
    name: &'a str,
    version: &'a str,
    applies: bool,
}

fn frozen<'a>(entry: &'a str, path: &str) -> Result<Option<Frozen<'a>>, InputError> {
    let end = entry
        .find(|c: char| c.is_whitespace() || matches!(c, '=' | '<' | '>' | '^'))
        .unwrap_or(entry.len());
    let (qualified, tail) = entry.split_at(end);
    if tail.trim().is_empty() {
        return Err(malformed_msg(path, FREEZE, "constraint has no property"));
    }
    let (name, applies) = if let Some(name) = qualified.strip_prefix("any.") {
        (name, true)
    } else if let Some(name) = qualified.strip_prefix("setup.") {
        (name, false)
    } else if let Some((owner, name)) = qualified.split_once(":setup.") {
        if !package_name(owner) {
            return Err(malformed_msg(path, FREEZE, "invalid setup qualifier"));
        }
        (name, false)
    } else {
        (qualified, true)
    };
    if !package_name(name) {
        return Err(malformed_msg(path, FREEZE, "invalid package name"));
    }
    let tail = tail.trim();
    if matches!(tail, "installed" | "source" | "test" | "bench")
        || (!tail.is_empty()
            && tail
                .split_whitespace()
                .all(|flag| flag.strip_prefix(['+', '-']).is_some_and(package_name)))
    {
        return Ok(None);
    }
    let (_, version) = dependency(&entry[end - name.len()..], (3, 0), path, FREEZE)?;
    Ok(Some(Frozen {
        name,
        version,
        applies,
    }))
}

fn freeze_fields(bytes: &[u8], path: &str) -> Result<Vec<Field>, InputError> {
    fields(utf8(bytes, path, FREEZE)?, path, FREEZE)
}

fn pins(fields: &[Field], path: &str) -> Result<BTreeMap<String, String>, InputError> {
    let mut result = BTreeMap::new();
    let mut count = 0;
    for field in fields.iter().filter(|field| field.name == "constraints") {
        for entry in entries(&field.value, path, FREEZE, true)? {
            count += 1;
            entry_bound(count, path, FREEZE)?;
            if let Some(frozen) = frozen(entry, path)?
                && frozen.applies
                && version(frozen.version)
                && let Some(previous) =
                    result.insert(frozen.name.to_owned(), frozen.version.to_owned())
                && previous != frozen.version
            {
                return Err(malformed_msg(
                    path,
                    FREEZE,
                    "conflicting exact package constraints",
                ));
            }
        }
    }
    Ok(result)
}

/// Union all build-depends branches; never invoke Cabal or resolve conditions.
/// A nearest in-tree ancestor freeze supplies pins without erasing malformed
/// manifest declarations or unmatched dependencies.
pub(crate) fn parse_cabal(
    path: &str,
    bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let fields = fields(utf8(bytes, path, CABAL)?, path, CABAL)?;
    let spec = cabal_spec(&fields, path)?;
    let name = fields
        .iter()
        .find(|field| field.name == "name" && field.indent == 0)
        .map(|f| f.value.as_str());
    let package_version = fields
        .iter()
        .find(|field| field.name == "version" && field.indent == 0)
        .map(|f| f.value.as_str());
    if !name.is_some_and(package_name) || !package_version.is_some_and(version) {
        return Err(malformed_msg(
            path,
            CABAL,
            "missing or invalid package name/version",
        ));
    }
    let mut freeze_path = sibling(path, FREEZE);
    let frozen = loop {
        if let Some(bytes) = files.get(&freeze_path) {
            break pins(&freeze_fields(bytes, &freeze_path)?, &freeze_path)?;
        }
        let Some((directory, _)) = freeze_path.rsplit_once('/') else {
            break BTreeMap::new();
        };
        freeze_path = sibling(directory, FREEZE);
    };
    let mut count = 0;
    for field in fields.iter().filter(|f| f.name == "build-depends") {
        for entry in entries(&field.value, path, CABAL, spec >= (2, 2))? {
            count += 1;
            entry_bound(count, path, CABAL)?;
            let (name, constraint) = dependency(entry, spec, path, CABAL)?;
            let resolved = frozen.get(name).map_or(constraint, String::as_str);
            let purl = package_url(
                "hackage",
                name,
                if version(resolved) { resolved } else { "" },
            );
            out.add_with_purl(name, resolved, purl, field.scope, path, BTreeSet::new())?;
        }
    }
    out.asset.metadata.insert(
        format!("haskell:{path}"),
        json!({
            "dependency_selection": "union of build-depends across all branches and common stanzas",
            "evaluation": false,
            "validation": "bounded layout and dependency syntax; not Cabal semantic validation",
            "freeze": if frozen.is_empty() { None } else { Some(freeze_path) }
        }),
    );
    Ok(())
}

pub(crate) fn parse_cabal_freeze(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let fields = freeze_fields(bytes, path)?;
    let pins = pins(&fields, path)?;
    for (name, version) in &pins {
        out.add(
            "hackage",
            name,
            version,
            Scope::Unknown,
            path,
            BTreeSet::new(),
        )?;
    }
    // Setup-qualified constraints describe separate dependency trees: inventory
    // their pins too, but never use them to resolve ordinary build-depends.
    for field in fields.iter().filter(|field| field.name == "constraints") {
        for entry in entries(&field.value, path, FREEZE, true)? {
            if let Some(frozen) = frozen(entry, path)?
                && (!frozen.applies || !version(frozen.version))
            {
                let purl = package_url(
                    "hackage",
                    frozen.name,
                    if version(frozen.version) {
                        frozen.version
                    } else {
                        ""
                    },
                );
                let scope = if frozen.applies {
                    Scope::Unknown
                } else {
                    Scope::Build
                };
                out.add_with_purl(
                    frozen.name,
                    frozen.version,
                    purl,
                    scope,
                    path,
                    BTreeSet::new(),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::input::{InputError, config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    const HEADER: &str = "cabal-version: 3.0\nname: demo\nversion: 1.0\n";

    #[test]
    fn ranges_multiline_branches_and_sublibraries_keep_package_identity() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("demo.cabal"), format!("{HEADER}library\n  build-depends:\n    , base >=4.17 && <5\n    , foo:{{foo,internal}} ^>= {{1.0,2.0}}\n  if os(windows)\n    build-depends: Win32 ==2.14.0.0\n  else\n    build-depends: unix >=2.8\n")).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let purls: std::collections::BTreeSet<_> = inventory
            .components
            .values()
            .map(|c| c.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            [
                "pkg:hackage/base",
                "pkg:hackage/foo",
                "pkg:hackage/Win32@2.14.0.0",
                "pkg:hackage/unix"
            ]
            .into()
        );
    }

    #[test]
    fn special_and_parenthesized_ranges_never_become_versions() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("demo.cabal"), format!("{HEADER}library\n  build-depends: foo -any, bar -none, baz (>=1 && <2), quux ==1.2.*\n")).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(inventory.components.values().all(|c| !c.purl.contains('@')));
        assert_eq!(
            inventory
                .components
                .values()
                .find(|c| c.name == "bar")
                .unwrap()
                .version,
            "-none"
        );
        let nested = format!(
            "{}>=1{}",
            "(".repeat(super::MAX_NESTING),
            ")".repeat(super::MAX_NESTING)
        );
        fs::write(
            dir.path().join("demo.cabal"),
            format!("{HEADER}library\n  build-depends: foo {nested}\n"),
        )
        .unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config()),
            Err(InputError::Malformed { .. })
        ));
    }

    #[test]
    fn nearest_freeze_replaces_only_matching_pins_and_preserves_provenance() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("child")).unwrap();
        fs::write(
            dir.path().join("cabal.project.freeze"),
            "constraints: any.aeson ==2.1.0.0\n",
        )
        .unwrap();
        fs::write(dir.path().join("child/cabal.project.freeze"), "constraints: any.aeson ==2.2.3.0, aeson +ordered-keymap, setup.aeson ==1.0\nindex-state: 2026-01-01T00:00:00Z\n").unwrap();
        fs::write(
            dir.path().join("child/demo.cabal"),
            format!("{HEADER}library\n  build-depends: aeson >=2, text >=1\n"),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert!(
            !inventory
                .components
                .values()
                .any(|c| c.purl == "pkg:hackage/aeson")
        );
        let setup = inventory
            .components
            .values()
            .find(|c| c.purl == "pkg:hackage/aeson@1.0")
            .unwrap();
        assert_eq!(setup.scope, crate::model::Scope::Build);
        assert!(
            !setup
                .provenance
                .iter()
                .any(|p| p.locator == "child/demo.cabal")
        );
        let aeson = inventory
            .components
            .values()
            .find(|c| c.purl == "pkg:hackage/aeson@2.2.3.0")
            .unwrap();
        assert!(
            aeson
                .provenance
                .iter()
                .any(|p| p.locator == "child/demo.cabal")
        );
        assert!(
            inventory
                .components
                .values()
                .any(|c| c.purl == "pkg:hackage/text")
        );
    }

    #[test]
    fn malformed_dependencies_are_not_hidden_by_freeze() {
        for dependency in [
            "base >=4.*",
            "base =={2.8.*}",
            "base >=",
            "foo:{} >=1",
            "foo: sub",
            "base,,text",
            "base >=1 garbage",
            "base (>=1",
            "base -- comment",
        ] {
            let dir = tempdir().unwrap();
            fs::write(
                dir.path().join("demo.cabal"),
                format!("{HEADER}library\n  build-depends: {dependency}\n"),
            )
            .unwrap();
            fs::write(
                dir.path().join("cabal.project.freeze"),
                "constraints: base ==4.18\n",
            )
            .unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { .. })
                ),
                "accepted {dependency}"
            );
        }
    }

    #[test]
    fn malformed_documents_and_conflicting_pins_fail_closed() {
        for contents in [
            "not a cabal document",
            "name: demo\nversion: broken\n",
            "name: demo\nversion: 1\nlibrary\n  build-depends: , base\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("demo.cabal"), contents).unwrap();
            assert!(matches!(
                scan_path(dir.path(), &config()),
                Err(InputError::Malformed { .. })
            ));
        }
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("cabal.project.freeze"),
            "constraints: any.base ==4.18, base ==4.19\n",
        )
        .unwrap();
        assert!(matches!(
            scan_path(dir.path(), &config()),
            Err(InputError::Malformed { .. })
        ));
    }
}
