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

// Tabs count as one indentation character in Cabal, not as tab stops.
// Layout field values are opaque lines (including inline -- and version-set
// braces); explicit field bodies and inline fields use brace delimiters.
struct Layout<'a> {
    rest: &'a str,
    line_start: bool,
    path: &'a str,
    format: &'static str,
    fields: Vec<Field>,
}

impl Layout<'_> {
    fn fail(&self, message: &str) -> InputError {
        malformed_msg(self.path, self.format, message)
    }

    fn advance(&mut self, bytes: usize) {
        self.rest = &self.rest[bytes..];
        self.line_start = false;
    }

    fn newline(&mut self) {
        if self.rest.starts_with("\r\n") {
            self.rest = &self.rest[2..];
        } else {
            self.rest = &self.rest[1..];
        }
        self.line_start = true;
    }

    // Do not consume indentation: callers need it for the layout boundary.
    fn blank_lines(&mut self) {
        loop {
            let trimmed = self.rest.trim_start_matches([' ', '\t']);
            if trimmed.starts_with("--") {
                self.rest = trimmed.trim_start_matches(|c| c != '\n' && c != '\r');
            } else if trimmed.starts_with(['\n', '\r']) {
                self.rest = trimmed;
            } else {
                return;
            }
            if self.rest.is_empty() {
                return;
            }
            self.newline();
        }
    }

    fn braced_value(&mut self) -> Result<String, InputError> {
        self.advance(1);
        let mut value = String::new();
        loop {
            if self.line_start {
                self.blank_lines();
            }
            let end = self
                .rest
                .find(['{', '}', '\n', '\r'])
                .unwrap_or(self.rest.len());
            let line = self.rest[..end].trim();
            if !value.is_empty() && !line.is_empty() {
                value.push(' ');
            }
            value.push_str(line);
            self.advance(end);
            match self.rest.as_bytes().first() {
                Some(b'}') => {
                    self.advance(1);
                    return Ok(value);
                }
                Some(b'\n' | b'\r') => self.newline(),
                Some(b'{') => return Err(self.fail("nested explicit field brace")),
                _ => return Err(self.fail("unclosed explicit field brace")),
            }
        }
    }

    fn field_value(&mut self, indent: Option<usize>) -> Result<String, InputError> {
        self.rest = self.rest.trim_start_matches([' ', '\t']);
        // An opening brace may be on the next non-comment line regardless of
        // indentation. Otherwise restore the newline for layout continuation.
        let saved = (self.rest, self.line_start);
        if self.rest.starts_with(['\n', '\r']) {
            self.blank_lines();
        }
        let trimmed = self.rest.trim_start_matches([' ', '\t']);
        if trimmed.starts_with('{') {
            self.rest = trimmed;
            return self.braced_value();
        }
        (self.rest, self.line_start) = saved;
        let mut value = String::new();
        loop {
            let end = self
                .rest
                .find(|c| matches!(c, '\n' | '\r') || (indent.is_none() && matches!(c, '{' | '}')))
                .unwrap_or(self.rest.len());
            let line = self.rest[..end].trim();
            if !value.is_empty() && !line.is_empty() {
                value.push(' ');
            }
            value.push_str(line);
            self.advance(end);
            if !self.rest.starts_with(['\n', '\r']) {
                return Ok(value);
            }
            self.newline();
            self.blank_lines();
            let spaces = self.rest.len() - self.rest.trim_start_matches([' ', '\t']).len();
            if indent.is_none_or(|indent| spaces <= indent) || self.rest.trim().is_empty() {
                return Ok(value);
            }
            self.advance(spaces);
        }
    }

    fn elements(&mut self, minimum: usize, scope: Scope, depth: usize) -> Result<(), InputError> {
        if depth >= MAX_NESTING {
            return Err(self.fail("stanza nesting limit exceeded"));
        }
        loop {
            self.blank_lines();
            let trimmed = self.rest.trim_start_matches([' ', '\t']);
            let spaces = self.rest.len() - trimmed.len();
            if trimmed.is_empty() || trimmed.starts_with('}') {
                self.rest = trimmed;
                return Ok(());
            }
            let indent = self.line_start.then_some(spaces);
            if indent.is_some_and(|indent| indent < minimum) {
                return Ok(());
            }
            self.advance(spaces);
            let end = self
                .rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .unwrap_or(self.rest.len());
            if end == 0 {
                return Err(self.fail("expected a field or supported layout stanza"));
            }
            let name = self.rest[..end].to_ascii_lowercase();
            self.advance(end);
            self.rest = self.rest.trim_start_matches([' ', '\t']);
            if self.rest.starts_with(':') {
                self.advance(1);
                let value = self.field_value(indent)?;
                self.fields.push(Field {
                    name,
                    value,
                    indent: depth,
                    scope,
                });
                entry_bound(self.fields.len(), self.path, self.format)?;
                continue;
            }
            let mut quoted = false;
            let mut escaped = false;
            let end = self
                .rest
                .char_indices()
                .find_map(|(offset, c)| {
                    if !quoted
                        && (matches!(c, '{' | '}' | '\n' | '\r')
                            || self.rest[offset..].starts_with("--"))
                    {
                        return Some(offset);
                    }
                    if c == '"' && !escaped {
                        quoted = !quoted;
                    }
                    escaped = quoted && c == '\\' && !escaped;
                    None
                })
                .unwrap_or(self.rest.len());
            if quoted {
                return Err(self.fail("unclosed stanza argument quote"));
            }
            let argument = self.rest[..end].trim();
            let child_scope = match name.as_str() {
                "library" => Scope::Runtime,
                "executable" if !argument.is_empty() => Scope::Runtime,
                "test-suite" | "benchmark" if !argument.is_empty() => Scope::Test,
                "custom-setup" if argument.is_empty() => Scope::Build,
                "common" | "flag" | "source-repository" | "if" | "elif" if !argument.is_empty() => {
                    scope
                }
                "else" if argument.is_empty() => scope,
                _ => return Err(self.fail("expected a field or supported layout stanza")),
            };
            if self.format == FREEZE || argument.contains(';') {
                return Err(self.fail("unsupported project stanza syntax"));
            }
            self.advance(end);
            self.blank_lines();
            let trimmed = self.rest.trim_start_matches([' ', '\t']);
            if trimmed.starts_with('{') {
                self.rest = trimmed;
                self.advance(1);
                self.elements(0, child_scope, depth + 1)?;
                if !self.rest.starts_with('}') {
                    return Err(self.fail("unclosed explicit stanza brace"));
                }
                self.advance(1);
            } else if let Some(indent) = indent {
                self.elements(indent + 1, child_scope, depth + 1)?;
            } else {
                return Err(self.fail("inline stanza requires explicit braces"));
            }
        }
    }
}

fn fields(text: &str, path: &str, format: &'static str) -> Result<Vec<Field>, InputError> {
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(malformed_msg(path, format, "control character in document"));
    }
    let mut layout = Layout {
        rest: text,
        line_start: true,
        path,
        format,
        fields: Vec::new(),
    };
    layout.elements(0, Scope::Runtime, 0)?;
    if !layout.rest.is_empty() {
        return Err(layout.fail("unmatched explicit stanza brace"));
    }
    Ok(layout.fields)
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
        // An absent range means unrestricted, not an empty component version.
        // Use the inventory's existing unconstrained specifier convention.
        return Ok((name, "*"));
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
    fn outdated_freeze_preserves_unconstrained_legacy_dependencies() {
        let dir = tempdir().unwrap();
        // Dependency declarations from the pinned Outdated/my.cabal pair.
        fs::write(dir.path().join("my.cabal"), "name: my\nversion: 0.1\ncabal-version: 1.20\nlibrary\n  build-depends: base >= 3 && < 4, binary == 0.8.6.*\ntest-suite tests-Foo\n  build-depends: base, template-haskell >= 2.3.0.0 && < 2.4\n").unwrap();
        fs::write(
            dir.path().join("cabal.project.freeze"),
            "constraints: base == 3.0.3.2, template-haskell ==2.3.0.0, binary ==0.8.5.0\n",
        )
        .unwrap();
        // The real Outdated repo also contains old-style top-level dependency
        // fields with bare containers. Its ancestor freeze does not pin it.
        fs::write(
            dir.path().join("legacy.cabal"),
            "name: legacy\nversion: 0.1\nbuild-depends: base, containers\n",
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let components: std::collections::BTreeMap<_, _> = inventory
            .components
            .values()
            .map(|component| (component.purl.as_str(), component.version.as_str()))
            .collect();
        assert_eq!(
            components,
            [
                ("pkg:hackage/base@3.0.3.2", "3.0.3.2"),
                ("pkg:hackage/binary@0.8.5.0", "0.8.5.0"),
                ("pkg:hackage/template-haskell@2.3.0.0", "2.3.0.0"),
                ("pkg:hackage/containers", "*"),
            ]
            .into()
        );
        // A standalone old-style manifest must not borrow its own version as
        // the dependency version when no freeze file is available.
        let standalone = tempdir().unwrap();
        fs::copy(
            dir.path().join("legacy.cabal"),
            standalone.path().join("legacy.cabal"),
        )
        .unwrap();
        let inventory = scan_path(standalone.path(), &config()).unwrap();
        let components: std::collections::BTreeMap<_, _> = inventory
            .components
            .values()
            .map(|component| (component.purl.as_str(), component.version.as_str()))
            .collect();
        assert_eq!(
            components,
            [("pkg:hackage/base", "*"), ("pkg:hackage/containers", "*")].into()
        );
    }

    #[test]
    fn explicit_and_tab_layouts_preserve_dependencies_and_scope() {
        // Cabal's ParserTests/warnings/tab.cabal uses both tab indentation and
        // explicit field braces. A tab has width one, even alongside spaces.
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("demo.cabal"),
            format!("{HEADER}Library\n\tbuild-depends: {{ base >=4.9 && <4.10 }}\n\t hs-source-dirs: .\nTest-Suite tests\n{{\nif flag(dev) {{ build-depends: {{ aeson ==2.2.3.0 }} }} else {{ build-depends: {{ text >=1 }} }}\n}}\n"),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let components: std::collections::BTreeMap<_, _> = inventory
            .components
            .values()
            .map(|component| (component.purl.as_str(), component.scope))
            .collect();
        assert_eq!(
            components,
            [
                ("pkg:hackage/base", crate::model::Scope::Runtime),
                ("pkg:hackage/aeson@2.2.3.0", crate::model::Scope::Test),
                ("pkg:hackage/text", crate::model::Scope::Test),
            ]
            .into()
        );
    }

    #[test]
    fn field_braces_do_not_capture_following_fields_or_opaque_layout_braces() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("demo.cabal"),
            format!("{HEADER}description: example\n  > if (ready) {{ run(); }}\nlibrary\n  build-depends:\n  {{ base >=4\n     -- whole-line comment\n     && <5 }}\n    build-depends: foo:{{foo,internal}} ^>= {{1.0,2.0}}\n"),
        )
        .unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        let purls: std::collections::BTreeSet<_> = inventory
            .components
            .values()
            .map(|component| component.purl.as_str())
            .collect();
        assert_eq!(purls, ["pkg:hackage/base", "pkg:hackage/foo"].into());
    }

    #[test]
    fn malformed_explicit_layout_fails_closed() {
        for body in [
            "library { build-depends: { base >=4 }",
            "library { build-depends: { base >=4 } }}",
            "library { build-depends: { base >= } }",
            "library { build-depends: { base -- inline comment } }",
            "library { build-depends: { base == {1,2} } }",
            "library { if flag(dev) build-depends: base }",
            "library\n  build-depends: -- not a whole-line comment\n    base >=4\n",
        ] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("demo.cabal"), format!("{HEADER}{body}")).unwrap();
            assert!(
                matches!(
                    scan_path(dir.path(), &config()),
                    Err(InputError::Malformed { .. })
                ),
                "accepted {body}"
            );
        }
    }

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
