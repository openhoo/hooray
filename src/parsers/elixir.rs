use std::{borrow::Cow, collections::BTreeSet};

use crate::input::{
    InputError, InventoryBuilder, concrete_version_specifier, entry_bound, malformed_msg,
    package_url, utf8,
};
use crate::model::Scope;
use crate::util::{is_purl_byte, percent_encode};

const FORMAT: &str = "mix.lock";
const MAX_DEPTH: usize = 64;
const MAX_TERMS: usize = 1_000_000;

/// Reads only the literal subset written by Mix/Hex, never Elixir code. Terms
/// are released after each entry; both nesting and total work are bounded.
pub(crate) fn parse_mix_lock(
    path: &str,
    bytes: &[u8],
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let mut reader = Reader {
        text: utf8(bytes, path, FORMAT)?,
        offset: 0,
        terms: 0,
        path,
    };
    reader.expect("%{")?;
    let mut names = BTreeSet::new();
    while !reader.take("}") {
        let saved = reader.offset;
        let bare_key = reader.identifier().ok().filter(|_| reader.take(":"));
        let key = if let Some(key) = bare_key {
            Term::Atom(Cow::Borrowed(key))
        } else {
            reader.offset = saved;
            let key = reader.value(0)?;
            if !reader.take(":") {
                reader.expect("=>")?;
            }
            key
        };
        let name = key.text().filter(|name| !name.is_empty()).ok_or_else(|| reader.error("invalid lock key"))?;
        if !names.insert(name.to_owned()) {
            return Err(reader.error("duplicate lock key"));
        }
        entry_bound(names.len(), path, FORMAT)?;
        let lock = reader.value(0)?;
        add_lock(name, &lock, path, out)?;
        if reader.take("}") {
            break;
        }
        reader.expect(",")?;
    }
    reader.space();
    if reader.offset != reader.text.len() {
        return Err(reader.error("trailing content"));
    }
    Ok(())
}

fn add_lock(
    app: &str,
    lock: &Term<'_>,
    path: &str,
    out: &mut InventoryBuilder,
) -> Result<(), InputError> {
    let invalid = || malformed_msg(path, FORMAT, "invalid or unsupported locked source tuple");
    let Term::Tuple(fields) = lock else { return Err(invalid()) };
    match fields.first().and_then(Term::atom) {
        Some("hex") => {
            // Historical Hex locks omit trailing fields; current locks have eight.
            if !(4..=8).contains(&fields.len()) {
                return Err(invalid());
            }
            let name = fields[1].text().filter(|s| !s.is_empty()).ok_or_else(invalid)?;
            let version = fields[2].string().filter(|s| {
                concrete_version_specifier(s).as_deref() == Some(*s)
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
                    && s.as_bytes().first().is_some_and(u8::is_ascii_digit)
            }).ok_or_else(invalid)?;
            if !fields[3].string_or_nil()
                || fields.get(4).is_some_and(|v| !v.atom_list_or_nil())
                || fields.get(5).is_some_and(|v| !v.dependencies_or_nil())
                || fields.get(7).is_some_and(|v| !v.string_or_nil())
            {
                return Err(invalid());
            }
            let repo = match fields.get(6) {
                None => "hexpm",
                Some(term) if term.atom() == Some("nil") => "hexpm",
                Some(term) => term.string().filter(|s| !s.is_empty()).ok_or_else(invalid)?,
            };
            if repo == "hexpm" {
                out.add("hex", name, version, Scope::Runtime, path, BTreeSet::new())?;
            } else {
                // A private Hex repo is not the public OSV Hex package namespace.
                let purl = format!("{}?repository_url={}", package_url("generic", name, version), percent_encode(repo, is_purl_byte));
                out.add_with_purl(name, version, purl, Scope::Runtime, path, BTreeSet::new())?;
            }
        }
        Some("git") => {
            if fields.len() != 4 || !fields[3].keyword_list() {
                return Err(invalid());
            }
            let url = fields[1].string().filter(|s| !s.is_empty()).ok_or_else(invalid)?;
            let revision = fields[2].string().filter(|s| {
                matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
            }).ok_or_else(invalid)?;
            let purl = format!("{}?vcs_url={}", package_url("generic", app, revision), percent_encode(url, is_purl_byte));
            out.add_with_purl(app, revision, purl, Scope::Runtime, path, BTreeSet::new())?;
        }
        // Mix path dependencies do not produce locks. Unknown SCMs cannot be
        // interpreted honestly: refuse the scan rather than drop dependencies.
        _ => return Err(invalid()),
    }
    Ok(())
}

#[derive(Debug)]
enum Term<'a> {
    Atom(Cow<'a, str>),
    String(Cow<'a, str>),
    Integer,
    Tuple(Vec<Term<'a>>),
    List(Vec<Term<'a>>),
}

impl Term<'_> {
    fn text(&self) -> Option<&str> {
        match self { Self::Atom(s) | Self::String(s) => Some(s), _ => None }
    }
    fn atom(&self) -> Option<&str> {
        match self { Self::Atom(s) => Some(s), _ => None }
    }
    fn string(&self) -> Option<&str> {
        match self { Self::String(s) => Some(s), _ => None }
    }
    fn string_or_nil(&self) -> bool {
        self.string().is_some() || self.atom() == Some("nil")
    }
    fn atom_list_or_nil(&self) -> bool {
        self.atom() == Some("nil") || matches!(self, Self::List(v) if v.iter().all(|v| v.atom().is_some()))
    }
    fn keyword_list(&self) -> bool {
        matches!(self, Self::List(v) if v.iter().all(|v| matches!(v, Self::Tuple(pair) if pair.len() == 2 && pair[0].atom().is_some())))
    }
    fn dependencies_or_nil(&self) -> bool {
        self.atom() == Some("nil") || matches!(self, Self::List(v) if v.iter().all(|v| matches!(v, Self::Tuple(dep) if dep.len() == 3 && dep[0].atom().is_some() && dep[1].string_or_nil() && dep[2].keyword_list())))
    }
}

struct Reader<'a> {
    text: &'a str,
    offset: usize,
    terms: usize,
    path: &'a str,
}

impl<'a> Reader<'a> {
    fn error(&self, message: &str) -> InputError {
        malformed_msg(self.path, FORMAT, format!("{message} at byte {}", self.offset))
    }
    fn space(&mut self) {
        loop {
            let rest = &self.text[self.offset..];
            let trimmed = rest.trim_start_matches(char::is_whitespace);
            self.offset += rest.len() - trimmed.len();
            if !trimmed.starts_with('#') { break; }
            self.offset += trimmed.find('\n').unwrap_or(trimmed.len());
        }
    }
    fn take(&mut self, token: &str) -> bool {
        self.space();
        if self.text[self.offset..].starts_with(token) {
            self.offset += token.len();
            true
        } else { false }
    }
    fn expect(&mut self, token: &str) -> Result<(), InputError> {
        if self.take(token) { Ok(()) } else { Err(self.error("unexpected token")) }
    }
    fn value(&mut self, depth: usize) -> Result<Term<'a>, InputError> {
        self.terms += 1;
        if depth > MAX_DEPTH || self.terms > MAX_TERMS {
            return Err(self.error("literal depth or term limit exceeded"));
        }
        self.space();
        if self.take("{") { return self.sequence("}", depth, false).map(Term::Tuple); }
        if self.take("[") { return self.sequence("]", depth, true).map(Term::List); }
        if self.take(":") {
            let atom = if self.take("\"") { self.quoted()? } else { Cow::Borrowed(self.identifier()?) };
            return Ok(Term::Atom(atom));
        }
        if self.take("\"") { return self.quoted().map(Term::String); }
        let start = self.offset;
        let rest = &self.text[start..];
        let digits = rest.strip_prefix('-').unwrap_or(rest);
        let count = digits.bytes().take_while(u8::is_ascii_digit).count();
        if count > 0 {
            self.offset += count + usize::from(rest.starts_with('-'));
            return Ok(Term::Integer);
        }
        let word = self.identifier()?;
        if matches!(word, "nil" | "true" | "false") {
            Ok(Term::Atom(Cow::Borrowed(word)))
        } else {
            Err(self.error("only literal values are supported"))
        }
    }
    fn identifier(&mut self) -> Result<&'a str, InputError> {
        self.space();
        let start = self.offset;
        let rest = &self.text[start..];
        if !rest.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') {
            return Err(self.error("expected atom identifier"));
        }
        self.offset += rest.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@' | b'!' | b'?')).count();
        Ok(&self.text[start..self.offset])
    }
    fn sequence(&mut self, end: &str, depth: usize, keywords: bool) -> Result<Vec<Term<'a>>, InputError> {
        let mut values = Vec::new();
        while !self.take(end) {
            // Elixir keyword syntax is a list of two-element atom tuples.
            let saved = self.offset;
            let key = if keywords {
                if self.take("\"") { Some(self.quoted()?) }
                else { self.identifier().ok().map(Cow::Borrowed) }
            } else { None };
            let value = if let Some(key) = key.filter(|_| self.take(":")) {
                self.terms += 2;
                Term::Tuple(vec![Term::Atom(key), self.value(depth + 1)?])
            } else {
                self.offset = saved;
                self.value(depth + 1)?
            };
            values.push(value);
            if self.take(end) { break; }
            self.expect(",")?;
        }
        Ok(values)
    }
    fn quoted(&mut self) -> Result<Cow<'a, str>, InputError> {
        let start = self.offset;
        let mut chunk = start;
        let mut decoded: Option<String> = None;
        while self.offset < self.text.len() {
            let c = self.text[self.offset..].chars().next().expect("remaining character");
            if c == '"' {
                let end = self.offset;
                self.offset += 1;
                return Ok(match decoded {
                    Some(mut value) => { value.push_str(&self.text[chunk..end]); Cow::Owned(value) }
                    None => Cow::Borrowed(&self.text[start..end]),
                });
            }
            if self.text[self.offset..].starts_with("#{") {
                return Err(self.error("interpolation is not literal lock data"));
            }
            if c == '\\' {
                let value = decoded.get_or_insert_with(String::new);
                value.push_str(&self.text[chunk..self.offset]);
                self.offset += 1;
                let escaped = self.text[self.offset..].chars().next().ok_or_else(|| self.error("truncated escape"))?;
                self.offset += escaped.len_utf8();
                value.push(match escaped {
                    '"' | '\\' | '#' => escaped,
                    'n' => '\n', 'r' => '\r', 't' => '\t',
                    'a' => '\u{7}', 'b' => '\u{8}', 'd' => '\u{7f}',
                    'e' => '\u{1b}', 'f' => '\u{c}', 's' => ' ', 'v' => '\u{b}',
                    'x' | 'u' => self.unicode_escape(escaped)?,
                    _ => return Err(self.error("unsupported string escape")),
                });
                chunk = self.offset;
            } else {
                self.offset += c.len_utf8();
            }
        }
        Err(self.error("unterminated string"))
    }
    fn unicode_escape(&mut self, kind: char) -> Result<char, InputError> {
        let braced = kind == 'u' && self.text[self.offset..].starts_with('{');
        if braced { self.offset += 1; }
        let start = self.offset;
        let size = if braced {
            self.text[start..].find('}').filter(|n| (1..=6).contains(n)).ok_or_else(|| self.error("invalid unicode escape"))?
        } else if kind == 'x' { 2 } else { 4 };
        let digits = self.text.get(start..start + size).filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| self.error("invalid unicode escape"))?;
        let code = u32::from_str_radix(digits, 16).ok().and_then(char::from_u32).ok_or_else(|| self.error("invalid unicode scalar"))?;
        self.offset += size + usize::from(braced);
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{config, scan_path};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn mix_lock_multiline_aliases_and_cross_file_identity() {
        let dir = tempdir().unwrap();
        let lock = r#"%{
          "application_alias": {:hex, :real_package,
            "1.2.3", "checksum", [:mix],
            [{:other, "~> 2.0", [hex: :other, optional: true]}],
            "hexpm", "outer"},
          :other => {:hex, "other", "2.0.0", nil}
        }"#;
        fs::write(dir.path().join("mix.lock"), lock).unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        fs::write(dir.path().join("nested/mix.lock"), lock).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.values().map(|c| c.purl.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from(["pkg:hex/other@2.0.0", "pkg:hex/real_package@1.2.3"]));
        assert!(inventory.components.values().all(|c| c.scope == Scope::Runtime && c.provenance.len() == 2));
    }

    #[test]
    fn mix_lock_nonpublic_sources_keep_distinct_generic_identities() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("mix.lock"), r#"%{
          "source": {:git, "https://example.test/source.git", "0123456789012345678901234567890123456789", [branch: "main", submodules: true, depth: 1]},
          "private": {:hex, :same, "1.0.0", nil, [:mix], [], "private", nil},
          "public": {:hex, :same, "1.0.0", nil, [:mix], [], "hexpm", nil}
        }"#).unwrap();
        let inventory = scan_path(dir.path(), &config()).unwrap();
        assert_eq!(inventory.components.values().map(|c| c.purl.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from([
            "pkg:generic/source@0123456789012345678901234567890123456789?vcs_url=https%3A%2F%2Fexample.test%2Fsource.git",
            "pkg:generic/same@1.0.0?repository_url=private",
            "pkg:hex/same@1.0.0",
        ]));
    }

    #[test]
    fn mix_lock_refuses_malformed_and_nonliteral_input() {
        let dir = tempdir().unwrap();
        for text in [
            "", "%{", "%{a: {:hex, :a, \"1.0.0\", nil}",
            "%{a: {:hex, :a, \"~> 1.0\", nil}}",
            "%{a: {:hex, :a, \"1.0.0\"}}",
            "%{a: {:hex, :a, \"1.0.0\", nil, [:mix], [broken]}}",
            "%{a: {:git, \"url\", \"branch\", []}}",
            "%{a: {:unknown, \"1.0\"}}",
            "%{a: {:hex, :a, \"1.0\", nil}, a: {:hex, :a, \"2.0\", nil}}",
            "%{a: {:hex, :a, \"1.0\", nil}} trailing",
            "%{a: {:hex, :a, \"#{value}\", nil}}",
            "%{a: {:hex, :a, \"1.0\", nil, [], [{:dep, \"~> 1\", [1]}]}}",
        ] {
            fs::write(dir.path().join("mix.lock"), text).unwrap();
            assert!(matches!(scan_path(dir.path(), &config()), Err(InputError::Malformed { .. })), "accepted {text}");
        }
        fs::write(dir.path().join("mix.lock"), format!("%{{a: {}0{}}}", "[".repeat(MAX_DEPTH + 2), "]".repeat(MAX_DEPTH + 2))).unwrap();
        assert!(matches!(scan_path(dir.path(), &config()), Err(InputError::Malformed { .. })));
    }

    #[test]
    fn mix_lock_empty_and_escaped_literal_controls() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("mix.lock"), "%{} # no dependencies\n").unwrap();
        assert!(scan_path(dir.path(), &config()).unwrap().components.is_empty());
        fs::write(dir.path().join("mix.lock"), r#"%{"a": {:hex, :"p\u0061ckage", "1.0.0", "quoted\"checksum", [], [], "hexpm", nil}}"#).unwrap();
        assert_eq!(scan_path(dir.path(), &config()).unwrap().components.values().next().unwrap().purl, "pkg:hex/package@1.0.0");
    }
}
