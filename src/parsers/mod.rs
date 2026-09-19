//! Per-ecosystem lockfile and container-image parsers shared by the
//! `input` dispatch layer.

pub(crate) mod archive;
pub(crate) mod bun;
pub(crate) mod cargo;
pub(crate) mod conda;
pub(crate) mod dart;
pub(crate) mod elixir;
pub(crate) mod go;
pub(crate) mod gradle;
pub(crate) mod gradle_catalog;
pub(crate) mod haskell;
pub(crate) mod helm;
pub(crate) mod image;
pub(crate) mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod php;
pub(crate) mod pnpm;
pub(crate) mod python;
pub(crate) mod ruby;
pub(crate) mod swift;
pub(crate) mod yarn;

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::model::ComponentId;

/// Resolved lockfile components keyed by (lowercased) name, then resolved
/// version.
pub(crate) type LockComponents = BTreeMap<String, BTreeMap<String, ComponentId>>;
/// Resolves a lockfile dependency reference against the recorded versions of
/// one component name: the exact requested version when present, otherwise
/// the smallest recorded version satisfying the request when it reads as a
/// version constraint, otherwise the first (lexically smallest) recorded
/// version — matching prior flat-map scan semantics.
pub(crate) fn resolve_lock_component(
    versions: &BTreeMap<String, ComponentId>,
    requested: Option<&str>,
) -> Option<ComponentId> {
    if let Some(id) = requested.and_then(|requested| versions.get(requested)) {
        return Some(id.clone());
    }
    if let Some(requested) = requested
        && let Some(id) = versions
            .iter()
            .filter(|(version, _)| version_satisfies(version, requested))
            .min_by(|(a, _), (b, _)| version_cmp(a, b))
            .map(|(_, id)| id.clone())
    {
        return Some(id);
    }
    versions.values().next().cloned()
}

/// Reports whether a recorded `version` satisfies a lockfile dependency
/// `constraint`. Supports the forms lockfiles actually record: exact pins,
/// `*`/`x` wildcards, `>=`/`>`/`<=`/`<`/`=` comparisons, `^`/`~` npm ranges,
/// `||` alternation, comma/space-separated conjunctions, and NuGet interval
/// notation (`[1,2)`, `(1,]`, `[1]`). Unparseable constraints satisfy
/// nothing so callers fall back to their default resolution.
fn version_satisfies(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();
    if constraint.is_empty() || constraint == "*" {
        return true;
    }
    if constraint.contains("||") {
        return constraint
            .split("||")
            .any(|alternative| version_satisfies(version, alternative));
    }
    if constraint.starts_with(['[', '(']) && constraint.ends_with([']', ')']) {
        return nuget_interval_satisfies(version, constraint);
    }
    // ">= 5" / "<= 2.0" — whitespace between operator and operand is legal
    // in lockfile constraints; collapse it before clause splitting.
    let normalized = constraint
        .replace(">= ", ">=")
        .replace("<= ", "<=")
        .replace("> ", ">")
        .replace("< ", "<")
        .replace("= ", "=");
    normalized
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|clause| !clause.is_empty())
        .all(|clause| version_clause_satisfies(version, clause))
}

/// NuGet interval notation: `[1.0,2.0)` lower-inclusive/upper-exclusive,
/// `(,2.0]` open lower bound, `[1.0]` an exact-version pin.
fn nuget_interval_satisfies(version: &str, constraint: &str) -> bool {
    let lower_inclusive = constraint.starts_with('[');
    let upper_inclusive = constraint.ends_with(']');
    let inner = &constraint[1..constraint.len() - 1];
    let (lower, upper) = match inner.split_once(',') {
        Some((lower, upper)) => (lower.trim(), upper.trim()),
        None => return version_cmp(version, inner.trim()) == Ordering::Equal,
    };
    if !lower.is_empty() {
        let order = version_cmp(version, lower);
        if order == Ordering::Less || (order == Ordering::Equal && !lower_inclusive) {
            return false;
        }
    }
    if !upper.is_empty() {
        let order = version_cmp(version, upper);
        if order == Ordering::Greater || (order == Ordering::Equal && !upper_inclusive) {
            return false;
        }
    }
    true
}

/// One clause of a version conjunction: an operator comparison, an npm
/// `^`/`~` range, a wildcard prefix, or a bare version (minimum-version
/// semantics, matching NuGet; exact pins already matched before this runs).
fn version_clause_satisfies(version: &str, clause: &str) -> bool {
    enum Op {
        Ge,
        Gt,
        Le,
        Lt,
        Eq,
    }
    let (op, operand) = if let Some(rest) = clause.strip_prefix(">=") {
        (Op::Ge, rest)
    } else if let Some(rest) = clause.strip_prefix("<=") {
        (Op::Le, rest)
    } else if let Some(rest) = clause.strip_prefix('>') {
        (Op::Gt, rest)
    } else if let Some(rest) = clause.strip_prefix('<') {
        (Op::Lt, rest)
    } else if let Some(rest) = clause.strip_prefix('=') {
        (Op::Eq, rest)
    } else if let Some(rest) = clause.strip_prefix('^') {
        return npm_caret_satisfies(version, rest.trim());
    } else if let Some(rest) = clause.strip_prefix('~') {
        return npm_tilde_satisfies(version, rest.trim());
    } else {
        (Op::Ge, clause)
    };
    let operand = operand.trim();
    if operand.is_empty() {
        return false;
    }
    if operand == "*" || operand.eq_ignore_ascii_case("x") {
        return true;
    }
    if let Some(prefix) = operand
        .strip_suffix(".*")
        .or_else(|| operand.strip_suffix(".x"))
        .or_else(|| operand.strip_suffix(".X"))
    {
        return version == prefix || version.starts_with(&format!("{prefix}."));
    }
    let order = version_cmp(version, operand);
    match op {
        Op::Ge => order != Ordering::Less,
        Op::Gt => order == Ordering::Greater,
        Op::Le => order != Ordering::Greater,
        Op::Lt => order == Ordering::Less,
        Op::Eq => order == Ordering::Equal,
    }
}

/// npm `^` ranges: `^1.2.3` is `>=1.2.3 <2.0.0`, `^0.2.3` is `>=0.2.3
/// <0.3.0`, `^0.0.3` is `>=0.0.3 <0.0.4` — the upper bound increments the
/// leftmost non-zero component, or the last component when all are zero.
fn npm_caret_satisfies(version: &str, operand: &str) -> bool {
    let Some(mut upper) = numeric_parts(operand) else {
        return false;
    };
    if version_cmp(version, operand) == Ordering::Less {
        return false;
    }
    match upper.iter().position(|part| *part > 0) {
        Some(index) => {
            upper[index] += 1;
            upper.iter_mut().skip(index + 1).for_each(|part| *part = 0);
        }
        None => {
            let last = upper.len() - 1;
            upper[last] += 1;
        }
    }
    version_cmp(version, &join_numeric(&upper)) == Ordering::Less
}

/// npm `~` ranges: `~1.2.3` is `>=1.2.3 <1.3.0`, `~1` is `>=1 <2` — the
/// upper bound increments the minor component, or the major when only one
/// component is given.
fn npm_tilde_satisfies(version: &str, operand: &str) -> bool {
    let Some(mut upper) = numeric_parts(operand) else {
        return false;
    };
    if version_cmp(version, operand) == Ordering::Less {
        return false;
    }
    if upper.len() >= 2 {
        upper[1] += 1;
        upper.iter_mut().skip(2).for_each(|part| *part = 0);
    } else {
        upper[0] += 1;
    }
    version_cmp(version, &join_numeric(&upper)) == Ordering::Less
}

/// Renders numeric version parts back to `a.b.c` text for comparison.
fn join_numeric(parts: &[u64]) -> String {
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Numeric release components of a version operand: `1.2.3` → `[1,2,3]`,
/// wildcard `x`/`*` components count as zero, prerelease/build suffixes are
/// dropped. `None` when a component is not numeric.
fn numeric_parts(version: &str) -> Option<Vec<u64>> {
    let release = version.split(['-', '+']).next().unwrap_or(version);
    release
        .split('.')
        .map(|part| {
            if part.eq_ignore_ascii_case("x") || part == "*" {
                Some(0)
            } else {
                part.parse().ok()
            }
        })
        .collect()
}

/// Compares two version strings semver-ishly: numeric dot-separated release
/// parts (missing parts count as zero), then prerelease identifiers where a
/// prerelease sorts before its release and numeric identifiers rank below
/// alphanumeric ones. Non-numeric release parts compare lexicographically so
/// unusual versions still order deterministically.
fn version_cmp(a: &str, b: &str) -> Ordering {
    let (a_release, a_pre) = split_prerelease(a);
    let (b_release, b_pre) = split_prerelease(b);
    let mut a_parts = a_release.split('.');
    let mut b_parts = b_release.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (None, None) => break,
            (a_part, b_part) => {
                let a_part = a_part.unwrap_or("0");
                let b_part = b_part.unwrap_or("0");
                let order = match (a_part.parse::<u64>(), b_part.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => a_part.cmp(b_part),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a_pre), Some(b_pre)) => {
            let mut a_ids = a_pre.split('.');
            let mut b_ids = b_pre.split('.');
            loop {
                match (a_ids.next(), b_ids.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(a), Some(b)) => {
                        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(a), Ok(b)) => a.cmp(&b),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            _ => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                }
            }
        }
    }
}

/// Splits a version into its release part and optional prerelease suffix,
/// dropping `+build` metadata which never affects precedence.
fn split_prerelease(version: &str) -> (&str, Option<&str>) {
    let version = version.split('+').next().unwrap_or(version);
    match version.split_once('-') {
        Some((release, prerelease)) => (release, Some(prerelease)),
        None => (version, None),
    }
}

/// Reads a YAML scalar as a version string, coercing unquoted numeric
/// scalars (`version: 1.0` parses as a float, `version: 2` as an integer)
/// back to text instead of failing the whole document.
pub(crate) fn yaml_str(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Some(int.to_string())
            } else {
                number.as_f64().map(|float| {
                    if float.is_finite() && float.fract() == 0.0 {
                        format!("{float:.1}")
                    } else {
                        float.to_string()
                    }
                })
            }
        }
        _ => None,
    }
}

/// Splits an npm-style `name@locator` descriptor into package name and locator,
/// honoring `@scope/name` packages and optional pnpm `/`-prefixed lockfile keys.
pub(crate) fn split_descriptor(descriptor: &str) -> Option<(&str, &str)> {
    let rest = descriptor.strip_prefix('/').unwrap_or(descriptor);
    if let Some(scoped) = rest.strip_prefix('@') {
        let at = scoped.find('@')?;
        Some((&rest[..at + 1], &rest[at + 2..]))
    } else {
        let at = rest.find('@')?;
        Some((&rest[..at], &rest[at + 1..]))
    }
}

/// Parses an XML manifest document, tolerating a UTF-8 byte-order mark
/// (Visual Studio and Maven tooling write BOM-prefixed project files) and
/// failing closed on any malformed XML.
pub(crate) fn xml_doc<'a>(
    text: &'a str,
    path: &str,
    format: &'static str,
) -> Result<roxmltree::Document<'a>, crate::input::InputError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    roxmltree::Document::parse(text).map_err(|e| crate::input::malformed(path, format, e))
}

/// Text of the first direct child element named `name`, trimmed; `None`
/// when absent, empty, or mixed-content.
pub(crate) fn child_text<'a>(node: &roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ComponentId;

    fn versions(ids: &[&str]) -> BTreeMap<String, ComponentId> {
        ids.iter()
            .map(|version| {
                (
                    (*version).to_owned(),
                    ComponentId::new(format!("component:{version}")).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn resolve_prefers_smallest_satisfying_version() {
        let recorded = versions(&["4.0.0", "6.0.0"]);
        // `>= 5` must not resolve to 4.0.0 — the satisfying 6.0.0 wins.
        let resolved = resolve_lock_component(&recorded, Some(">= 5")).unwrap();
        assert_eq!(resolved.as_str(), "component:6.0.0");
        // Exact pins still resolve exactly.
        let resolved = resolve_lock_component(&recorded, Some("4.0.0")).unwrap();
        assert_eq!(resolved.as_str(), "component:4.0.0");
        // NuGet intervals: [4.0.0,6.0.0) satisfies 4.0.0 only.
        let resolved = resolve_lock_component(&recorded, Some("[4.0.0,6.0.0)")).unwrap();
        assert_eq!(resolved.as_str(), "component:4.0.0");
        // npm ranges: ^4 resolves 4.0.0, ~6 resolves 6.0.0.
        let resolved = resolve_lock_component(&recorded, Some("^4.0.0")).unwrap();
        assert_eq!(resolved.as_str(), "component:4.0.0");
        // Unsatisfiable and unparseable constraints keep the smallest-
        // recorded fallback.
        let resolved = resolve_lock_component(&recorded, Some(">= 9")).unwrap();
        assert_eq!(resolved.as_str(), "component:4.0.0");
        let resolved = resolve_lock_component(&recorded, None).unwrap();
        assert_eq!(resolved.as_str(), "component:4.0.0");
    }

    #[test]
    fn version_cmp_orders_semver_release_and_prerelease() {
        assert_eq!(version_cmp("1.0.0", "1.0"), Ordering::Equal);
        assert_eq!(version_cmp("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0"), Ordering::Less);
        assert_eq!(
            version_cmp("1.0.0-alpha.1", "1.0.0-alpha"),
            Ordering::Greater
        );
        assert_eq!(version_cmp("1.0.0-2", "1.0.0-beta"), Ordering::Less);
    }

    #[test]
    fn yaml_str_coerces_numeric_scalars() {
        assert_eq!(
            yaml_str(&serde_yaml::Value::String("1.2.3".into())).as_deref(),
            Some("1.2.3")
        );
        let doc: serde_yaml::Value = serde_yaml::from_str("v: 1.0").unwrap();
        assert_eq!(yaml_str(doc.get("v").unwrap()).as_deref(), Some("1.0"));
        let doc: serde_yaml::Value = serde_yaml::from_str("v: 2").unwrap();
        assert_eq!(yaml_str(doc.get("v").unwrap()).as_deref(), Some("2"));
    }
}
