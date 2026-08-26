//! Small shared helpers reused across modules.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Strictly parsed body of a package-URL: the `type/namespace/name` chain
/// plus an optional trailing version. Qualifiers (`?key=value`) and
/// fragments (`#...`) are cut before validation and never surface here.
pub(crate) struct PurlBody<'a> {
    /// Trailing `@version` of the final `/`-segment, when present and
    /// well-formed on both sides of the separator.
    version: Option<&'a str>,
}

impl<'a> PurlBody<'a> {
    pub(crate) fn version(&self) -> Option<&'a str> {
        self.version
    }
}

/// Parses a purl body strictly:
///
/// - the leading `pkg:` prefix is required;
/// - everything from the first `?` or `#` on is cut before validation;
/// - every `/`-separated segment must be non-empty (fail closed);
/// - the version is the last `@` inside the final segment with both sides
///   non-empty; a malformed final segment (e.g. a trailing `@`) yields no
///   version, while a raw `@` in non-final namespace segments (npm scopes
///   like `@babel/core`) is tolerated verbatim.
pub(crate) fn parse_purl_body(purl: &str) -> Option<PurlBody<'_>> {
    let body = purl.strip_prefix("pkg:")?;
    let body = body.split(['?', '#']).next().unwrap_or(body);
    let final_segment = match body.rsplit_once('/') {
        Some((namespace, name)) => {
            if name.is_empty() || namespace.split('/').any(str::is_empty) {
                return None;
            }
            name
        }
        None => body,
    };
    if final_segment.is_empty() {
        return None;
    }
    // The version separator is the last `@` of the FINAL segment only, and
    // must leave both name and version non-empty; anything else fails closed.
    let version = final_segment
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map(|(_, version)| version);
    Some(PurlBody { version })
}

/// Percent-encodes every byte rejected by `keep` as uppercase `%XX`;
/// kept bytes pass through verbatim.
pub(crate) fn percent_encode(value: &str, keep: fn(u8) -> bool) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if keep(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Purl bytes: RFC 3986 unreserved characters plus `+`.
pub(crate) fn is_purl_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+')
}

/// Path URI bytes: RFC 3986 unreserved characters plus `/`.
pub(crate) fn is_path_uri_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~')
}

/// Strict percent-decode: `None` for a truncated or non-hex escape or a
/// non-UTF-8 result; moved verbatim from remediation.rs.
pub(crate) fn percent_decode_strict(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            output.push(u8::from_str_radix(text, 16).ok()?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

/// Replaces every control character ([`char::is_control`]) with a space so
/// untrusted text cannot smuggle terminal escapes into single-line output;
/// mirrors `monitor::redact_error`.
pub fn sanitize_cell_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        is_path_uri_byte, is_purl_byte, parse_purl_body, percent_decode_strict, percent_encode,
        sanitize_cell_text,
    };

    #[test]
    fn extracts_versions_from_scoped_and_namespaced_bodies() {
        assert_eq!(
            parse_purl_body("pkg:npm/@babel/core@7.0.0")
                .unwrap()
                .version(),
            Some("7.0.0")
        );
        assert_eq!(
            parse_purl_body("pkg:golang/github.com/foo/bar@v1.2.3")
                .unwrap()
                .version(),
            Some("v1.2.3")
        );
        assert_eq!(
            parse_purl_body("pkg:cargo/a@1").unwrap().version(),
            Some("1")
        );
    }

    #[test]
    fn unversioned_scoped_names_carry_no_version() {
        assert_eq!(
            parse_purl_body("pkg:npm/@babel/core").unwrap().version(),
            None
        );
        assert_eq!(parse_purl_body("pkg:npm/a").unwrap().version(), None);
    }

    #[test]
    fn cuts_qualifiers_and_fragments_before_validation() {
        assert_eq!(
            parse_purl_body("pkg:npm/a@1.0?key=v#frag")
                .unwrap()
                .version(),
            Some("1.0")
        );
        assert_eq!(
            parse_purl_body("pkg:maven/group/artifact#sha:abc")
                .unwrap()
                .version(),
            None
        );
    }

    #[test]
    fn rejects_empty_segments_structurally() {
        for purl in [
            "not-a-purl:x@1",
            "pkg:",
            "pkg:/x@1",
            "pkg://x@1",
            "pkg:npm//x@1",
            "pkg:npm/x/",
            "pkg:npm/x@1/",
        ] {
            assert!(parse_purl_body(purl).is_none(), "{purl}");
        }
    }

    #[test]
    fn malformed_final_segments_fail_closed_without_a_version() {
        assert_eq!(parse_purl_body("pkg:npm/a@").unwrap().version(), None);
        assert_eq!(parse_purl_body("pkg:npm/@1").unwrap().version(), None);
        assert_eq!(parse_purl_body("pkg:x/@1").unwrap().version(), None);
        // Last-`@` rule matches the previous rsplit semantics.
        assert_eq!(parse_purl_body("pkg:a@b@1").unwrap().version(), Some("1"));
        assert_eq!(parse_purl_body("pkg:a@b@").unwrap().version(), None);
    }

    #[test]
    fn purl_predicate_preserves_unreserved_and_plus() {
        assert_eq!(
            percent_encode("safe-name._~+v1.0", is_purl_byte),
            "safe-name._~+v1.0"
        );
        assert_eq!(percent_encode("a b/c@%", is_purl_byte), "a%20b%2Fc%40%25");
        // Uppercase hex; UTF-8 encodes byte-wise.
        assert_eq!(percent_encode("ü", is_purl_byte), "%C3%BC");
        assert_eq!(percent_encode("", is_purl_byte), "");
    }

    #[test]
    fn path_uri_predicate_keeps_slashes_but_escapes_plus() {
        assert_eq!(
            percent_encode("dir/sub_file-1.0~", is_path_uri_byte),
            "dir/sub_file-1.0~"
        );
        assert_eq!(percent_encode("a b+c/", is_path_uri_byte), "a%20b%2Bc/");
        assert_eq!(percent_encode("@", is_path_uri_byte), "%40");
    }

    #[test]
    fn encode_then_strict_decode_round_trips_arbitrary_names() {
        for name in ["serde", "@scope/pkg name+1.0", "ü/ä@%", "~tilde_-._"] {
            for predicate in [is_purl_byte as fn(u8) -> bool, is_path_uri_byte] {
                assert_eq!(
                    percent_decode_strict(&percent_encode(name, predicate)).as_deref(),
                    Some(name)
                );
            }
        }
    }

    #[test]
    fn strict_decoding_fails_closed_like_the_moved_body() {
        assert_eq!(percent_decode_strict("abc").as_deref(), Some("abc"));
        assert_eq!(percent_decode_strict("%C3%BC").as_deref(), Some("ü"));
        assert_eq!(percent_decode_strict("%FF"), None);
        assert_eq!(percent_decode_strict("%zz"), None);
        assert_eq!(percent_decode_strict("a%2"), None);
        assert_eq!(percent_decode_strict("trailing%"), None);
    }

    #[test]
    fn sanitize_cell_text_maps_control_characters_to_spaces() {
        assert_eq!(sanitize_cell_text("a\r\nb\tc"), "a  b c");
        assert_eq!(sanitize_cell_text("\x1b[31mred\x1b[0m"), " [31mred [0m");
        assert_eq!(sanitize_cell_text("\x1b]8;;url\x1b\\\u{7}"), " ]8;;url \\ ");
        assert_eq!(sanitize_cell_text("\x0b\x0c"), "  ");
        assert_eq!(sanitize_cell_text("plain |pipe| é"), "plain |pipe| é");
    }
}
