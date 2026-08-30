use std::{collections::BTreeMap, path::Path, sync::LazyLock};

use regex::Regex;

use crate::model::{Confidence, FindingKind, Severity};

use super::spans::{non_code_spans, offset_in_non_code_span};
use super::{FindingBuilder, FindingSpec, indexed_line_column, line_starts};

struct SastRule {
    rule: &'static str,
    regex: Regex,
    summary: &'static str,
    cwe: &'static str,
    severity: Severity,
    remediation: &'static str,
}

/// One compile-time SAST rule: finding metadata plus the regex pattern that
/// [`SAST_RULES`] compiles once at first use.
struct SastRuleSpec {
    rule: &'static str,
    pattern: &'static str,
    summary: &'static str,
    cwe: &'static str,
    severity: Severity,
    remediation: &'static str,
}

/// `(extensions, rules)` table; every extension in the first slice maps to
/// the same compiled rule list.
const SAST_RULE_TABLE: &[(&[&str], &[SastRuleSpec])] = &[
    (
        &["rs"],
        &[
            SastRuleSpec {
                rule: "sast.rust.command-shell",
                pattern: r#"\bCommand\s*::\s*new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*\)\s*\.\s*arg\s*\(\s*["'](?:-c|/C|Command)["']\s*\)\s*\.\s*arg\s*\([^"']"#,
                summary: "Dynamic shell command execution",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Pass fixed arguments directly to the target executable and strictly map permitted operations.",
            },
            SastRuleSpec {
                rule: "sast.rust.sql-format",
                pattern: r#"(?s)\b(?:query|execute)\s*\(\s*&?format!\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b"#,
                summary: "Formatted SQL passed to a database API",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use parameterized queries and bind every untrusted value.",
            },
            SastRuleSpec {
                rule: "sast.rust.weak-hash-md5",
                pattern: r"\bMd5\s*::\s*new\s*\(",
                summary: "MD5 hash construction",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Use SHA-256 or BLAKE3; MD5 is broken for security-sensitive digests.",
            },
            SastRuleSpec {
                rule: "sast.rust.weak-hash-sha1",
                pattern: r"\bSha1\s*::\s*new\s*\(",
                summary: "SHA-1 hash construction",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Use SHA-256 or BLAKE3; SHA-1 is broken for security-sensitive digests.",
            },
        ],
    ),
    (
        &["js", "jsx", "ts", "tsx"],
        &[
            SastRuleSpec {
                rule: "sast.javascript.eval-dynamic",
                pattern: r"\b(?:eval|Function)\s*\(\s*",
                summary: "Dynamic JavaScript evaluation",
                cwe: "CWE-95",
                severity: Severity::High,
                remediation: "Replace dynamic evaluation with explicit parsing and a fixed dispatch table.",
            },
            SastRuleSpec {
                rule: "sast.javascript.exec-dynamic",
                pattern: r#"(?m)(?:^|[^.A-Za-z0-9_$])(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^"'`])"#,
                summary: "Dynamic command execution",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Use spawn/execFile with a fixed executable and validated argument array.",
            },
            SastRuleSpec {
                rule: "sast.javascript.sql-template",
                pattern: r"\b(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{",
                summary: "Interpolated SQL query",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use driver placeholders and parameter binding.",
            },
            SastRuleSpec {
                rule: "sast.javascript.weak-hash",
                pattern: r#"\bcreateHash\s*\(\s*["'](md5|sha1)["']\s*\)"#,
                summary: "Weak hash algorithm selected",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Hash with createHash('sha256') or stronger algorithms.",
            },
        ],
    ),
    (
        &["py"],
        &[
            SastRuleSpec {
                rule: "sast.python.eval-dynamic",
                pattern: r"\b(?:eval|exec)\s*\(\s*",
                summary: "Dynamic Python evaluation",
                cwe: "CWE-95",
                severity: Severity::High,
                remediation: "Parse expected data formats and use explicit operations rather than eval or exec.",
            },
            SastRuleSpec {
                rule: "sast.python.shell-true",
                pattern: r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^\)]*\bshell\s*=\s*True",
                summary: "Python subprocess enables a command shell",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Set shell=False and pass a fixed executable plus a validated argument list.",
            },
            SastRuleSpec {
                rule: "sast.python.sql-format",
                pattern: r#"(?i)\.execute\s*\(\s*(?:f["']|["'][^"']*(?:select|insert|update|delete)[^"']*["']\s*(?:%|\.format\s*\())"#,
                summary: "Formatted SQL execution",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use DB-API placeholders and a separate parameter sequence.",
            },
            SastRuleSpec {
                rule: "sast.python.weak-hash-md5",
                pattern: r"\bhashlib\.md5\s*\(",
                summary: "MD5 hash usage",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Prefer hashlib.sha256 or stronger for security-sensitive digests.",
            },
            SastRuleSpec {
                rule: "sast.python.weak-hash-sha1",
                pattern: r"\bhashlib\.sha1\s*\(",
                summary: "SHA-1 hash usage",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Prefer hashlib.sha256 or stronger for security-sensitive digests.",
            },
            SastRuleSpec {
                rule: "sast.python.pickle-deserialization",
                pattern: r"\bpickle\.loads?\s*\(",
                summary: "Pickle deserialization",
                cwe: "CWE-502",
                severity: Severity::High,
                remediation: "Exchange data in inert formats such as JSON instead of unpickling bytes.",
            },
            SastRuleSpec {
                rule: "sast.python.yaml-unsafe-load",
                pattern: r"\byaml\.load\s*\(",
                summary: "YAML load without a restricted Loader",
                cwe: "CWE-502",
                severity: Severity::High,
                remediation: "Use yaml.safe_load or pass an explicit Loader limited to safe types.",
            },
        ],
    ),
    (
        &["go"],
        &[
            SastRuleSpec {
                rule: "sast.go.command-shell",
                pattern: r#"\bexec\.Command\s*\(\s*["'](?:sh|bash)["']\s*,\s*["']-c["']\s*,\s*[^"']"#,
                summary: "Dynamic shell command execution",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Invoke the intended executable directly with a validated argument slice.",
            },
            SastRuleSpec {
                rule: "sast.go.sql-format",
                pattern: r#"\b(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b"#,
                summary: "Formatted SQL passed to database/sql",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use database/sql placeholders and pass values as query arguments.",
            },
            SastRuleSpec {
                rule: "sast.go.weak-hash-md5",
                pattern: r"\bmd5\.New\s*\(",
                summary: "MD5 hash construction",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Use crypto/sha256 or stronger hashes for security-sensitive digests.",
            },
            SastRuleSpec {
                rule: "sast.go.weak-hash-sha1",
                pattern: r"\bsha1\.New\s*\(",
                summary: "SHA-1 hash construction",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Use crypto/sha256 or stronger hashes for security-sensitive digests.",
            },
        ],
    ),
    (
        &["java"],
        &[
            SastRuleSpec {
                rule: "sast.java.runtime-exec",
                pattern: r"\bRuntime\.getRuntime\(\)\.exec\s*\(\s*",
                summary: "Dynamic Runtime.exec command",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Use ProcessBuilder with a fixed executable and validated arguments.",
            },
            SastRuleSpec {
                rule: "sast.java.sql-concat",
                pattern: r#"\b(?:executeQuery|executeUpdate|execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+"#,
                summary: "Concatenated SQL execution",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use PreparedStatement placeholders and typed setters.",
            },
            SastRuleSpec {
                rule: "sast.java.weak-hash",
                pattern: r#"\bMessageDigest\s*\.\s*getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']\s*\)"#,
                summary: "Weak MessageDigest algorithm requested",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Request SHA-256 or stronger digest algorithms.",
            },
            SastRuleSpec {
                rule: "sast.java.unsafe-deserialization",
                pattern: r"\bObjectInputStream\b[^;\n]*?\.readObject\s*\(",
                summary: "Native Java deserialization",
                cwe: "CWE-502",
                severity: Severity::High,
                remediation: "Parse untrusted bytes with schema-based formats instead of ObjectInputStream.readObject.",
            },
        ],
    ),
    (
        &["cs"],
        &[
            SastRuleSpec {
                rule: "sast.csharp.process-shell",
                pattern: r#"\bProcess\.Start\s*\(\s*["'](?:cmd\.exe|powershell(?:\.exe)?)["']\s*,\s*[^"']"#,
                summary: "Dynamic shell process execution",
                cwe: "CWE-78",
                severity: Severity::High,
                remediation: "Use ProcessStartInfo.ArgumentList with a fixed executable and validated arguments.",
            },
            SastRuleSpec {
                rule: "sast.csharp.sql-concat",
                pattern: r#"\b(?:SqlCommand|ExecuteSqlRaw)\s*\(\s*(?:\$["']|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)"#,
                summary: "Interpolated or concatenated SQL",
                cwe: "CWE-89",
                severity: Severity::High,
                remediation: "Use SQL parameters or ExecuteSqlInterpolated with trusted query structure.",
            },
            SastRuleSpec {
                rule: "sast.csharp.weak-hash",
                pattern: r"\b(?:MD5|SHA1)\.Create\s*\(\s*\)",
                summary: "Weak hash algorithm instance",
                cwe: "CWE-327",
                severity: Severity::Medium,
                remediation: "Create SHA256 or stronger hash instances for security-sensitive digests.",
            },
            SastRuleSpec {
                rule: "sast.csharp.unsafe-deserialization",
                pattern: r"\bBinaryFormatter\b[^;\n]*?\.Deserialize\s*\(",
                summary: "BinaryFormatter deserialization",
                cwe: "CWE-502",
                severity: Severity::High,
                remediation: "Replace BinaryFormatter with a safe serializer; never deserialize untrusted input.",
            },
        ],
    ),
];

static SAST_RULES: LazyLock<BTreeMap<&'static str, Vec<SastRule>>> = LazyLock::new(|| {
    let mut by_extension = BTreeMap::new();
    for (extensions, rules) in SAST_RULE_TABLE {
        for extension in *extensions {
            by_extension.insert(
                *extension,
                rules
                    .iter()
                    .map(|spec| SastRule {
                        rule: spec.rule,
                        regex: Regex::new(spec.pattern).expect("constant SAST regex"),
                        summary: spec.summary,
                        cwe: spec.cwe,
                        severity: spec.severity,
                        remediation: spec.remediation,
                    })
                    .collect(),
            );
        }
    }
    by_extension
});

pub(super) fn scan_sast(path: &str, text: &str, builder: &mut FindingBuilder<'_>) {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(rules) = SAST_RULES.get(extension.as_str()) else {
        return;
    };
    let line_starts = line_starts(text);
    let non_code = non_code_spans(text, &extension);
    for rule in rules {
        for matched in rule.regex.find_iter(text) {
            if offset_in_non_code_span(&non_code, matched.start()) {
                continue;
            }
            let line_end = text[matched.start()..]
                .find('\n')
                .map_or(text.len(), |relative| matched.start() + relative);
            let line_start = text[..matched.start()]
                .rfind('\n')
                .map_or(0, |offset| offset + 1);
            if text[line_start..line_end]
                .to_ascii_lowercase()
                .contains("hooray:allow-sast")
            {
                continue;
            }
            if matches!(
                rule.rule,
                "sast.javascript.eval-dynamic"
                    | "sast.python.eval-dynamic"
                    | "sast.java.runtime-exec"
            ) && has_single_literal_argument(&text[matched.end()..])
            {
                continue;
            }
            if rule.rule == "sast.python.yaml-unsafe-load"
                && yaml_call_specifies_loader(&text[matched.end()..])
            {
                continue;
            }
            let (line, column) = indexed_line_column(&line_starts, matched.start());
            builder.add(FindingSpec { kind: FindingKind::Sast, rule: rule.rule, line, column, summary: rule.summary, details: "A language-specific call expression uses a dangerous sink with dynamic or explicitly unsafe syntax.", severity: rule.severity, confidence: Confidence::High, description: "Dangerous sink invocation detected; source expression omitted.".to_owned(), references: &["https://owasp.org/www-project-code-review-guide/"], properties: BTreeMap::new(), redacted: true, remediation: rule.remediation, cwe: Some(rule.cwe) });
        }
    }
}

fn has_single_literal_argument(after_open_paren: &str) -> bool {
    let source = after_open_paren.trim_start();
    let mut chars = source.char_indices();
    let Some((_, quote @ ('\'' | '"' | '`'))) = chars.next() else {
        return false;
    };
    let mut escaped = false;
    for (offset, character) in chars {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if quote == '`' && character == '$' && source[offset..].starts_with("${") {
            return false;
        }
        if character == quote {
            return source[offset + character.len_utf8()..]
                .trim_start()
                .starts_with(')');
        }
    }
    false
}

static YAML_RESTRICTED_LOADER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Loader\s*=|C?SafeLoader|BaseLoader)\b")
        .expect("constant YAML restricted-loader regex")
});

pub(super) fn yaml_call_specifies_loader(after_open_paren: &str) -> bool {
    const MAX_CALL_ARGUMENT_SCAN_BYTES: usize = 16 * 1024;
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut end = after_open_paren.len().min(MAX_CALL_ARGUMENT_SCAN_BYTES);
    for (index, character) in after_open_paren.char_indices() {
        if index >= MAX_CALL_ARGUMENT_SCAN_BYTES {
            break;
        }
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' => {
                if depth == 0 {
                    end = index;
                    break;
                }
                depth -= 1;
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    // The byte cap can stop inside a multi-byte UTF-8 character; fall back to
    // the nearest char boundary so slicing can never panic on crafted input.
    while end > 0 && !after_open_paren.is_char_boundary(end) {
        end -= 1;
    }
    YAML_RESTRICTED_LOADER_REGEX.is_match(&after_open_paren[..end])
}
