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
    let mut emitted_exec_spans = Vec::new();
    for rule in rules {
        let mut finding = SastFindingContext {
            rule,
            text,
            non_code: &non_code,
            line_starts: &line_starts,
            emitted_spans: &mut emitted_exec_spans,
            deduplicate: rule.rule == "sast.javascript.exec-dynamic",
            builder,
        };
        for matched in rule.regex.find_iter(text) {
            emit_sast_finding(&mut finding, matched.start(), matched.end());
        }
    }
    if matches!(extension.as_str(), "js" | "jsx" | "ts" | "tsx")
        && let Some(rule) = rules
            .iter()
            .find(|rule| rule.rule == "sast.javascript.exec-dynamic")
    {
        scan_javascript_exec_receivers(
            text,
            &non_code,
            &line_starts,
            rule,
            &mut emitted_exec_spans,
            builder,
        );
    }
}

struct SastFindingContext<'a, 'b> {
    rule: &'a SastRule,
    text: &'a str,
    non_code: &'a [(usize, usize)],
    line_starts: &'a [usize],
    emitted_spans: &'a mut Vec<(usize, usize)>,
    deduplicate: bool,
    builder: &'a mut FindingBuilder<'b>,
}

fn emit_sast_finding(context: &mut SastFindingContext<'_, '_>, start: usize, end: usize) {
    if offset_in_non_code_span(context.non_code, start)
        || (context.deduplicate
            && context
                .emitted_spans
                .iter()
                .any(|(previous_start, previous_end)| {
                    *previous_start < end && start < *previous_end
                }))
    {
        return;
    }
    let line_end = context.text[start..]
        .find('\n')
        .map_or(context.text.len(), |relative| start + relative);
    let line_start = context.text[..start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    if context.text[line_start..line_end]
        .to_ascii_lowercase()
        .contains("hooray:allow-sast")
    {
        return;
    }
    if context.rule.rule == "sast.javascript.exec-dynamic"
        && (javascript_call_has_no_arguments(&context.text[end..])
            || has_single_literal_argument(&context.text[end..]))
    {
        return;
    }
    if matches!(
        context.rule.rule,
        "sast.javascript.eval-dynamic" | "sast.python.eval-dynamic" | "sast.java.runtime-exec"
    ) && has_single_literal_argument(&context.text[end..])
    {
        return;
    }
    if context.rule.rule == "sast.python.yaml-unsafe-load"
        && yaml_call_specifies_loader(&context.text[end..])
    {
        return;
    }
    let (line, column) = indexed_line_column(context.line_starts, start);
    context.builder.add(FindingSpec {
        kind: FindingKind::Sast,
        rule: context.rule.rule,
        line,
        column,
        summary: context.rule.summary,
        details: "A language-specific call expression uses a dangerous sink with dynamic or explicitly unsafe syntax.",
        severity: context.rule.severity,
        confidence: Confidence::High,
        description: "Dangerous sink invocation detected; source expression omitted.".to_owned(),
        references: &["https://owasp.org/www-project-code-review-guide/"],
        properties: BTreeMap::new(),
        redacted: true,
        remediation: context.rule.remediation,
        cwe: Some(context.rule.cwe),
    });
    if context.deduplicate {
        context.emitted_spans.push((start, end));
    }
}

static JAVASCRIPT_COMMONJS_NAMESPACE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)(?:^|[^.A-Za-z0-9_$])(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)"#,
    )
    .expect("constant CommonJS child_process namespace regex")
});

static JAVASCRIPT_ESM_NAMESPACE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+["'](?:node:)?child_process["']"#,
    )
    .expect("constant ES-module child_process namespace regex")
});

static JAVASCRIPT_COMMONJS_NAMED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)(?:^|[^.A-Za-z0-9_$])(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)"#,
    )
    .expect("constant CommonJS child_process named regex")
});

static JAVASCRIPT_ESM_NAMED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*import\s+\{([^}]*)\}\s+from\s+["'](?:node:)?child_process["']"#)
        .expect("constant ES-module child_process named regex")
});

static JAVASCRIPT_MEMBER_EXEC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)(?:^|[^.A-Za-z0-9_$])(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?P<method>execSync|exec)\s*\("#,
    )
    .expect("constant child_process member call regex")
});

static JAVASCRIPT_DIRECT_REQUIRE_EXEC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)(?:^|[^.A-Za-z0-9_$])(?P<require>require)\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*(?P<method>execSync|exec)\s*\("#,
    )
    .expect("constant direct child_process require call regex")
});

static JAVASCRIPT_NAMED_EXEC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:^|[^.A-Za-z0-9_$])(?P<callee>[A-Za-z_$][A-Za-z0-9_$]*)\s*\("#)
        .expect("constant child_process named call regex")
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JavascriptAliasKind {
    Namespace,
    Named,
}

#[derive(Debug)]
struct JavascriptAlias {
    name: String,
    start: usize,
    kind: JavascriptAliasKind,
}

#[derive(Clone, Copy, Debug)]
struct JavascriptToken<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug)]
struct JavascriptBinding {
    name_start: usize,
    kind: Option<JavascriptAliasKind>,
    assignment: bool,
}

#[derive(Debug)]
struct JavascriptScope {
    start: usize,
    end: usize,
    parent: Option<usize>,
    function: bool,
    bindings: Vec<JavascriptBinding>,
}

#[derive(Debug)]
struct JavascriptBindingModel {
    scopes: Vec<JavascriptScope>,
}

impl JavascriptBindingModel {
    fn new(text: &str, tokens: &[JavascriptToken<'_>], aliases: &[JavascriptAlias]) -> Self {
        let pairs = matching_javascript_parentheses(tokens);
        let (mut scopes, static_token_scopes, opening_scopes) =
            javascript_scopes(text.len(), tokens);
        mark_javascript_function_scopes(tokens, &pairs, &opening_scopes, &mut scopes);
        for index in 0..tokens.len() {
            let token = tokens[index];
            let scope = static_token_scopes[index];
            match token.text {
                "const" | "let" => {
                    collect_javascript_variable_bindings(tokens, index, scope, aliases, &mut scopes)
                }
                "var" => {
                    let function_scope = javascript_function_scope(&scopes, scope);
                    collect_javascript_variable_bindings(
                        tokens,
                        index,
                        function_scope,
                        aliases,
                        &mut scopes,
                    );
                }
                "function" => {
                    let mut name = index + 1;
                    if tokens.get(name).is_some_and(|token| token.text == "*") {
                        name += 1;
                    }
                    if let Some(token) = tokens.get(name)
                        && is_javascript_identifier(token.text)
                    {
                        let binding_scope = javascript_named_function_scope(
                            tokens,
                            &pairs,
                            &opening_scopes,
                            index,
                            scope,
                        )
                        .unwrap_or(scope);
                        add_javascript_binding(&mut scopes, binding_scope, token, aliases);
                    }
                }
                "class" => {
                    if let Some(token) = tokens.get(index + 1)
                        && is_javascript_identifier(token.text)
                    {
                        let binding_scope =
                            javascript_named_class_scope(tokens, &opening_scopes, index, scope)
                                .unwrap_or(scope);
                        add_javascript_binding(&mut scopes, binding_scope, token, aliases);
                    }
                }
                "import" => {
                    collect_javascript_import_bindings(tokens, index, scope, aliases, &mut scopes)
                }
                _ => {}
            }
        }
        let token_scopes = add_javascript_expression_arrow_scopes(
            text,
            tokens,
            &pairs,
            &mut scopes,
            aliases,
            &static_token_scopes,
            &opening_scopes,
        );
        for (index, token) in tokens.iter().enumerate() {
            if token.text != "{" {
                continue;
            }
            let Some(scope) = opening_scopes[index] else {
                continue;
            };
            if let Some((open, close)) = javascript_body_parameter_range(tokens, index, &pairs) {
                if javascript_body_has_parameters(tokens, open)
                    || tokens
                        .get(open.saturating_sub(1))
                        .is_some_and(|token| token.text == "catch")
                {
                    collect_javascript_parameters(
                        tokens,
                        open + 1,
                        close,
                        scope,
                        aliases,
                        &mut scopes,
                    );
                }
            } else if index > 0
                && tokens[index - 1].text == "=>"
                && let Some((start, end)) =
                    javascript_arrow_parameter_range(tokens, index - 1, &pairs)
            {
                collect_javascript_parameters(tokens, start, end, scope, aliases, &mut scopes);
            }
        }
        collect_javascript_assignments(text, tokens, &token_scopes, &mut scopes);
        let mut model = Self { scopes };
        for alias in aliases {
            let scope = javascript_scope_at(&model.scopes, alias.start);
            let valid = model.require_is_unshadowed(text, alias.start);
            if let Some(binding) = model.scopes[scope]
                .bindings
                .iter_mut()
                .find(|binding| binding.name_start == alias.start)
            {
                if !valid {
                    binding.kind = None;
                }
            } else if valid {
                model.scopes[scope].bindings.push(JavascriptBinding {
                    name_start: alias.start,
                    kind: Some(alias.kind),
                    assignment: false,
                });
            }
        }
        model
    }

    fn resolves_alias(
        &self,
        text: &str,
        name: &str,
        offset: usize,
        kind: JavascriptAliasKind,
    ) -> bool {
        let mut scope = javascript_scope_at(&self.scopes, offset);
        loop {
            let bindings = self.scopes[scope]
                .bindings
                .iter()
                .filter(|binding| {
                    text[binding.name_start..]
                        .split(|character: char| !is_javascript_identifier_character(character))
                        .next()
                        == Some(name)
                })
                .collect::<Vec<_>>();
            if let Some(binding) = bindings
                .iter()
                .filter(|binding| binding.name_start < offset)
                .max_by_key(|binding| binding.name_start)
            {
                return binding.kind == Some(kind);
            }
            if bindings.iter().any(|binding| !binding.assignment) {
                return false;
            }
            let Some(parent) = self.scopes[scope].parent else {
                return false;
            };
            scope = parent;
        }
    }

    fn require_is_unshadowed(&self, text: &str, offset: usize) -> bool {
        let mut scope = javascript_scope_at(&self.scopes, offset);
        loop {
            if self.scopes[scope].bindings.iter().any(|binding| {
                text[binding.name_start..]
                    .split(|character: char| !is_javascript_identifier_character(character))
                    .next()
                    == Some("require")
            }) {
                return false;
            }
            let Some(parent) = self.scopes[scope].parent else {
                return true;
            };
            scope = parent;
        }
    }
}

fn scan_javascript_exec_receivers(
    text: &str,
    non_code: &[(usize, usize)],
    line_starts: &[usize],
    rule: &SastRule,
    emitted_spans: &mut Vec<(usize, usize)>,
    builder: &mut FindingBuilder<'_>,
) {
    let mut aliases = Vec::new();
    let tokens = javascript_tokens(text, non_code);
    for captures in JAVASCRIPT_COMMONJS_NAMESPACE_REGEX
        .captures_iter(text)
        .chain(JAVASCRIPT_ESM_NAMESPACE_REGEX.captures_iter(text))
    {
        let Some(alias) = captures.get(1) else {
            continue;
        };
        let Some(declaration) = captures.get(0) else {
            continue;
        };
        if !offset_in_non_code_span(non_code, alias.start())
            && has_javascript_declaration_boundary(text, declaration.end())
        {
            aliases.push(JavascriptAlias {
                name: alias.as_str().to_owned(),
                start: alias.start(),
                kind: JavascriptAliasKind::Namespace,
            });
        }
    }
    for captures in JAVASCRIPT_COMMONJS_NAMED_REGEX
        .captures_iter(text)
        .chain(JAVASCRIPT_ESM_NAMED_REGEX.captures_iter(text))
    {
        let (Some(bindings), Some(declaration)) = (captures.get(1), captures.get(0)) else {
            continue;
        };
        if offset_in_non_code_span(non_code, bindings.start())
            || !has_javascript_declaration_boundary(text, declaration.end())
        {
            continue;
        }
        collect_named_child_process_aliases(bindings.as_str(), bindings.start(), &mut aliases);
    }
    let model = JavascriptBindingModel::new(text, &tokens, &aliases);
    let mut finding = SastFindingContext {
        rule,
        text,
        non_code,
        line_starts,
        emitted_spans,
        deduplicate: true,
        builder,
    };
    for captures in JAVASCRIPT_MEMBER_EXEC_REGEX.captures_iter(text) {
        let (Some(receiver), Some(method)) = (captures.name("receiver"), captures.name("method"))
        else {
            continue;
        };
        if javascript_member_access_before(&tokens, receiver.start())
            || !model.resolves_alias(
                text,
                receiver.as_str(),
                receiver.start(),
                JavascriptAliasKind::Namespace,
            )
        {
            continue;
        }
        let start = method.start();
        emit_sast_finding(
            &mut finding,
            start,
            method.end() + text[method.end()..].find('(').unwrap_or(0) + 1,
        );
    }
    for captures in JAVASCRIPT_DIRECT_REQUIRE_EXEC_REGEX.captures_iter(text) {
        let (Some(require), Some(method)) = (captures.name("require"), captures.name("method"))
        else {
            continue;
        };
        if javascript_member_access_before(&tokens, require.start())
            || !model.require_is_unshadowed(text, require.start())
        {
            continue;
        }
        let start = method.start();
        emit_sast_finding(
            &mut finding,
            start,
            method.end() + text[method.end()..].find('(').unwrap_or(0) + 1,
        );
    }
    for captures in JAVASCRIPT_NAMED_EXEC_REGEX.captures_iter(text) {
        let Some(callee) = captures.name("callee") else {
            continue;
        };
        if javascript_member_access_before(&tokens, callee.start())
            || !model.resolves_alias(
                text,
                callee.as_str(),
                callee.start(),
                JavascriptAliasKind::Named,
            )
        {
            continue;
        }
        let start = callee.start();
        emit_sast_finding(
            &mut finding,
            start,
            callee.end() + text[callee.end()..].find('(').unwrap_or(0) + 1,
        );
    }
}
fn javascript_member_access_before(tokens: &[JavascriptToken<'_>], offset: usize) -> bool {
    let previous = tokens.partition_point(|token| token.end <= offset);
    tokens
        .get(previous.saturating_sub(1))
        .is_some_and(|token| token.text == ".")
}

#[cfg(test)]
type JavascriptAssignmentCollectionResult = usize;
#[cfg(not(test))]
type JavascriptAssignmentCollectionResult = ();

fn collect_javascript_assignments(
    text: &str,
    tokens: &[JavascriptToken<'_>],
    token_scopes: &[usize],
    scopes: &mut [JavascriptScope],
) -> JavascriptAssignmentCollectionResult {
    #[cfg(test)]
    let mut ownership_lookups = 0;
    for index in 1..tokens.len() {
        if tokens[index].text != "=" || !is_javascript_identifier(tokens[index - 1].text) {
            continue;
        }
        if index >= 2 && tokens[index - 2].text == "." {
            continue;
        }
        let assignment = tokens[index - 1];
        #[cfg(test)]
        {
            ownership_lookups += 1;
        }
        let mut scope = token_scopes[index - 1];
        let assigning_function = javascript_function_scope(scopes, scope);
        loop {
            if scopes[scope]
                .bindings
                .iter()
                .any(|binding| binding.name_start == assignment.start)
            {
                break;
            }
            if scopes[scope].bindings.iter().any(|binding| {
                binding.name_start < assignment.start
                    && text[binding.name_start..]
                        .split(|character: char| !is_javascript_identifier_character(character))
                        .next()
                        == Some(assignment.text)
            }) {
                let invalidation_scope =
                    if javascript_function_scope(scopes, scope) == assigning_function {
                        scope
                    } else {
                        assigning_function
                    };
                scopes[invalidation_scope].bindings.push(JavascriptBinding {
                    name_start: assignment.start,
                    kind: None,
                    assignment: true,
                });
                break;
            }
            let Some(parent) = scopes[scope].parent else {
                break;
            };
            scope = parent;
        }
    }
    #[cfg(test)]
    {
        ownership_lookups
    }
    #[cfg(not(test))]
    {}
}

fn javascript_tokens<'a>(text: &'a str, non_code: &[(usize, usize)]) -> Vec<JavascriptToken<'a>> {
    let bytes = text.as_bytes();
    let mut tokens: Vec<JavascriptToken<'a>> = Vec::new();
    let mut index = 0;
    // `non_code` is sorted and disjoint, so one cursor avoids rescanning it
    // for every byte in the source.
    let mut non_code_index = 0;
    'tokenize: while index < bytes.len() {
        while let Some(&(start, end)) = non_code.get(non_code_index) {
            if index < start {
                let line_comment = start == index + 1
                    && bytes[index] == b'/'
                    && bytes.get(index + 1) == Some(&b'/');
                let block_comment = start == index + 1
                    && bytes[index] == b'/'
                    && bytes.get(index + 1) == Some(&b'*');
                if line_comment || block_comment {
                    index = end
                        .saturating_add(usize::from(block_comment))
                        .min(bytes.len());
                    non_code_index += 1;
                    continue 'tokenize;
                }
                break;
            }
            if index < end {
                index = end;
                non_code_index += 1;
                continue;
            }
            non_code_index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let byte = bytes[index];
        if !bytes[index].is_ascii() {
            let character = text[index..]
                .chars()
                .next()
                .expect("valid UTF-8 boundary while tokenizing JavaScript");
            index += character.len_utf8();
            continue;
        }
        if byte == b'/'
            && bytes.get(index + 1) != Some(&b'/')
            && bytes.get(index + 1) != Some(&b'*')
            && javascript_can_start_regex(tokens.last().map(|token| token.text))
            && let Some(end) = javascript_regex_literal_end(bytes, index)
        {
            tokens.push(JavascriptToken {
                text: &text[index..end],
                start: index,
                end,
            });
            index = end;
            continue;
        }
        if byte == b'_' || byte == b'$' || byte.is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len() && is_javascript_identifier_character(bytes[index] as char) {
                index += 1;
            }
            tokens.push(JavascriptToken {
                text: &text[start..index],
                start,
                end: index,
            });
        } else if byte.is_ascii_whitespace() {
            index += 1;
        } else {
            let start = index;
            index += 1;
            if (byte == b'=' && bytes.get(index) == Some(&b'>'))
                || (matches!(byte, b'&' | b'|' | b'?') && bytes.get(index) == Some(&byte))
            {
                index += 1;
            } else if byte == b'.'
                && bytes
                    .get(index..)
                    .is_some_and(|remaining| remaining.starts_with(b".."))
            {
                index += 2;
            }
            tokens.push(JavascriptToken {
                text: &text[start..index],
                start,
                end: index,
            });
        }
    }
    tokens
}
fn javascript_can_start_regex(previous: Option<&str>) -> bool {
    previous.is_none_or(|token| {
        matches!(
            token,
            "=" | "=="
                | "==="
                | "!="
                | "!=="
                | "!"
                | "&&"
                | "||"
                | "??"
                | "?"
                | ":"
                | ","
                | ";"
                | "("
                | "["
                | "{"
                | "=>"
                | "case"
                | "delete"
                | "do"
                | "else"
                | "in"
                | "instanceof"
                | "new"
                | "of"
                | "return"
                | "throw"
                | "typeof"
                | "void"
                | "await"
                | "yield"
        )
    })
}

fn javascript_regex_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let mut escaped = false;
    let mut character_class = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'\n' || byte == b'\r' {
            return None;
        } else if byte == b'[' {
            character_class = true;
        } else if byte == b']' {
            character_class = false;
        } else if byte == b'/' && !character_class {
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            {
                index += 1;
            }
            return Some(index);
        }
        index += 1;
    }
    None
}

fn javascript_scopes(
    text_length: usize,
    tokens: &[JavascriptToken<'_>],
) -> (Vec<JavascriptScope>, Vec<usize>, Vec<Option<usize>>) {
    let mut scopes = vec![JavascriptScope {
        start: 0,
        end: text_length,
        parent: None,
        function: true,
        bindings: Vec::new(),
    }];
    let mut token_scopes = vec![0; tokens.len()];
    let mut opening_scopes = vec![None; tokens.len()];
    let mut stack = vec![0];
    for (index, token) in tokens.iter().enumerate() {
        token_scopes[index] = *stack.last().expect("root JavaScript scope exists");
        if token.text == "{" {
            let scope = scopes.len();
            scopes.push(JavascriptScope {
                start: token.end,
                end: text_length,
                parent: Some(*stack.last().expect("scope stack is non-empty")),
                function: false,
                bindings: Vec::new(),
            });
            opening_scopes[index] = Some(scope);
            stack.push(scope);
        } else if token.text == "}" && stack.len() > 1 {
            let scope = stack.pop().expect("non-root scope exists");
            scopes[scope].end = token.start;
        }
    }
    (scopes, token_scopes, opening_scopes)
}

fn matching_javascript_parentheses(tokens: &[JavascriptToken<'_>]) -> Vec<Option<usize>> {
    let mut pairs = vec![None; tokens.len()];
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.text == "(" {
            stack.push(index);
        } else if token.text == ")"
            && let Some(open) = stack.pop()
        {
            pairs[index] = Some(open);
        }
    }
    pairs
}
fn mark_javascript_function_scopes(
    tokens: &[JavascriptToken<'_>],
    pairs: &[Option<usize>],
    opening_scopes: &[Option<usize>],
    scopes: &mut [JavascriptScope],
) {
    for (index, token) in tokens.iter().enumerate() {
        if token.text != "{" {
            continue;
        }
        let Some(scope) = opening_scopes[index] else {
            continue;
        };
        let is_function = tokens
            .get(index.checked_sub(1).unwrap_or_default())
            .is_some_and(|previous| previous.text == "=>")
            || javascript_body_parameter_range(tokens, index, pairs)
                .is_some_and(|(open, _)| javascript_body_has_parameters(tokens, open));
        if is_function {
            scopes[scope].function = true;
        }
    }
}

fn javascript_function_scope(scopes: &[JavascriptScope], mut scope: usize) -> usize {
    loop {
        if scopes[scope].function {
            return scope;
        }
        let Some(parent) = scopes[scope].parent else {
            return 0;
        };
        scope = parent;
    }
}

fn javascript_body_parameter_range(
    tokens: &[JavascriptToken<'_>],
    body: usize,
    pairs: &[Option<usize>],
) -> Option<(usize, usize)> {
    let previous = body.checked_sub(1)?;
    if tokens[previous].text == ")" {
        return pairs
            .get(previous)
            .copied()
            .flatten()
            .map(|open| (open, previous));
    }
    if matches!(tokens[previous].text, ":" | "<" | "&" | "|" | "," | "=") {
        return None;
    }
    let mut index = previous;
    while index > 0 {
        if tokens[index].text == ")" {
            if let Some(open) = pairs.get(index).copied().flatten()
                && tokens.get(index + 1).is_some_and(|token| token.text == ":")
            {
                return Some((open, index));
            }
            if let Some(open) = pairs.get(index).copied().flatten() {
                index = open;
            }
        }
        index = index.saturating_sub(1);
    }
    None
}

fn javascript_function_body_open(
    tokens: &[JavascriptToken<'_>],
    function: usize,
    pairs: &[Option<usize>],
) -> Option<usize> {
    let parameter_open = (function + 1..tokens.len()).find(|&index| tokens[index].text == "(")?;
    let parameter_close = (parameter_open + 1..tokens.len())
        .find(|&index| pairs.get(index).copied().flatten() == Some(parameter_open))?;
    (parameter_close + 1..tokens.len()).find(|&index| {
        tokens[index].text == "{"
            && javascript_body_parameter_range(tokens, index, pairs)
                .is_some_and(|(open, _)| open == parameter_open)
    })
}

fn javascript_is_expression(tokens: &[JavascriptToken<'_>], index: usize) -> bool {
    let mut previous = index.checked_sub(1);
    if previous.is_some_and(|index| tokens[index].text == "async") {
        previous = previous.and_then(|index| index.checked_sub(1));
    }
    previous.is_some_and(|index| {
        matches!(
            tokens[index].text,
            "=" | "(" | "[" | "," | ":" | "return" | "=>"
        )
    })
}

fn javascript_named_function_scope(
    tokens: &[JavascriptToken<'_>],
    pairs: &[Option<usize>],
    opening_scopes: &[Option<usize>],
    function: usize,
    declaration_scope: usize,
) -> Option<usize> {
    if !javascript_is_expression(tokens, function) {
        return None;
    }
    let body = javascript_function_body_open(tokens, function, pairs)?;
    opening_scopes[body].or(Some(declaration_scope))
}

fn javascript_named_class_scope(
    tokens: &[JavascriptToken<'_>],
    opening_scopes: &[Option<usize>],
    class: usize,
    declaration_scope: usize,
) -> Option<usize> {
    if !javascript_is_expression(tokens, class) {
        return None;
    }
    let body = (class + 1..tokens.len()).find(|&index| tokens[index].text == "{")?;
    opening_scopes[body].or(Some(declaration_scope))
}

fn javascript_body_has_parameters(tokens: &[JavascriptToken<'_>], open: usize) -> bool {
    let Some(previous) = open.checked_sub(1).and_then(|index| tokens.get(index)) else {
        return false;
    };
    !matches!(
        previous.text,
        "if" | "for" | "while" | "switch" | "with" | "catch"
    )
}

// Expression-bodied arrows need a temporary scope bounded by their body.
fn add_javascript_expression_arrow_scopes(
    text: &str,
    tokens: &[JavascriptToken<'_>],
    pairs: &[Option<usize>],
    scopes: &mut Vec<JavascriptScope>,
    aliases: &[JavascriptAlias],
    token_scopes: &[usize],
    opening_scopes: &[Option<usize>],
) -> Vec<usize> {
    let mut arrow_scopes = Vec::new();
    let mut active_arrows = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        active_arrows.retain(|(_, _, end)| *end > token.start);
        if token.text != "=>" || tokens.get(index + 1).is_some_and(|next| next.text == "{") {
            continue;
        }
        let parent = active_arrows
            .last()
            .map(|(scope, _, _)| *scope)
            .unwrap_or(token_scopes[index]);
        let start = token.end;
        let end = javascript_arrow_expression_end(text, tokens, index + 1);
        let scope = scopes.len();
        scopes.push(JavascriptScope {
            start,
            end,
            parent: Some(parent),
            function: true,
            bindings: Vec::new(),
        });
        if let Some((parameter_start, parameter_end)) =
            javascript_arrow_parameter_range(tokens, index, pairs)
        {
            collect_javascript_parameters(
                tokens,
                parameter_start,
                parameter_end,
                scope,
                aliases,
                scopes,
            );
        }
        arrow_scopes.push((scope, start, end));
    }

    let mut final_token_scopes = token_scopes.to_vec();
    active_arrows.clear();
    let mut next_arrow = 0;
    for (index, token) in tokens.iter().enumerate() {
        active_arrows.retain(|(_, _, end)| *end > token.start);
        while let Some((scope, start, end)) = arrow_scopes.get(next_arrow).copied() {
            if start > token.start {
                break;
            }
            next_arrow += 1;
            if end > token.start {
                active_arrows.push((scope, start, end));
            }
        }
        if token.text == "{"
            && let Some(scope) = opening_scopes[index]
            && let Some((parent, _, _)) = active_arrows.last().copied()
        {
            scopes[scope].parent = Some(parent);
        }
        if let Some((scope, _, _)) = active_arrows.last().copied() {
            let static_scope = token_scopes[index];
            if scopes[scope].start > scopes[static_scope].start {
                final_token_scopes[index] = scope;
            }
        }
    }
    final_token_scopes
}

fn javascript_arrow_expression_end(
    text: &str,
    tokens: &[JavascriptToken<'_>],
    start: usize,
) -> usize {
    let mut parentheses = 0_usize;
    let mut brackets = 0_usize;
    let mut braces = 0_usize;
    let mut previous: Option<&JavascriptToken<'_>> = None;
    for token in tokens.iter().skip(start) {
        if let Some(previous_token) = previous
            && parentheses == 0
            && brackets == 0
            && braces == 0
            && text[previous_token.end..token.start].contains('\n')
            && javascript_expression_can_end(previous_token.text)
            && !javascript_expression_continues(token.text)
        {
            return token.start;
        }
        match token.text {
            "(" => parentheses += 1,
            ")" if parentheses == 0 => return token.start,
            ")" => parentheses -= 1,
            "[" => brackets += 1,
            "]" if brackets == 0 => return token.start,
            "]" => brackets -= 1,
            "{" => braces += 1,
            "}" if braces == 0 => return token.start,
            "}" => braces -= 1,
            "," | ";" if parentheses == 0 && brackets == 0 && braces == 0 => return token.start,
            _ => {}
        }
        previous = Some(token);
    }
    text.len()
}

fn javascript_expression_can_end(token: &str) -> bool {
    is_javascript_identifier(token)
        || token
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
        || token
            .as_bytes()
            .strip_prefix(b"/")
            .is_some_and(|rest| rest.contains(&b'/'))
        || matches!(token, ")" | "]" | "}" | "'" | "\"" | "`")
}

fn javascript_expression_continues(token: &str) -> bool {
    matches!(
        token,
        "." | "?" | ":" | "(" | "[" | "+" | "-" | "*" | "/" | "%" | "&&" | "||" | "??" | "="
    )
}

fn javascript_arrow_parameter_range(
    tokens: &[JavascriptToken<'_>],
    arrow: usize,
    pairs: &[Option<usize>],
) -> Option<(usize, usize)> {
    let previous = arrow.checked_sub(1)?;
    if tokens[previous].text == ")" {
        return pairs
            .get(previous)
            .copied()
            .flatten()
            .map(|open| (open + 1, previous));
    }
    let mut candidate = previous;
    while candidate > 0 {
        if tokens[candidate].text == ")"
            && tokens
                .get(candidate + 1)
                .is_some_and(|token| token.text == ":")
            && let Some(open) = pairs.get(candidate).copied().flatten()
        {
            return Some((open + 1, candidate));
        }
        if let Some(open) = pairs.get(candidate).copied().flatten() {
            candidate = open;
        }
        candidate = candidate.saturating_sub(1);
    }
    let mut start = previous;
    while start > 0 {
        let previous_token = tokens[start - 1].text;
        if matches!(
            previous_token,
            ";" | "," | "{" | "}" | "[" | "]" | "(" | "="
        ) {
            break;
        }
        start -= 1;
    }
    if tokens.get(start).is_some_and(|token| token.text == "async") {
        start += 1;
    }
    Some((start, arrow))
}

fn javascript_parameter_binding_start(
    tokens: &[JavascriptToken<'_>],
    mut start: usize,
    end: usize,
) -> usize {
    while start < end
        && matches!(
            tokens[start].text,
            "public" | "private" | "protected" | "readonly" | "override"
        )
        && tokens
            .get(start + 1)
            .is_some_and(|token| is_javascript_identifier(token.text))
    {
        start += 1;
    }
    start
}

fn collect_javascript_parameters(
    tokens: &[JavascriptToken<'_>],
    start: usize,
    end: usize,
    scope: usize,
    aliases: &[JavascriptAlias],
    scopes: &mut [JavascriptScope],
) {
    let mut segment_start = start;
    let mut depth = 0_usize;
    for index in start..=end {
        let separator = index == end || tokens[index].text == ",";
        if separator && depth == 0 {
            let binding_start = javascript_parameter_binding_start(tokens, segment_start, index);
            collect_javascript_pattern_bindings(
                tokens,
                binding_start,
                index,
                scope,
                aliases,
                scopes,
            );
            segment_start = index + 1;
        } else if index < end && matches!(tokens[index].text, "{" | "[" | "(") {
            depth += 1;
        } else if index < end && matches!(tokens[index].text, "}" | "]" | ")") {
            depth = depth.saturating_sub(1);
        }
    }
}

fn collect_javascript_variable_bindings(
    tokens: &[JavascriptToken<'_>],
    keyword: usize,
    scope: usize,
    aliases: &[JavascriptAlias],
    scopes: &mut [JavascriptScope],
) {
    let mut index = keyword + 1;
    loop {
        let pattern_start = index;
        let mut depth = 0_usize;
        while index < tokens.len() {
            let token = tokens[index].text;
            if depth == 0 && matches!(token, "=" | "," | ";") {
                break;
            }
            if matches!(token, "{" | "[" | "(") {
                depth += 1;
            } else if matches!(token, "}" | "]" | ")") {
                depth = depth.saturating_sub(1);
            }
            index += 1;
        }
        collect_javascript_pattern_bindings(tokens, pattern_start, index, scope, aliases, scopes);
        if index >= tokens.len() || tokens[index].text == ";" {
            break;
        }
        if tokens[index].text == "=" {
            index += 1;
            depth = 0;
            while index < tokens.len() {
                let token = tokens[index].text;
                if depth == 0 && matches!(token, "," | ";") {
                    break;
                }
                if matches!(token, "{" | "[" | "(") {
                    depth += 1;
                } else if matches!(token, "}" | "]" | ")") {
                    depth = depth.saturating_sub(1);
                }
                index += 1;
            }
        }
        if index < tokens.len() && tokens[index].text == "," {
            index += 1;
            continue;
        }
        break;
    }
}

fn collect_javascript_pattern_bindings(
    tokens: &[JavascriptToken<'_>],
    start: usize,
    end: usize,
    scope: usize,
    aliases: &[JavascriptAlias],
    scopes: &mut [JavascriptScope],
) {
    if start >= end {
        return;
    }
    if tokens[start].text == "..." {
        collect_javascript_pattern_bindings(tokens, start + 1, end, scope, aliases, scopes);
        return;
    }
    if is_javascript_identifier(tokens[start].text) {
        add_javascript_binding(scopes, scope, &tokens[start], aliases);
        return;
    }
    let closing = if tokens[start].text == "{" { "}" } else { "]" };
    let mut index = start + 1;
    let mut segment_start = index;
    let mut depth = 0_usize;
    while index < end {
        let token = tokens[index].text;
        if depth == 0 && (token == "," || token == closing) {
            collect_javascript_pattern_entry(tokens, segment_start, index, scope, aliases, scopes);
            segment_start = index + 1;
        } else if matches!(token, "{" | "[" | "(") {
            depth += 1;
        } else if matches!(token, "}" | "]" | ")") {
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    if segment_start < end {
        collect_javascript_pattern_entry(tokens, segment_start, end, scope, aliases, scopes);
    }
}

fn collect_javascript_pattern_entry(
    tokens: &[JavascriptToken<'_>],
    start: usize,
    end: usize,
    scope: usize,
    aliases: &[JavascriptAlias],
    scopes: &mut [JavascriptScope],
) {
    if start >= end {
        return;
    }
    if tokens[start].text == "..." {
        collect_javascript_pattern_bindings(tokens, start + 1, end, scope, aliases, scopes);
        return;
    }
    let mut depth = 0_usize;
    for index in start..end {
        let token = tokens[index].text;
        if depth == 0 && token == ":" {
            collect_javascript_pattern_bindings(tokens, index + 1, end, scope, aliases, scopes);
            return;
        }
        if depth == 0 && token == "=" {
            add_javascript_binding(scopes, scope, &tokens[start], aliases);
            return;
        }
        if matches!(token, "{" | "[" | "(") {
            depth += 1;
        } else if matches!(token, "}" | "]" | ")") {
            depth = depth.saturating_sub(1);
        }
    }
    if is_javascript_identifier(tokens[start].text) {
        add_javascript_binding(scopes, scope, &tokens[start], aliases);
    }
}

fn collect_javascript_import_bindings(
    tokens: &[JavascriptToken<'_>],
    import: usize,
    scope: usize,
    aliases: &[JavascriptAlias],
    scopes: &mut [JavascriptScope],
) {
    let mut index = import + 1;
    while index < tokens.len() && tokens[index].text != ";" && tokens[index].text != "from" {
        if tokens[index].text == "as" {
            if let Some(local) = tokens.get(index + 1)
                && is_javascript_identifier(local.text)
            {
                add_javascript_binding(scopes, scope, local, aliases);
            }
            index += 2;
            continue;
        }
        if is_javascript_identifier(tokens[index].text)
            && !matches!(tokens[index].text, "type" | "typeof")
            && (index == import + 1 || tokens[index - 1].text == ",")
        {
            add_javascript_binding(scopes, scope, &tokens[index], aliases);
        }
        index += 1;
    }
}

fn add_javascript_binding(
    scopes: &mut [JavascriptScope],
    scope: usize,
    token: &JavascriptToken<'_>,
    aliases: &[JavascriptAlias],
) {
    let kind = aliases
        .iter()
        .find(|alias| alias.name == token.text && alias.start == token.start)
        .map(|alias| alias.kind);
    scopes[scope].bindings.push(JavascriptBinding {
        name_start: token.start,
        kind,
        assignment: false,
    });
}

fn javascript_scope_at(scopes: &[JavascriptScope], offset: usize) -> usize {
    scopes
        .iter()
        .enumerate()
        .filter(|(_, scope)| scope.start <= offset && offset < scope.end)
        .max_by_key(|(_, scope)| scope.start)
        .map(|(index, _)| index)
        .unwrap_or(0)
}

fn has_javascript_declaration_boundary(text: &str, offset: usize) -> bool {
    let bytes = text.as_bytes();
    let mut index = offset;
    loop {
        while matches!(bytes.get(index), Some(b' ' | b'\t' | b'\x0b' | b'\x0c')) {
            index += 1;
        }
        if bytes
            .get(index..)
            .is_some_and(|remaining| remaining.starts_with(b"/*"))
        {
            let Some(relative_end) = bytes[index + 2..]
                .windows(2)
                .position(|window| window == b"*/")
            else {
                return true;
            };
            index += relative_end + 4;
            continue;
        }
        if bytes
            .get(index..)
            .is_some_and(|remaining| remaining.starts_with(b"//"))
        {
            return true;
        }
        return matches!(bytes.get(index), None | Some(b';' | b',' | b'\r' | b'\n'));
    }
}

fn collect_named_child_process_aliases(
    bindings: &str,
    bindings_start: usize,
    aliases: &mut Vec<JavascriptAlias>,
) {
    let mut cursor = 0;
    for binding in bindings.split(',') {
        let binding_start = cursor;
        cursor += binding.len() + 1;
        let leading = binding.len() - binding.trim_start().len();
        let binding = binding.trim();
        let (exported, local, local_offset) = if let Some(index) = binding.find(':') {
            let local = &binding[index + 1..];
            let leading_local = local.len() - local.trim_start().len();
            let local = local.split('=').next().map(str::trim).unwrap_or(local);
            (
                binding[..index].trim(),
                local,
                binding_start + leading + index + 1 + leading_local,
            )
        } else if let Some(index) = binding.find(" as ") {
            let local = &binding[index + 4..];
            let leading_local = local.len() - local.trim_start().len();
            let local = local.split('=').next().map(str::trim).unwrap_or(local);
            (
                binding[..index].trim(),
                local,
                binding_start + leading + index + 4 + leading_local,
            )
        } else {
            let local = binding.split('=').next().map(str::trim).unwrap_or(binding);
            let local_offset = binding_start + leading + binding.find(local).unwrap_or(0);
            (binding, local, local_offset)
        };
        if matches!(exported, "exec" | "execSync") && is_javascript_identifier(local) {
            aliases.push(JavascriptAlias {
                name: local.to_owned(),
                start: bindings_start + local_offset,
                kind: JavascriptAliasKind::Named,
            });
        }
    }
}

fn is_javascript_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first == '$' || first.is_ascii_alphabetic())
        && chars.all(is_javascript_identifier_character)
}

fn is_javascript_identifier_character(value: char) -> bool {
    value == '_' || value == '$' || value.is_ascii_alphanumeric()
}
fn javascript_call_has_no_arguments(after_open_paren: &str) -> bool {
    let bytes = after_open_paren.as_bytes();
    let mut index = 0;
    loop {
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if bytes
            .get(index..)
            .is_some_and(|rest| rest.starts_with(b"/*"))
        {
            let Some(relative_end) = bytes[index + 2..]
                .windows(2)
                .position(|window| window == b"*/")
            else {
                return false;
            };
            index += relative_end + 4;
            continue;
        }
        if bytes
            .get(index..)
            .is_some_and(|rest| rest.starts_with(b"//"))
        {
            let Some((relative_end, line_terminator)) = after_open_paren[index + 2..]
                .char_indices()
                .find(|(_, character)| matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
            else {
                return false;
            };
            index += 2 + relative_end + line_terminator.len_utf8();
            continue;
        }
        return bytes.get(index) == Some(&b')');
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn javascript_arrow_fixture(count: usize) -> String {
        let mut source = String::with_capacity(count * 32);
        for index in 0..count {
            writeln!(source, "const arrow_{index} = () => value;").expect("write fixture");
        }
        source
    }

    fn assignment_ownership_lookups(source: &str) -> (usize, usize) {
        let tokens = javascript_tokens(source, &[]);
        let pairs = matching_javascript_parentheses(&tokens);
        let (mut scopes, static_token_scopes, opening_scopes) =
            javascript_scopes(source.len(), &tokens);
        mark_javascript_function_scopes(&tokens, &pairs, &opening_scopes, &mut scopes);
        let token_scopes = add_javascript_expression_arrow_scopes(
            source,
            &tokens,
            &pairs,
            &mut scopes,
            &[],
            &static_token_scopes,
            &opening_scopes,
        );
        let lookups = collect_javascript_assignments(source, &tokens, &token_scopes, &mut scopes);
        (lookups, tokens.len())
    }

    #[test]
    fn assignment_scope_ownership_is_linear() {
        let (small_lookups, small_tokens) =
            assignment_ownership_lookups(&javascript_arrow_fixture(4_000));
        let (large_lookups, large_tokens) =
            assignment_ownership_lookups(&javascript_arrow_fixture(8_000));
        assert_eq!(small_lookups, 4_000);
        assert_eq!(large_lookups, 8_000);
        assert_eq!(large_lookups, small_lookups * 2);
        assert!(large_tokens > small_tokens);
    }
}
