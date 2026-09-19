use std::collections::BTreeMap;

use crate::model::{Confidence, FindingKind, Severity};

use super::{FindingBuilder, FindingSpec};

const WEAK_TLS_PROTOCOL_TOKENS: &[&str] = &["sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"];

struct ServiceConfigRule<'a> {
    rule: &'a str,
    summary: &'a str,
    details: &'a str,
    remediation: &'a str,
    severity: Severity,
    cwe: &'a str,
    references: &'a [&'a str],
}

fn add_service_finding(
    builder: &mut FindingBuilder<'_>,
    rule: &ServiceConfigRule<'_>,
    description: String,
    line: u32,
    column: u32,
) {
    builder.add(FindingSpec {
        kind: FindingKind::Iac,
        rule: rule.rule,
        line,
        column,
        summary: rule.summary,
        details: rule.details,
        severity: rule.severity,
        confidence: Confidence::High,
        description,
        references: rule.references,
        properties: BTreeMap::new(),
        redacted: false,
        remediation: rule.remediation,
        cwe: Some(rule.cwe),
    });
}

pub(super) fn scan_service_config(path: &str, text: &str, builder: &mut FindingBuilder<'_>) {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let directory = path.rsplit('/').nth(1).unwrap_or("").to_ascii_lowercase();
    // Routing is name- and directory-aware: suffixed names (`my-nginx.conf`,
    // `postgresql.auto.conf`), drop-in directories (`sshd_config.d/`,
    // `conf.d/` under nginx), and service-named directories all select the
    // matching check table; the generic `.conf` fallback stays Apache.
    let nginx_conf = (name.contains("nginx") && name.ends_with(".conf"))
        || directory.contains("nginx")
        || (name.ends_with(".conf") && directory == "conf.d" && path.contains("nginx"));
    if nginx_conf {
        scan_directive_config(text, builder, NGINX_CHECKS);
        return;
    }
    let sshd_conf = name == "sshd_config"
        || (name.ends_with(".conf") && directory == "sshd_config.d")
        || (name.ends_with(".conf") && directory == "sshd");
    if sshd_conf {
        scan_directive_config(text, builder, SSHD_CHECKS);
        return;
    }
    if name == "pg_hba.conf" || (name.ends_with(".conf") && directory == "pg_hba.d") {
        scan_directive_config(text, builder, PG_HBA_CHECKS);
        return;
    }
    if name == "postgresql.conf"
        || name == "postgresql.auto.conf"
        || (name.ends_with(".conf") && directory == "postgresql.d")
        || (name.ends_with(".conf") && directory == "conf.d" && path.contains("postgres"))
    {
        scan_key_value_config(text, builder, POSTGRESQL_CHECKS);
        return;
    }
    if name == "redis.conf"
        || (name.ends_with(".conf") && directory == "redis.d")
        || (name.ends_with(".conf") && directory.contains("redis"))
    {
        scan_key_value_config(text, builder, REDIS_CHECKS);
        return;
    }
    if name.ends_with(".conf") {
        scan_directive_config(text, builder, APACHE_CHECKS);
    }
}

fn config_lines(text: &str) -> impl Iterator<Item = (u32, usize, &str)> {
    let mut offset = 0_usize;
    text.lines().enumerate().map(move |(index, line)| {
        let start = offset;
        offset += line.len() + 1;
        (index as u32 + 1, start, line)
    })
}

/// Strips a trailing `#` comment, but only when the `#` sits outside single
/// or double quotes — `requirepass "a#b"` keeps its full value.
fn effective_config_line(line: &str) -> &str {
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quote.is_some() => escaped = true,
            b'"' | b'\'' => {
                if quote == Some(byte) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(byte);
                }
            }
            b'#' if quote.is_none() => return line[..index].trim(),
            _ => {}
        }
    }
    line.trim()
}

fn split_config_directive(line: &str) -> Option<(&str, &str)> {
    line.split_once(char::is_whitespace)
}

fn directive_column(line: &str) -> u32 {
    u32::try_from(line.len() - line.trim_start().len())
        .unwrap_or(u32::MAX)
        .saturating_add(1)
}

fn argument_tokens(arguments: &str) -> impl Iterator<Item = &str> {
    arguments
        .split(|character: char| character.is_whitespace() || character == ',' || character == ';')
        .filter(|token| !token.is_empty())
}

fn is_weak_protocol_token(token: &str) -> bool {
    let normalized = token.trim_matches(['+', '-']);
    WEAK_TLS_PROTOCOL_TOKENS
        .iter()
        .any(|weak| normalized.eq_ignore_ascii_case(weak))
}

fn enables_weak_protocol(token: &str) -> bool {
    !token.starts_with('-') && is_weak_protocol_token(token)
}

fn config_assignment(line: &str) -> Option<(&str, &str)> {
    let content = effective_config_line(line);
    if content.is_empty() {
        return None;
    }
    let (key, value) = content
        .split_once('=')
        .or_else(|| content.split_once(char::is_whitespace))?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, unquote_config_value(value)))
}

fn unquote_config_value(value: &str) -> &str {
    let trimmed = value.trim();
    let Some(first) = trimmed.chars().next() else {
        return "";
    };
    if (first == '"' || first == '\'')
        && trimmed.len() >= 2 * first.len_utf8()
        && trimmed.ends_with(first)
    {
        return &trimmed[first.len_utf8()..trimmed.len() - first.len_utf8()];
    }
    trimmed
}

const NGINX_WEAK_TLS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.nginx.weak-tls-protocol",
    summary: "Nginx enables deprecated TLS protocols",
    details: "The ssl_protocols directive explicitly lists SSLv2, SSLv3, TLSv1, or TLSv1.1.",
    remediation: "Restrict ssl_protocols to TLSv1.2 and TLSv1.3.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols"],
};

const NGINX_SERVER_TOKENS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.nginx.server-tokens",
    summary: "Nginx broadcasts its server version",
    details: "The server_tokens directive is set to on, exposing the exact version in headers and error pages.",
    remediation: "Set server_tokens off to reduce fingerprinting.",
    severity: Severity::Low,
    cwe: "CWE-200",
    references: &["https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"],
};

const APACHE_WEAK_TLS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.apache.weak-tls-protocol",
    summary: "Apache enables deprecated SSL/TLS protocols",
    details: "The SSLProtocol directive enables SSLv2, SSLv3, TLSv1, or TLSv1.1.",
    remediation: "Enable only TLSv1.2 and TLSv1.3 in SSLProtocol.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslprotocol"],
};

const APACHE_SERVER_TOKENS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.apache.server-tokens",
    summary: "Apache discloses detailed server information",
    details: "The ServerTokens directive is Full or OS, sending product, version, and OS details in response headers.",
    remediation: "Set ServerTokens Prod to minimize version disclosure.",
    severity: Severity::Low,
    cwe: "CWE-200",
    references: &["https://httpd.apache.org/docs/current/mod/core.html#servertokens"],
};

const PG_HBA_TRUST_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.pg-hba.trust-authentication",
    summary: "PostgreSQL pg_hba entry trusts connections without authentication",
    details: "A pg_hba.conf record uses the trust auth method, granting access without any credential check.",
    remediation: "Replace trust with scram-sha-256 or certificate authentication.",
    severity: Severity::Critical,
    cwe: "CWE-306",
    references: &["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
};
const PG_HBA_IDENT_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.pg-hba.ident-authentication",
    summary: "pg_hba remote record trusts ident/peer authentication",
    details: "A non-local pg_hba record uses ident or peer, which trusts the remote host's account claims and is effectively trust-equivalent over the network.",
    remediation: "Use scram-sha-256 or another credential-based method for remote records; restrict ident/peer to local records.",
    severity: Severity::High,
    cwe: "CWE-306",
    references: &["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
};

const POSTGRES_SSL_OFF_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.postgres.ssl-disabled",
    summary: "PostgreSQL accepts unencrypted connections",
    details: "The ssl setting is off, so client traffic is not encrypted.",
    remediation: "Enable ssl and require encrypted connections for remote clients.",
    severity: Severity::High,
    cwe: "CWE-319",
    references: &["https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-SSL"],
};

const POSTGRES_WEAK_PASSWORD_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.postgres.weak-password-encryption",
    summary: "PostgreSQL stores passwords with a weak scheme",
    details: "password_encryption is md5 or plain instead of a modern password-based scheme.",
    remediation: "Set password_encryption to scram-sha-256 and re-set roles to upgrade stored verifiers.",
    severity: Severity::Medium,
    cwe: "CWE-916",
    references: &[
        "https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-PASSWORD-ENCRYPTION",
    ],
};

const REDIS_PROTECTED_MODE_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.redis.protected-mode-disabled",
    summary: "Redis protected mode disabled",
    details: "protected-mode no lets Redis serve external clients even when no authentication is configured.",
    remediation: "Keep protected-mode yes or configure ACLs and bind addresses before exposing Redis.",
    severity: Severity::High,
    cwe: "CWE-306",
    references: &["https://redis.io/docs/latest/operate/oss_and_mgmt/admin/"],
};

const REDIS_EMPTY_PASSWORD_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.redis.empty-password",
    summary: "Redis requirepass configured with an empty password",
    details: "The requirepass directive is set to an empty quoted string, disabling authentication.",
    remediation: "Configure a strong requirepass value or ACL users instead of an empty password.",
    severity: Severity::High,
    cwe: "CWE-521",
    references: &["https://redis.io/docs/latest/operate/oss_and_mgmt/admin/"],
};

const SSHD_ROOT_LOGIN_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.root-login-permitted",
    summary: "SSH permits direct root login",
    details: "PermitRootLogin yes allows logins straight into the root account.",
    remediation: "Use PermitRootLogin no (or prohibit-password) and escalate via sudo.",
    severity: Severity::High,
    cwe: "CWE-250",
    references: &["https://man.openbsd.org/sshd_config#PermitRootLogin"],
};

const SSHD_PASSWORD_AUTH_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.password-authentication",
    summary: "SSH permits password authentication",
    details: "PasswordAuthentication yes allows brute-forceable password logins.",
    remediation: "Require public key authentication.",
    severity: Severity::Medium,
    cwe: "CWE-521",
    references: &["https://man.openbsd.org/sshd_config#PasswordAuthentication"],
};

const SSHD_PROTOCOL_ONE_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.protocol-version-1",
    summary: "SSH protocol version 1 enabled",
    details: "Protocol 1 enables the deprecated SSHv1 protocol with weak integrity guarantees.",
    remediation: "Support SSH protocol version 2 only.",
    severity: Severity::High,
    cwe: "CWE-327",
    references: &["https://man.openbsd.org/sshd_config#Protocol"],
};

const SSHD_EMPTY_PASSWORDS_RULE: ServiceConfigRule<'static> = ServiceConfigRule {
    rule: "iac.sshd.empty-passwords-permitted",
    summary: "SSH permits empty passwords",
    details: "PermitEmptyPasswords yes lets accounts without passwords authenticate.",
    remediation: "Reject empty passwords with PermitEmptyPasswords no.",
    severity: Severity::High,
    cwe: "CWE-521",
    references: &["https://man.openbsd.org/sshd_config#PermitEmptyPasswords"],
};

/// One service-config check: the directive keyword (compared
/// case-insensitively; empty matches any line, used by record-style formats
/// One service-config check: the directive keyword (compared
/// case-insensitively; empty matches any line, used by record-style formats
/// like pg_hba.conf), a predicate over the directive keyword and its value,
/// and the finding metadata to emit when both match. Table order is
/// significant: the first matching check wins, mirroring the previous
/// per-format if/else chains.
struct ServiceConfigCheck {
    directive: &'static str,
    matches_value: fn(&str, &str) -> bool,
    rule: &'static ServiceConfigRule<'static>,
}

static NGINX_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "ssl_protocols",
        matches_value: |_, arguments| arguments_contain_weak_protocol(arguments),
        rule: &NGINX_WEAK_TLS_RULE,
    },
    ServiceConfigCheck {
        directive: "server_tokens",
        matches_value: |_, arguments| first_argument_is_on(arguments),
        rule: &NGINX_SERVER_TOKENS_RULE,
    },
];

static APACHE_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "SSLProtocol",
        matches_value: |_, arguments| arguments_enable_weak_protocol(arguments),
        rule: &APACHE_WEAK_TLS_RULE,
    },
    ServiceConfigCheck {
        directive: "ServerTokens",
        matches_value: |_, arguments| first_argument_is_full_or_os(arguments),
        rule: &APACHE_SERVER_TOKENS_RULE,
    },
];

static PG_HBA_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "",
        matches_value: |_, arguments| hba_tail_is_trust(arguments),
        rule: &PG_HBA_TRUST_RULE,
    },
    ServiceConfigCheck {
        directive: "",
        matches_value: hba_record_is_remote_ident,
        rule: &PG_HBA_IDENT_RULE,
    },
];

static POSTGRESQL_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "ssl",
        matches_value: |_, value| value_is_off(value),
        rule: &POSTGRES_SSL_OFF_RULE,
    },
    ServiceConfigCheck {
        directive: "password_encryption",
        matches_value: |_, value| value_is_md5_or_plain(value),
        rule: &POSTGRES_WEAK_PASSWORD_RULE,
    },
];

static REDIS_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "protected-mode",
        matches_value: |_, value| value_is_no(value),
        rule: &REDIS_PROTECTED_MODE_RULE,
    },
    ServiceConfigCheck {
        directive: "requirepass",
        matches_value: |_, value| str::is_empty(value),
        rule: &REDIS_EMPTY_PASSWORD_RULE,
    },
];

static SSHD_CHECKS: &[ServiceConfigCheck] = &[
    ServiceConfigCheck {
        directive: "PermitRootLogin",
        matches_value: |_, arguments| first_argument_is_yes(arguments),
        rule: &SSHD_ROOT_LOGIN_RULE,
    },
    ServiceConfigCheck {
        directive: "PasswordAuthentication",
        matches_value: |_, arguments| first_argument_is_yes(arguments),
        rule: &SSHD_PASSWORD_AUTH_RULE,
    },
    ServiceConfigCheck {
        directive: "Protocol",
        matches_value: |_, arguments| arguments_contain_protocol_one(arguments),
        rule: &SSHD_PROTOCOL_ONE_RULE,
    },
    ServiceConfigCheck {
        directive: "PermitEmptyPasswords",
        matches_value: |_, arguments| first_argument_is_yes(arguments),
        rule: &SSHD_EMPTY_PASSWORDS_RULE,
    },
];

fn first_argument_is(arguments: &str, expected: &str) -> bool {
    argument_tokens(arguments)
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn first_argument_is_on(arguments: &str) -> bool {
    first_argument_is(arguments, "on")
}

fn first_argument_is_full_or_os(arguments: &str) -> bool {
    first_argument_is(arguments, "full") || first_argument_is(arguments, "os")
}

fn first_argument_is_yes(arguments: &str) -> bool {
    first_argument_is(arguments, "yes")
}

/// `Protocol 2,1` still enables SSHv1, so any token equal to `1` flags.
fn arguments_contain_protocol_one(arguments: &str) -> bool {
    argument_tokens(arguments).any(|token| token == "1")
}

fn arguments_contain_weak_protocol(arguments: &str) -> bool {
    argument_tokens(arguments).any(is_weak_protocol_token)
}

/// `SSLProtocol all` enables every protocol including SSLv3 and TLSv1, so a
/// bare `all` token counts as enabling weak protocols alongside explicit
/// weak tokens that are not negated with `-`.
fn arguments_enable_weak_protocol(arguments: &str) -> bool {
    argument_tokens(arguments)
        .any(|token| enables_weak_protocol(token) || token.eq_ignore_ascii_case("all"))
}

/// PostgreSQL accepts `off`, `false`, `0`, and `no` as boolean false.
fn value_is_off(value: &str) -> bool {
    ["off", "false", "0", "no"]
        .iter()
        .any(|off| value.eq_ignore_ascii_case(off))
}

fn value_is_md5_or_plain(value: &str) -> bool {
    value.eq_ignore_ascii_case("md5") || value.eq_ignore_ascii_case("plain")
}

fn value_is_no(value: &str) -> bool {
    value.eq_ignore_ascii_case("no")
}

/// pg_hba.conf records carry no directive keyword: the driver hands this
/// predicate everything after the first whitespace-separated field, so a
/// trust record (connection type, database, user, method) has at least
/// three remaining fields and ends with the trust method.
fn hba_tail_is_trust(arguments: &str) -> bool {
    arguments.split_whitespace().count() >= 3
        && arguments
            .split_whitespace()
            .next_back()
            .is_some_and(|method| method.eq_ignore_ascii_case("trust"))
}

/// Remote (`host`/`hostssl`/`hostnossl`/`hostgssenc`/`hostnogssenc`)
/// pg_hba records whose auth method is `ident` or `peer` trust the remote
/// host's account claims — effectively trust-equivalent over the network.
/// `local` records legitimately use peer auth and are not flagged.
fn hba_record_is_remote_ident(directive: &str, arguments: &str) -> bool {
    directive.starts_with("host")
        && arguments.split_whitespace().count() >= 3
        && arguments
            .split_whitespace()
            .next_back()
            .is_some_and(|method| {
                method.eq_ignore_ascii_case("ident") || method.eq_ignore_ascii_case("peer")
            })
}

/// Shared directive-style driver (nginx, Apache, sshd, pg_hba): at most one
/// finding per line, first matching table entry wins.
fn scan_directive_config(
    text: &str,
    builder: &mut FindingBuilder<'_>,
    checks: &[ServiceConfigCheck],
) {
    for (number, _, line) in config_lines(text) {
        let content = effective_config_line(line);
        let Some((directive, arguments)) = split_config_directive(content) else {
            continue;
        };
        let Some(check) = checks.iter().find(|check| {
            (check.directive.is_empty() || directive.eq_ignore_ascii_case(check.directive))
                && (check.matches_value)(directive, arguments)
        }) else {
            continue;
        };
        add_service_finding(
            builder,
            check.rule,
            content.to_owned(),
            number,
            directive_column(line),
        );
    }
}

/// Shared key=value driver (postgresql.conf, redis.conf).
fn scan_key_value_config(
    text: &str,
    builder: &mut FindingBuilder<'_>,
    checks: &[ServiceConfigCheck],
) {
    for (number, _, line) in config_lines(text) {
        let Some((key, value)) = config_assignment(line) else {
            continue;
        };
        let Some(check) = checks.iter().find(|check| {
            key.eq_ignore_ascii_case(check.directive) && (check.matches_value)(key, value)
        }) else {
            continue;
        };
        add_service_finding(
            builder,
            check.rule,
            effective_config_line(line).to_owned(),
            number,
            directive_column(line),
        );
    }
}
