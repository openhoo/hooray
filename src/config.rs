use std::{
    env,
    ffi::{OsStr, OsString},
    fmt, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DEFAULT_OSV_URL: &str = "https://api.osv.dev";
const MAX_CONCURRENCY: usize = 256;
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 1_000_000;
const MAX_TIMEOUT_SECS: u64 = 300;
const MAX_MONITOR_INTERVAL_SECS: u64 = 86_400;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct BearerTokenHash(String);

impl BearerTokenHash {
    pub fn matches_token(&self, token: &str) -> bool {
        let actual = Sha256::digest(token.as_bytes());
        let Some(expected) = decode_sha256_hex(&self.0) else {
            return false;
        };

        actual
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (actual, expected)| {
                difference | (*actual ^ expected)
            })
            == 0
    }
}

impl fmt::Debug for BearerTokenHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerTokenHash([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub max_concurrency: usize,
    pub max_request_bytes: u64,
    pub max_input_bytes: u64,
    pub max_archive_bytes: u64,
    pub max_archive_entries: usize,
    pub database_path: PathBuf,
    pub osv_url: String,
    pub osv_connect_timeout_secs: u64,
    pub osv_request_timeout_secs: u64,
    pub policy_path: PathBuf,
    pub monitor_interval_secs: u64,
    pub api_bind: SocketAddr,
    pub auth_bearer_sha256: Option<BearerTokenHash>,
    pub offline: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_concurrency: 32,
            max_request_bytes: 1024 * 1024,
            max_input_bytes: 100 * 1024 * 1024,
            max_archive_bytes: 512 * 1024 * 1024,
            max_archive_entries: 100_000,
            database_path: PathBuf::from("hooray.db"),
            osv_url: DEFAULT_OSV_URL.to_owned(),
            osv_connect_timeout_secs: 10,
            osv_request_timeout_secs: 30,
            policy_path: PathBuf::from("hooray-policy.yaml"),
            monitor_interval_secs: 300,
            api_bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            auth_bearer_sha256: None,
            offline: false,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let config = match path {
            Some(path) => Self::from_file(path)?,
            None => Self::default(),
        };
        config.with_env(env::vars_os())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_bound(
            "max_concurrency",
            self.max_concurrency as u64,
            MAX_CONCURRENCY as u64,
        )?;
        validate_bound(
            "max_request_bytes",
            self.max_request_bytes,
            MAX_REQUEST_BYTES,
        )?;
        validate_bound("max_input_bytes", self.max_input_bytes, MAX_INPUT_BYTES)?;
        validate_bound(
            "max_archive_bytes",
            self.max_archive_bytes,
            MAX_ARCHIVE_BYTES,
        )?;
        validate_bound(
            "max_archive_entries",
            self.max_archive_entries as u64,
            MAX_ARCHIVE_ENTRIES as u64,
        )?;
        validate_bound(
            "osv_connect_timeout_secs",
            self.osv_connect_timeout_secs,
            MAX_TIMEOUT_SECS,
        )?;
        validate_bound(
            "osv_request_timeout_secs",
            self.osv_request_timeout_secs,
            MAX_TIMEOUT_SECS,
        )?;
        validate_bound(
            "monitor_interval_secs",
            self.monitor_interval_secs,
            MAX_MONITOR_INTERVAL_SECS,
        )?;
        validate_path("database_path", &self.database_path)?;
        validate_path("policy_path", &self.policy_path)?;

        validate_osv_url(&self.osv_url)?;

        if !self.api_bind.ip().is_loopback() && self.auth_bearer_sha256.is_none() {
            return Err(ConfigError::UnauthenticatedPublicBind(self.api_bind));
        }
        if let Some(hash) = &self.auth_bearer_sha256 {
            validate_bearer_hash(&hash.0)?;
        }

        Ok(())
    }

    fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let extension = path
            .extension()
            .and_then(OsStr::to_str)
            .map(str::to_ascii_lowercase);
        let config: Self = match extension.as_deref() {
            Some("yaml" | "yml") => {
                serde_yaml::from_str(&contents).map_err(|source| ConfigError::Yaml {
                    path: path.to_owned(),
                    source,
                })?
            }
            Some("toml") => toml::from_str(&contents).map_err(|source| ConfigError::Toml {
                path: path.to_owned(),
                source,
            })?,
            _ => return Err(ConfigError::UnsupportedFormat(path.to_owned())),
        };
        config.validate()?;
        Ok(config)
    }

    fn with_env<I, K, V>(mut self, variables: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (key, value) in variables {
            let key = key.into();
            let Some(key) = key.to_str() else {
                continue;
            };
            let Some(field) = key.strip_prefix("HOORAY_") else {
                continue;
            };
            let value = value.into();
            let value = value
                .to_str()
                .ok_or_else(|| ConfigError::InvalidEnvironment(key.to_owned()))?;
            match field {
                "MAX_CONCURRENCY" => self.max_concurrency = parse_env(key, value)?,
                "MAX_REQUEST_BYTES" => self.max_request_bytes = parse_env(key, value)?,
                "MAX_INPUT_BYTES" => self.max_input_bytes = parse_env(key, value)?,
                "MAX_ARCHIVE_BYTES" => self.max_archive_bytes = parse_env(key, value)?,
                "MAX_ARCHIVE_ENTRIES" => self.max_archive_entries = parse_env(key, value)?,
                "DATABASE_PATH" => self.database_path = PathBuf::from(value),
                "OSV_URL" => self.osv_url = value.to_owned(),
                "OSV_CONNECT_TIMEOUT_SECS" => {
                    self.osv_connect_timeout_secs = parse_env(key, value)?
                }
                "OSV_REQUEST_TIMEOUT_SECS" => {
                    self.osv_request_timeout_secs = parse_env(key, value)?
                }
                "POLICY_PATH" => self.policy_path = PathBuf::from(value),
                "MONITOR_INTERVAL_SECS" => self.monitor_interval_secs = parse_env(key, value)?,
                "API_BIND" => self.api_bind = parse_env(key, value)?,
                "AUTH_BEARER_SHA256" => {
                    self.auth_bearer_sha256 = if value.is_empty() {
                        None
                    } else {
                        Some(BearerTokenHash(value.to_owned()))
                    }
                }
                "OFFLINE" => self.offline = parse_bool_env(key, value)?,
                _ => return Err(ConfigError::UnknownEnvironment(key.to_owned())),
            }
        }
        self.validate()?;
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse YAML configuration file {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse TOML configuration file {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("configuration file must have a .yaml, .yml, or .toml extension: {0}")]
    UnsupportedFormat(PathBuf),
    #[error("unknown configuration environment variable: {0}")]
    UnknownEnvironment(String),
    #[error("invalid value for configuration environment variable: {0}")]
    InvalidEnvironment(String),
    #[error("{field} must be between 1 and {maximum}, inclusive")]
    OutOfRange { field: &'static str, maximum: u64 },
    #[error("{field} must be non-empty and at most {maximum} bytes")]
    InvalidPath { field: &'static str, maximum: usize },
    #[error("invalid OSV URL: {0}")]
    InvalidOsvUrl(&'static str),
    #[error("API bind {0} is not loopback and requires auth_bearer_sha256")]
    UnauthenticatedPublicBind(SocketAddr),
    #[error("auth_bearer_sha256 must be a lowercase 64-character SHA-256 digest")]
    InvalidBearerHash,
}

fn parse_env<T: FromStr>(key: &str, value: &str) -> Result<T, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::InvalidEnvironment(key.to_owned()))
}

fn parse_bool_env(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidEnvironment(key.to_owned())),
    }
}

fn validate_bound(field: &'static str, value: u64, maximum: u64) -> Result<(), ConfigError> {
    if value == 0 || value > maximum {
        return Err(ConfigError::OutOfRange { field, maximum });
    }
    Ok(())
}

fn validate_path(field: &'static str, value: &Path) -> Result<(), ConfigError> {
    let length = value.as_os_str().as_encoded_bytes().len();
    if length == 0 || length > MAX_PATH_BYTES {
        return Err(ConfigError::InvalidPath {
            field,
            maximum: MAX_PATH_BYTES,
        });
    }
    Ok(())
}

fn validate_osv_url(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidOsvUrl("malformed URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::InvalidOsvUrl("credentials are forbidden"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::InvalidOsvUrl(
            "query strings and fragments are forbidden",
        ));
    }
    let host = url
        .host_str()
        .ok_or(ConfigError::InvalidOsvUrl("host is required"))?;
    // `Url::host_str` retains brackets around IPv6 literals, so normalize only
    // that syntactic wrapper before parsing the already-validated URL host.
    let ip_host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || ip_host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ConfigError::InvalidOsvUrl(
            "HTTPS is required except for loopback test servers",
        ));
    }
    Ok(())
}

fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }

    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        *target = (high << 4) | low;
    }
    Some(decoded)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_bearer_hash(value: &str) -> Result<(), ConfigError> {
    if decode_sha256_hex(value).is_none() {
        return Err(ConfigError::InvalidBearerHash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hash() -> BearerTokenHash {
        BearerTokenHash("a".repeat(64))
    }

    fn assert_out_of_range(config: &Config, expected_field: &'static str, maximum: u64) {
        assert!(
            matches!(config.validate(), Err(ConfigError::OutOfRange { field, maximum: actual }) if field == expected_field && actual == maximum)
        );
    }

    #[test]
    fn defaults_are_valid_and_loopback_only() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert!(config.api_bind.ip().is_loopback());
        assert!(config.auth_bearer_sha256.is_none());
    }

    #[test]
    fn rejects_unknown_file_fields() {
        assert!(
            serde_yaml::from_str::<Config>("unexpected: true")
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }

    #[test]
    fn loads_and_validates_yaml_and_toml_case_insensitively() {
        let directory = tempfile::tempdir().unwrap();
        let yaml_path = directory.path().join("config.YAML");
        let toml_path = directory.path().join("config.ToMl");
        fs::write(&yaml_path, "max_concurrency: 12\noffline: true\n").unwrap();
        fs::write(&toml_path, "max_concurrency = 13\noffline = true\n").unwrap();
        let yaml = Config::from_file(&yaml_path).unwrap();
        let toml = Config::from_file(&toml_path).unwrap();
        assert_eq!(yaml.max_concurrency, 12);
        assert_eq!(toml.max_concurrency, 13);
        assert!(yaml.offline && toml.offline);
    }

    #[test]
    fn reports_file_read_and_parse_failures() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.yaml");
        assert!(
            matches!(Config::from_file(&missing), Err(ConfigError::Read { path, .. }) if path == missing)
        );
        let yaml_path = directory.path().join("broken.yaml");
        fs::write(&yaml_path, "max_concurrency: [").unwrap();
        assert!(
            matches!(Config::from_file(&yaml_path), Err(ConfigError::Yaml { path, .. }) if path == yaml_path)
        );
        let toml_path = directory.path().join("broken.toml");
        fs::write(&toml_path, "max_concurrency = [").unwrap();
        assert!(
            matches!(Config::from_file(&toml_path), Err(ConfigError::Toml { path, .. }) if path == toml_path)
        );
    }

    #[test]
    fn file_configuration_is_validated_before_use() {
        let directory = tempfile::tempdir().unwrap();
        let invalid_bound = directory.path().join("bound.yaml");
        fs::write(&invalid_bound, "max_concurrency: 0\n").unwrap();
        assert!(matches!(
            Config::from_file(&invalid_bound),
            Err(ConfigError::OutOfRange {
                field: "max_concurrency",
                ..
            })
        ));
        let public_without_auth = directory.path().join("public.yaml");
        fs::write(&public_without_auth, "api_bind: 0.0.0.0:8080\n").unwrap();
        assert!(matches!(
            Config::from_file(&public_without_auth),
            Err(ConfigError::UnauthenticatedPublicBind(_))
        ));
        let public_with_auth = directory.path().join("authenticated.toml");
        fs::write(
            &public_with_auth,
            format!(
                "api_bind = \"0.0.0.0:8080\"\nauth_bearer_sha256 = \"{}\"\n",
                "b".repeat(64)
            ),
        )
        .unwrap();
        assert!(Config::from_file(&public_with_auth).is_ok());
    }

    #[test]
    fn rejects_unsupported_file_extension() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, "{}").unwrap();
        assert!(matches!(
            Config::from_file(&path),
            Err(ConfigError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn applies_every_environment_override_individually() {
        let cases = [
            ("HOORAY_MAX_CONCURRENCY", "64"),
            ("HOORAY_MAX_REQUEST_BYTES", "2048"),
            ("HOORAY_MAX_INPUT_BYTES", "4096"),
            ("HOORAY_MAX_ARCHIVE_BYTES", "8192"),
            ("HOORAY_MAX_ARCHIVE_ENTRIES", "123"),
            ("HOORAY_DATABASE_PATH", "state/custom.db"),
            ("HOORAY_OSV_URL", "http://127.0.0.1:8081"),
            ("HOORAY_OSV_CONNECT_TIMEOUT_SECS", "11"),
            ("HOORAY_OSV_REQUEST_TIMEOUT_SECS", "31"),
            ("HOORAY_POLICY_PATH", "policy/custom.yaml"),
            ("HOORAY_MONITOR_INTERVAL_SECS", "301"),
            ("HOORAY_API_BIND", "127.0.0.1:9000"),
            (
                "HOORAY_AUTH_BEARER_SHA256",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            ("HOORAY_OFFLINE", "true"),
        ];
        for (key, value) in cases {
            let config = Config::default().with_env([(key, value)]).unwrap();
            match key {
                "HOORAY_MAX_CONCURRENCY" => assert_eq!(config.max_concurrency, 64),
                "HOORAY_MAX_REQUEST_BYTES" => assert_eq!(config.max_request_bytes, 2048),
                "HOORAY_MAX_INPUT_BYTES" => assert_eq!(config.max_input_bytes, 4096),
                "HOORAY_MAX_ARCHIVE_BYTES" => assert_eq!(config.max_archive_bytes, 8192),
                "HOORAY_MAX_ARCHIVE_ENTRIES" => assert_eq!(config.max_archive_entries, 123),
                "HOORAY_DATABASE_PATH" => assert_eq!(config.database_path, PathBuf::from(value)),
                "HOORAY_OSV_URL" => assert_eq!(config.osv_url, value),
                "HOORAY_OSV_CONNECT_TIMEOUT_SECS" => {
                    assert_eq!(config.osv_connect_timeout_secs, 11)
                }
                "HOORAY_OSV_REQUEST_TIMEOUT_SECS" => {
                    assert_eq!(config.osv_request_timeout_secs, 31)
                }
                "HOORAY_POLICY_PATH" => assert_eq!(config.policy_path, PathBuf::from(value)),
                "HOORAY_MONITOR_INTERVAL_SECS" => assert_eq!(config.monitor_interval_secs, 301),
                "HOORAY_API_BIND" => assert_eq!(config.api_bind, value.parse().unwrap()),
                "HOORAY_AUTH_BEARER_SHA256" => assert_eq!(
                    config.auth_bearer_sha256,
                    Some(BearerTokenHash(value.to_owned()))
                ),
                "HOORAY_OFFLINE" => assert!(config.offline),
                _ => unreachable!(),
            }
        }
        let cleared = Config {
            auth_bearer_sha256: Some(valid_hash()),
            ..Config::default()
        }
        .with_env([("HOORAY_AUTH_BEARER_SHA256", "")])
        .unwrap();
        assert!(cleared.auth_bearer_sha256.is_none());
        assert_eq!(
            Config::default()
                .with_env([("PATH", "ignored"), ("OTHER_MAX_CONCURRENCY", "0")])
                .unwrap(),
            Config::default()
        );
    }

    #[test]
    fn accepts_only_documented_boolean_environment_spellings() {
        for value in ["true", "1"] {
            assert!(
                Config::default()
                    .with_env([("HOORAY_OFFLINE", value)])
                    .unwrap()
                    .offline
            );
        }
        for value in ["false", "0"] {
            assert!(
                !Config {
                    offline: true,
                    ..Config::default()
                }
                .with_env([("HOORAY_OFFLINE", value)])
                .unwrap()
                .offline
            );
        }
        for value in ["TRUE", "False", "yes", "", "2"] {
            assert!(
                matches!(Config::default().with_env([("HOORAY_OFFLINE", value)]), Err(ConfigError::InvalidEnvironment(key)) if key == "HOORAY_OFFLINE")
            );
        }
    }

    #[test]
    fn rejects_unknown_and_malformed_environment_overrides() {
        assert!(
            matches!(Config::default().with_env([("HOORAY_REMOVED_SETTING", "true")]), Err(ConfigError::UnknownEnvironment(key)) if key == "HOORAY_REMOVED_SETTING")
        );
        for key in [
            "HOORAY_MAX_CONCURRENCY",
            "HOORAY_MAX_REQUEST_BYTES",
            "HOORAY_MAX_INPUT_BYTES",
            "HOORAY_MAX_ARCHIVE_BYTES",
            "HOORAY_MAX_ARCHIVE_ENTRIES",
            "HOORAY_OSV_CONNECT_TIMEOUT_SECS",
            "HOORAY_OSV_REQUEST_TIMEOUT_SECS",
            "HOORAY_MONITOR_INTERVAL_SECS",
            "HOORAY_API_BIND",
        ] {
            assert!(
                matches!(Config::default().with_env([(key, "not-a-value")]), Err(ConfigError::InvalidEnvironment(actual)) if actual == key)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn handles_non_unicode_environment_without_global_mutation() {
        use std::os::unix::ffi::OsStringExt;
        let invalid_key = OsString::from_vec(vec![b'H', b'O', b'O', b'R', b'A', b'Y', b'_', 0xff]);
        assert_eq!(
            Config::default()
                .with_env([(invalid_key, OsString::from("ignored"))])
                .unwrap(),
            Config::default()
        );
        let invalid_value = OsString::from_vec(vec![0xff]);
        assert!(
            matches!(Config::default().with_env([(OsString::from("HOORAY_DATABASE_PATH"), invalid_value)]), Err(ConfigError::InvalidEnvironment(key)) if key == "HOORAY_DATABASE_PATH")
        );
    }

    #[test]
    fn validates_every_numeric_bound_at_zero_maximum_and_overflow() {
        macro_rules! check_bound {
            ($field:ident, $maximum:expr) => {{
                let mut config = Config::default();
                config.$field = 0;
                assert_out_of_range(&config, stringify!($field), $maximum as u64);
                config.$field = $maximum;
                assert!(
                    config.validate().is_ok(),
                    "{} rejected maximum",
                    stringify!($field)
                );
                config.$field = $maximum + 1;
                assert_out_of_range(&config, stringify!($field), $maximum as u64);
            }};
        }
        check_bound!(max_concurrency, MAX_CONCURRENCY);
        check_bound!(max_request_bytes, MAX_REQUEST_BYTES);
        check_bound!(max_input_bytes, MAX_INPUT_BYTES);
        check_bound!(max_archive_bytes, MAX_ARCHIVE_BYTES);
        check_bound!(max_archive_entries, MAX_ARCHIVE_ENTRIES);
        check_bound!(osv_connect_timeout_secs, MAX_TIMEOUT_SECS);
        check_bound!(osv_request_timeout_secs, MAX_TIMEOUT_SECS);
        check_bound!(monitor_interval_secs, MAX_MONITOR_INTERVAL_SECS);
    }

    #[test]
    fn enforces_osv_url_security_contract() {
        for url in [
            "https://api.osv.dev",
            "https://example.com/path",
            "http://localhost:8080",
            "http://LOCALHOST:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://[0:0:0:0:0:0:0:1]:8080",
        ] {
            assert!(
                Config {
                    osv_url: url.to_owned(),
                    ..Config::default()
                }
                .validate()
                .is_ok(),
                "rejected {url}"
            );
        }
        for (url, reason) in [
            ("not a URL", "malformed URL"),
            ("https://user@example.com", "credentials are forbidden"),
            (
                "https://user:password@example.com",
                "credentials are forbidden",
            ),
            (
                "https://example.com?q=1",
                "query strings and fragments are forbidden",
            ),
            (
                "https://example.com/#section",
                "query strings and fragments are forbidden",
            ),
            ("file:///tmp/osv", "host is required"),
            (
                "ftp://example.com",
                "HTTPS is required except for loopback test servers",
            ),
            (
                "http://example.com",
                "HTTPS is required except for loopback test servers",
            ),
            (
                "http://localhost.example:8080",
                "HTTPS is required except for loopback test servers",
            ),
            (
                "http://[::]:8080",
                "HTTPS is required except for loopback test servers",
            ),
            (
                "http://[2001:db8::1]:8080",
                "HTTPS is required except for loopback test servers",
            ),
            (
                "http://[::ffff:127.0.0.1]:8080",
                "HTTPS is required except for loopback test servers",
            ),
        ] {
            assert!(
                matches!(Config { osv_url: url.to_owned(), ..Config::default() }.validate(), Err(ConfigError::InvalidOsvUrl(actual)) if actual == reason),
                "accepted {url}"
            );
        }
    }

    #[test]
    fn public_api_requires_valid_authentication() {
        let mut config = Config {
            api_bind: "0.0.0.0:8080".parse().unwrap(),
            ..Config::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnauthenticatedPublicBind(_))
        ));
        config.auth_bearer_sha256 = Some(valid_hash());
        assert!(config.validate().is_ok());
        config.auth_bearer_sha256 = Some(BearerTokenHash("A".repeat(64)));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidBearerHash)
        ));
    }

    #[test]
    fn validates_path_byte_boundaries_for_both_paths() {
        for (field, database) in [("database_path", true), ("policy_path", false)] {
            for (length, valid) in [
                (0, false),
                (MAX_PATH_BYTES, true),
                (MAX_PATH_BYTES + 1, false),
            ] {
                let mut config = Config::default();
                let path = PathBuf::from("p".repeat(length));
                if database {
                    config.database_path = path;
                } else {
                    config.policy_path = path;
                }
                if valid {
                    assert!(config.validate().is_ok());
                } else {
                    assert!(
                        matches!(config.validate(), Err(ConfigError::InvalidPath { field: actual, maximum: MAX_PATH_BYTES }) if actual == field)
                    );
                }
            }
        }
    }

    #[test]
    fn bearer_digest_requires_exact_lowercase_sha256_hex() {
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            format!("{}g", "a".repeat(63)),
        ] {
            assert!(matches!(
                Config {
                    auth_bearer_sha256: Some(BearerTokenHash(invalid)),
                    ..Config::default()
                }
                .validate(),
                Err(ConfigError::InvalidBearerHash)
            ));
        }
        for valid in ["0".repeat(64), "f".repeat(64), "0123456789abcdef".repeat(4)] {
            assert!(
                Config {
                    auth_bearer_sha256: Some(BearerTokenHash(valid)),
                    ..Config::default()
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn bearer_hash_matches_tokens_without_exposing_secrets() {
        let token = "correct horse battery staple";
        let hash = BearerTokenHash(format!("{:x}", Sha256::digest(token.as_bytes())));
        assert!(hash.matches_token(token));
        assert!(!hash.matches_token("incorrect"));
        assert!(!BearerTokenHash("invalid".to_owned()).matches_token(token));
        assert!(!format!("{hash:?}").contains(token));
        assert!(!format!("{hash:?}").contains(&hash.0));
    }

    #[test]
    fn debug_output_redacts_bearer_hash() {
        let config = Config {
            auth_bearer_sha256: Some(valid_hash()),
            ..Config::default()
        };
        let output = format!("{config:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(&"a".repeat(64)));
    }
}
