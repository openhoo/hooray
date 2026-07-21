use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A package component extracted from an SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub purl: String,
}

/// A vulnerability associated with an SBOM component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub package_name: String,
    pub package_version: String,
    pub purl: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Severity,
    pub modified: Option<String>,
}

/// Normalized vulnerability severity, ordered from least to most severe.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("unknown") {
            Ok(Self::Unknown)
        } else if value.eq_ignore_ascii_case("low") {
            Ok(Self::Low)
        } else if value.eq_ignore_ascii_case("medium") {
            Ok(Self::Medium)
        } else if value.eq_ignore_ascii_case("high") {
            Ok(Self::High)
        } else if value.eq_ignore_ascii_case("critical") {
            Ok(Self::Critical)
        } else {
            Err(ParseSeverityError(value.to_owned()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid severity '{0}'; expected unknown, low, medium, high, or critical")]
pub struct ParseSeverityError(String);

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn severity_is_ordered_from_unknown_to_critical() {
        assert!(Severity::Unknown < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_parsing_is_case_insensitive_and_display_is_canonical() {
        let severity = "CrItIcAl".parse::<Severity>().unwrap();

        assert_eq!(severity, Severity::Critical);
        assert_eq!(severity.to_string(), "critical");
    }

    #[test]
    fn invalid_severity_has_a_clear_error() {
        let error = "urgent".parse::<Severity>().unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid severity 'urgent'; expected unknown, low, medium, high, or critical"
        );
    }
}
