//! Recording files: the persisted record–replay unit of the parity harness.
//!
//! A recording bundles the hooray and Xray canonical reports for one corpus
//! case together with provenance metadata and optional operator-chosen
//! enforcement thresholds. Loading validates the schema version and that all
//! case identifiers agree.

use serde::{Deserialize, Serialize};

use crate::parity::model::{CANONICAL_SCHEMA_VERSION, CanonicalReport, ParityError};

/// Schema version of the recording envelope itself.
///
/// Deliberately an independent literal rather than an alias of
/// [`CANONICAL_SCHEMA_VERSION`]: the recording envelope (provenance,
/// enforcement gates, side layout) evolves separately from the canonical
/// report model embedded inside it, so either may advance without forcing
/// a meaningless bump of the other. The nested hooray/xray canonical
/// reports are validated against [`CANONICAL_SCHEMA_VERSION`] on their own
/// by `Recording::validate`.
pub const RECORDING_SCHEMA_VERSION: u8 = 1;

/// Optional CI gates an operator pins onto a recording.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Enforcement {
    /// Minimum acceptable purl recall (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_purl_recall: Option<f64>,
    /// Minimum acceptable purl precision (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_purl_precision: Option<f64>,
    /// Minimum acceptable CVE Jaccard similarity (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cve_jaccard: Option<f64>,
}

/// Provenance captured at recording time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// Hooray version that produced [`Recording::hooray`].
    pub hooray_version: String,
    /// Xray CLI version reported by `jf --version`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_cli_version: Option<String>,
    /// Xray server version, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_version: Option<String>,
    /// Vulnerability database snapshot date (`YYYY-MM-DD`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_db_date: Option<String>,
    /// Exact `jf audit` invocations used to capture the Xray artifacts.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Free-text environment description, e.g. `"operator workstation"`.
    #[serde(default)]
    pub environment: String,
}

/// One persisted record–replay case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    /// Always [`RECORDING_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Corpus case identifier; must match both embedded canonical reports.
    pub case_id: String,
    /// RFC 3339 timestamp of when the recording was captured.
    pub recorded_at: String,
    /// Capture provenance.
    pub provenance: Provenance,
    /// Hooray side of the comparison.
    pub hooray: CanonicalReport,
    /// Xray side of the comparison.
    pub xray: CanonicalReport,
    /// Optional enforcement thresholds enforced by `hooray-parity check`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<Enforcement>,
}

impl Recording {
    fn validate(&self) -> Result<(), ParityError> {
        if self.schema_version != RECORDING_SCHEMA_VERSION {
            return Err(ParityError::UnsupportedSchemaVersion {
                context: "recording",
                found: self.schema_version,
                expected: RECORDING_SCHEMA_VERSION,
            });
        }
        // The embedded canonical reports carry their own schema version;
        // validate both against the canonical model constant instead of
        // trusting the outer envelope check above.
        if self.hooray.schema_version != CANONICAL_SCHEMA_VERSION {
            return Err(ParityError::UnsupportedSchemaVersion {
                context: "canonical hooray",
                found: self.hooray.schema_version,
                expected: CANONICAL_SCHEMA_VERSION,
            });
        }
        if self.xray.schema_version != CANONICAL_SCHEMA_VERSION {
            return Err(ParityError::UnsupportedSchemaVersion {
                context: "canonical xray",
                found: self.xray.schema_version,
                expected: CANONICAL_SCHEMA_VERSION,
            });
        }
        if self.hooray.case_id != self.case_id {
            return Err(ParityError::CaseMismatch {
                expected: self.case_id.clone(),
                found: self.hooray.case_id.clone(),
            });
        }
        if self.xray.case_id != self.case_id {
            return Err(ParityError::CaseMismatch {
                expected: self.case_id.clone(),
                found: self.xray.case_id.clone(),
            });
        }
        Ok(())
    }

    /// Loads and validates a recording from disk.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ParityError> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let recording: Recording = serde_json::from_str(&text)?;
        recording.validate()?;
        Ok(recording)
    }

    /// Saves the recording as pretty JSON (trailing newline), creating parent
    /// directories when needed.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), ParityError> {
        let path = path.as_ref();
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parity::model::{CanonicalComponent, Generator};

    fn fixture() -> Recording {
        let hooray = CanonicalReport::new(
            "npm-package-lock-basic",
            Generator {
                name: "hooray".into(),
                version: "0.5.1".into(),
            },
            "offline",
        );
        let mut xray = CanonicalReport::new(
            "npm-package-lock-basic",
            Generator {
                name: "xray".into(),
                version: "3.8.2".into(),
            },
            "provider-replay",
        );
        xray.components.push(CanonicalComponent {
            purl: "pkg:npm/lodash@4.17.15".into(),
            name: "lodash".into(),
            version: "4.17.15".into(),
            ecosystem: "npm".into(),
            licenses: vec!["MIT".into()],
            scope: "runtime".into(),
            directness: "disconnected".into(),
        });
        Recording {
            schema_version: RECORDING_SCHEMA_VERSION,
            case_id: "npm-package-lock-basic".into(),
            recorded_at: "2026-08-25T00:00:00Z".into(),
            provenance: Provenance {
                hooray_version: "0.5.1".into(),
                xray_cli_version: Some("3.8.2".into()),
                xray_version: None,
                xray_db_date: Some("2026-08-01".into()),
                commands: vec!["jf audit --format json".into()],
                environment: "operator workstation".into(),
            },
            hooray,
            xray,
            enforcement: Some(Enforcement {
                min_purl_recall: Some(0.9),
                min_purl_precision: None,
                min_cve_jaccard: Some(0.8),
            }),
        }
    }

    #[test]
    fn roundtrips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("case.recording.json");
        let recording = fixture();
        recording.save(&path).unwrap();
        let loaded = Recording::load(&path).unwrap();
        assert_eq!(loaded, recording);
        assert_eq!(
            loaded.provenance.xray_db_date.as_deref(),
            Some("2026-08-01")
        );
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut tampered = fixture();
        tampered.schema_version = 2;
        let error = tampered.validate().unwrap_err();
        assert!(matches!(
            error,
            ParityError::UnsupportedSchemaVersion { .. }
        ));
        assert!(error.to_string().contains("schema_version 2"));

        // Saving refuses to persist an invalid recording.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.json");
        assert!(tampered.save(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn rejects_wrong_nested_canonical_schema_version() {
        let mut tampered = fixture();
        tampered.hooray.schema_version = 2;
        let error = tampered.validate().unwrap_err();
        assert!(matches!(
            error,
            ParityError::UnsupportedSchemaVersion {
                context: "canonical hooray",
                ..
            }
        ));
        assert!(error.to_string().contains("schema_version 2"));

        let mut tampered = fixture();
        tampered.xray.schema_version = 3;
        let error = tampered.validate().unwrap_err();
        assert!(matches!(
            error,
            ParityError::UnsupportedSchemaVersion {
                context: "canonical xray",
                ..
            }
        ));
    }

    #[test]
    fn rejects_case_mismatch_between_sections() {
        let mut tampered = fixture();
        tampered.xray.case_id = "other-case".to_owned();
        let error = tampered.validate().unwrap_err();
        assert!(matches!(error, ParityError::CaseMismatch { .. }));
        assert!(error.to_string().contains("other-case"));
    }
}
