use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, FixedOffset};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApplicabilityStatus, Component, Confidence, Finding, FindingKind, Inventory, PolicyDecision,
    PolicyId, PolicyOutcome, PolicySummary, Scope, Severity,
};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub fail_closed: FailClosed,
    #[serde(default = "default_outcome")]
    pub default_outcome: PolicyOutcome,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub exceptions: Vec<PolicyException>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailClosed {
    #[serde(default)]
    pub unknown_applicability: bool,
    #[serde(default)]
    pub unknown_licenses: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: PolicyId,
    #[serde(default)]
    pub priority: i32,
    pub outcome: PolicyOutcome,
    pub reason: String,
    #[serde(default)]
    pub selectors: RuleSelectors,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSelectors {
    #[serde(default)]
    pub kinds: BTreeSet<FindingKind>,
    #[serde(default)]
    pub minimum_severity: Option<Severity>,
    #[serde(default)]
    pub confidence: BTreeSet<Confidence>,
    #[serde(default)]
    pub applicability: BTreeSet<ApplicabilityStatus>,
    #[serde(default)]
    pub risk: Option<RiskRange>,
    #[serde(default)]
    pub license_expressions: BTreeSet<String>,
    #[serde(default)]
    pub scopes: BTreeSet<Scope>,
    #[serde(default)]
    pub purls: BTreeSet<String>,
    #[serde(default)]
    pub rule_ids: BTreeSet<String>,
    #[serde(default)]
    pub advisory_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskRange {
    #[serde(default)]
    pub minimum: Option<u16>,
    #[serde(default)]
    pub maximum: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyException {
    pub id: String,
    pub owner: String,
    pub reason: String,
    pub ticket: String,
    pub expires_at: String,
    #[serde(default)]
    pub compensating_controls: BTreeSet<String>,
    pub selectors: ExceptionSelectors,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionSelectors {
    #[serde(default)]
    pub finding_id: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub kind: Option<FindingKind>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub advisory_id: Option<String>,
    #[serde(default)]
    pub scope: Option<Scope>,
    #[serde(default)]
    pub license_expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decisions: BTreeSet<PolicyDecision>,
    pub summary: PolicySummary,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid YAML policy: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid TOML policy: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported policy schema version {0}; expected 1")]
    UnsupportedVersion(u32),
    #[error("policy rule ID '{0}' is duplicated")]
    DuplicateRuleId(String),
    #[error("policy exception ID '{0}' is duplicated")]
    DuplicateExceptionId(String),
    #[error("{field} must not be empty")]
    EmptyField { field: String },
    #[error("rule '{rule_id}' has an invalid risk range")]
    InvalidRiskRange { rule_id: String },
    #[error("rule '{rule_id}' has invalid {selector} glob '{pattern}': {source}")]
    InvalidGlob {
        rule_id: String,
        selector: &'static str,
        pattern: String,
        source: globset::Error,
    },
    #[error("exception '{0}' must contain at least one exact selector")]
    BroadException(String),
    #[error("exception '{exception_id}' {selector} must be exact, not a glob")]
    NonExactExceptionSelector {
        exception_id: String,
        selector: &'static str,
    },
    #[error("exception '{exception_id}' has invalid ISO 8601 expiry '{value}'")]
    InvalidExpiry { exception_id: String, value: String },
}

fn default_outcome() -> PolicyOutcome {
    PolicyOutcome::Allow
}

impl Policy {
    pub fn from_yaml(contents: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(contents)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_toml(contents: &str) -> Result<Self, PolicyError> {
        let policy: Self = toml::from_str(contents)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }

        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.to_string()));
            }
            require_text(format!("rule '{}'.reason", rule.id), &rule.reason)?;
            if let Some(range) = rule.selectors.risk
                && (range.minimum.is_none() && range.maximum.is_none()
                    || range.minimum.is_some_and(|value| value > 10_000)
                    || range.maximum.is_some_and(|value| value > 10_000)
                    || matches!((range.minimum, range.maximum), (Some(min), Some(max)) if min > max))
            {
                return Err(PolicyError::InvalidRiskRange {
                    rule_id: rule.id.to_string(),
                });
            }
            validate_globs(rule, "purls", &rule.selectors.purls)?;
            validate_globs(rule, "rule_ids", &rule.selectors.rule_ids)?;
            validate_globs(rule, "advisory_ids", &rule.selectors.advisory_ids)?;
            for expression in &rule.selectors.license_expressions {
                require_text(
                    format!("rule '{}'.selectors.license_expressions", rule.id),
                    expression,
                )?;
            }
        }

        let mut exception_ids = BTreeSet::new();
        for exception in &self.exceptions {
            require_text("exception.id".to_owned(), &exception.id)?;
            if !exception_ids.insert(exception.id.as_str()) {
                return Err(PolicyError::DuplicateExceptionId(exception.id.clone()));
            }
            require_text(
                format!("exception '{}'.owner", exception.id),
                &exception.owner,
            )?;
            require_text(
                format!("exception '{}'.reason", exception.id),
                &exception.reason,
            )?;
            require_text(
                format!("exception '{}'.ticket", exception.id),
                &exception.ticket,
            )?;
            parse_expiry(exception)?;
            if exception.selectors.is_empty() {
                return Err(PolicyError::BroadException(exception.id.clone()));
            }
            validate_exact_exception_selectors(exception)?;
            for control in &exception.compensating_controls {
                require_text(
                    format!("exception '{}'.compensating_controls", exception.id),
                    control,
                )?;
            }
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        findings: &BTreeMap<crate::model::FindingId, Finding>,
        inventory: &Inventory,
        now: DateTime<FixedOffset>,
    ) -> Result<PolicyEvaluation, PolicyError> {
        self.validate()?;
        let compiled = CompiledPolicy::new(self)?;
        let decisions = findings
            .values()
            .map(|finding| compiled.evaluate_finding(finding, inventory, now))
            .collect();
        let summary = PolicySummary::from_decisions(&decisions);
        Ok(PolicyEvaluation { decisions, summary })
    }
}

impl ExceptionSelectors {
    fn is_empty(&self) -> bool {
        self.finding_id.is_none()
            && self.policy_id.is_none()
            && self.kind.is_none()
            && self.purl.is_none()
            && self.rule_id.is_none()
            && self.advisory_id.is_none()
            && self.scope.is_none()
            && self.license_expression.is_none()
    }
}

struct CompiledRule<'a> {
    rule: &'a PolicyRule,
    purls: GlobSet,
    rule_ids: GlobSet,
    advisory_ids: GlobSet,
}

struct CompiledPolicy<'a> {
    policy: &'a Policy,
    rules: Vec<CompiledRule<'a>>,
    expiries: BTreeMap<&'a str, DateTime<FixedOffset>>,
    exceptions: Vec<&'a PolicyException>,
}

impl<'a> CompiledPolicy<'a> {
    fn new(policy: &'a Policy) -> Result<Self, PolicyError> {
        let mut rules = policy
            .rules
            .iter()
            .map(|rule| {
                Ok(CompiledRule {
                    rule,
                    purls: compile_globs(rule, "purls", &rule.selectors.purls)?,
                    rule_ids: compile_globs(rule, "rule_ids", &rule.selectors.rule_ids)?,
                    advisory_ids: compile_globs(
                        rule,
                        "advisory_ids",
                        &rule.selectors.advisory_ids,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        rules.sort_by(|left, right| {
            right
                .rule
                .priority
                .cmp(&left.rule.priority)
                .then_with(|| left.rule.id.cmp(&right.rule.id))
        });
        let expiries = policy
            .exceptions
            .iter()
            .map(|exception| Ok((exception.id.as_str(), parse_expiry(exception)?)))
            .collect::<Result<_, PolicyError>>()?;
        let mut exceptions: Vec<_> = policy.exceptions.iter().collect();
        exceptions.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self {
            policy,
            rules,
            expiries,
            exceptions,
        })
    }

    fn evaluate_finding(
        &self,
        finding: &Finding,
        inventory: &Inventory,
        now: DateTime<FixedOffset>,
    ) -> PolicyDecision {
        let component = finding
            .component_id
            .as_ref()
            .and_then(|id| inventory.components.get(id));

        let mut decision = if self.policy.fail_closed.unknown_applicability
            && finding
                .applicability
                .as_ref()
                .is_none_or(|value| value.status == ApplicabilityStatus::Unknown)
        {
            decision(
                "fail-closed-applicability",
                finding,
                PolicyOutcome::Deny,
                "applicability is unknown and policy is fail-closed",
            )
        } else if self.policy.fail_closed.unknown_licenses
            && component.is_none_or(|value| known_license_expressions(value).is_empty())
        {
            decision(
                "fail-closed-license",
                finding,
                PolicyOutcome::Deny,
                "component license is unknown and policy is fail-closed",
            )
        } else if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.matches(finding, component, self.policy.fail_closed))
        {
            decision(
                rule.rule.id.as_str(),
                finding,
                rule.rule.outcome,
                &rule.rule.reason,
            )
        } else {
            decision(
                "default",
                finding,
                self.policy.default_outcome,
                "no policy rule matched",
            )
        };

        if let Some(exception) = self.exceptions.iter().copied().find(|exception| {
            self.expiries[exception.id.as_str()] > now
                && exception_matches(&exception.selectors, &decision, finding, component)
        }) {
            decision.outcome = PolicyOutcome::Allow;
            decision.reason = format!(
                "exception {}: {} (owner: {}; ticket: {})",
                exception.id, exception.reason, exception.owner, exception.ticket
            );
            decision.exception_id = Some(exception.id.clone());
        }
        decision
    }
}

impl CompiledRule<'_> {
    fn matches(
        &self,
        finding: &Finding,
        component: Option<&Component>,
        fail_closed: FailClosed,
    ) -> bool {
        let selectors = &self.rule.selectors;
        if !selectors.kinds.is_empty() && !selectors.kinds.contains(&finding.kind) {
            return false;
        }
        if selectors
            .minimum_severity
            .is_some_and(|minimum| finding.severity < minimum)
        {
            return false;
        }
        if !selectors.confidence.is_empty() && !selectors.confidence.contains(&finding.confidence) {
            return false;
        }
        if !selectors.applicability.is_empty() {
            let status = finding
                .applicability
                .as_ref()
                .map_or(ApplicabilityStatus::Unknown, |value| value.status);
            if status == ApplicabilityStatus::Unknown && fail_closed.unknown_applicability {
                return false;
            }
            if !selectors.applicability.contains(&status) {
                return false;
            }
        }
        if let Some(range) = selectors.risk {
            let Some(score) = finding.risk.as_ref().map(|risk| risk.score()) else {
                return false;
            };
            if range.minimum.is_some_and(|minimum| score < minimum)
                || range.maximum.is_some_and(|maximum| score > maximum)
            {
                return false;
            }
        }
        if !selectors.scopes.is_empty()
            && !component.is_some_and(|value| selectors.scopes.contains(&value.scope))
        {
            return false;
        }
        if !selectors.purls.is_empty()
            && !component.is_some_and(|value| self.purls.is_match(&value.purl))
        {
            return false;
        }
        if !selectors.rule_ids.is_empty() && !self.rule_ids.is_match(finding.rule_id.as_str()) {
            return false;
        }
        if !selectors.advisory_ids.is_empty()
            && !finding
                .advisory_id
                .as_deref()
                .is_some_and(|value| self.advisory_ids.is_match(value))
        {
            return false;
        }
        if !selectors.license_expressions.is_empty() {
            let expressions = component.map(known_license_expressions).unwrap_or_default();
            if expressions.is_empty() && fail_closed.unknown_licenses {
                return false;
            }
            if expressions.is_disjoint(&selectors.license_expressions) {
                return false;
            }
        }
        true
    }
}

fn decision(
    policy_id: &str,
    finding: &Finding,
    outcome: PolicyOutcome,
    reason: &str,
) -> PolicyDecision {
    PolicyDecision {
        policy_id: PolicyId::new(policy_id).expect("static and validated policy IDs are non-empty"),
        finding_id: Some(finding.id.clone()),
        outcome,
        reason: reason.to_owned(),
        exception_id: None,
    }
}

fn exception_matches(
    selectors: &ExceptionSelectors,
    decision: &PolicyDecision,
    finding: &Finding,
    component: Option<&Component>,
) -> bool {
    selectors
        .finding_id
        .as_deref()
        .is_none_or(|value| value == finding.id.as_str())
        && selectors
            .policy_id
            .as_deref()
            .is_none_or(|value| value == decision.policy_id.as_str())
        && selectors.kind.is_none_or(|value| value == finding.kind)
        && selectors
            .purl
            .as_deref()
            .is_none_or(|value| component.is_some_and(|component| value == component.purl))
        && selectors
            .rule_id
            .as_deref()
            .is_none_or(|value| value == finding.rule_id.as_str())
        && selectors
            .advisory_id
            .as_deref()
            .is_none_or(|value| finding.advisory_id.as_deref() == Some(value))
        && selectors
            .scope
            .is_none_or(|value| component.is_some_and(|component| value == component.scope))
        && selectors.license_expression.as_deref().is_none_or(|value| {
            component.is_some_and(|component| known_license_expressions(component).contains(value))
        })
}

fn known_license_expressions(component: &Component) -> BTreeSet<String> {
    component
        .licenses
        .iter()
        .filter_map(|license| license.expression.as_deref())
        .map(str::trim)
        .filter(|expression| !expression.is_empty())
        .map(str::to_owned)
        .collect()
}

fn require_text(field: String, value: &str) -> Result<(), PolicyError> {
    if value.trim().is_empty() {
        Err(PolicyError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn parse_expiry(exception: &PolicyException) -> Result<DateTime<FixedOffset>, PolicyError> {
    DateTime::parse_from_rfc3339(&exception.expires_at).map_err(|_| PolicyError::InvalidExpiry {
        exception_id: exception.id.clone(),
        value: exception.expires_at.clone(),
    })
}

fn validate_globs(
    rule: &PolicyRule,
    selector: &'static str,
    patterns: &BTreeSet<String>,
) -> Result<(), PolicyError> {
    compile_globs(rule, selector, patterns).map(|_| ())
}

fn compile_globs(
    rule: &PolicyRule,
    selector: &'static str,
    patterns: &BTreeSet<String>,
) -> Result<GlobSet, PolicyError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        require_text(format!("rule '{}'.selectors.{selector}", rule.id), pattern)?;
        builder.add(
            Glob::new(pattern).map_err(|source| PolicyError::InvalidGlob {
                rule_id: rule.id.to_string(),
                selector,
                pattern: pattern.clone(),
                source,
            })?,
        );
    }
    builder.build().map_err(|source| PolicyError::InvalidGlob {
        rule_id: rule.id.to_string(),
        selector,
        pattern: patterns.iter().cloned().collect::<Vec<_>>().join(","),
        source,
    })
}

fn validate_exact_exception_selectors(exception: &PolicyException) -> Result<(), PolicyError> {
    for (selector, value) in [
        ("finding_id", exception.selectors.finding_id.as_deref()),
        ("policy_id", exception.selectors.policy_id.as_deref()),
        ("purl", exception.selectors.purl.as_deref()),
        ("rule_id", exception.selectors.rule_id.as_deref()),
        ("advisory_id", exception.selectors.advisory_id.as_deref()),
        (
            "license_expression",
            exception.selectors.license_expression.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            require_text(
                format!("exception '{}'.selectors.{selector}", exception.id),
                value,
            )?;
            if value
                .bytes()
                .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
            {
                return Err(PolicyError::NonExactExceptionSelector {
                    exception_id: exception.id.clone(),
                    selector,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, ComponentId, FindingId, FindingStatus, License, Risk, RuleId,
    };

    fn now() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-07-21T12:00:00Z").unwrap()
    }

    fn inventory(license: Option<&str>, scope: Scope, purl: &str) -> Inventory {
        let component_id = ComponentId::new("component").unwrap();
        let licenses = license
            .map(|expression| License {
                expression: Some(expression.to_owned()),
                name: None,
                url: None,
            })
            .into_iter()
            .collect();
        Inventory {
            asset: Asset {
                id: AssetId::new("asset").unwrap(),
                name: "asset".to_owned(),
                kind: AssetKind::Package,
                version: None,
                metadata: BTreeMap::new(),
            },
            components: BTreeMap::from([(
                component_id.clone(),
                Component {
                    identity: component_id,
                    name: "component".to_owned(),
                    version: "1.0.0".to_owned(),
                    purl: purl.to_owned(),
                    scope,
                    provenance: BTreeSet::new(),
                    licenses,
                    locations: BTreeSet::new(),
                },
            )]),
            dependencies: BTreeSet::new(),
        }
    }

    fn finding(id: &str) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            kind: FindingKind::Vulnerability,
            rule_id: RuleId::new("CVE-2026-1").unwrap(),
            advisory_id: Some("GHSA-abcd-1234".to_owned()),
            component_id: Some(ComponentId::new("component").unwrap()),
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::High,
            confidence: Confidence::High,
            evidence: BTreeSet::new(),
            applicability: Some(crate::model::Applicability {
                status: ApplicabilityStatus::Affected,
                rationale: None,
            }),
            remediation: None,
            risk: Some(Risk::new(7_500).unwrap()),
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        }
    }

    fn policy(rules: Vec<PolicyRule>) -> Policy {
        Policy {
            version: 1,
            fail_closed: FailClosed::default(),
            default_outcome: PolicyOutcome::Allow,
            rules,
            exceptions: Vec::new(),
        }
    }

    fn rule(id: &str, priority: i32, outcome: PolicyOutcome) -> PolicyRule {
        PolicyRule {
            id: PolicyId::new(id).unwrap(),
            priority,
            outcome,
            reason: id.to_owned(),
            selectors: RuleSelectors::default(),
        }
    }

    fn evaluate_one(policy: &Policy, finding: Finding, inventory: &Inventory) -> PolicyDecision {
        policy
            .evaluate(
                &BTreeMap::from([(finding.id.clone(), finding)]),
                inventory,
                now(),
            )
            .unwrap()
            .decisions
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn rejects_unknown_yaml_and_toml_fields() {
        assert!(Policy::from_yaml("version: 1\nunknown: true").is_err());
        assert!(Policy::from_toml("version = 1\nunknown = true").is_err());
    }

    #[test]
    fn priority_then_policy_id_determines_precedence() {
        let inventory = inventory(Some("MIT"), Scope::Runtime, "pkg:cargo/example@1");
        let selected = evaluate_one(
            &policy(vec![
                rule("z-low", 1, PolicyOutcome::Deny),
                rule("z-peer", 2, PolicyOutcome::Warn),
                rule("a-peer", 2, PolicyOutcome::Deny),
            ]),
            finding("finding"),
            &inventory,
        );
        assert_eq!(selected.policy_id.as_str(), "a-peer");
        assert_eq!(selected.outcome, PolicyOutcome::Deny);
    }

    #[test]
    fn expiry_boundary_is_expired_and_never_applies() {
        let inventory = inventory(Some("MIT"), Scope::Runtime, "pkg:cargo/example@1");
        let mut policy = policy(vec![rule("deny", 0, PolicyOutcome::Deny)]);
        policy.exceptions.push(PolicyException {
            id: "exception-1".to_owned(),
            owner: "security".to_owned(),
            reason: "temporary acceptance".to_owned(),
            ticket: "SEC-1".to_owned(),
            expires_at: "2026-07-21T12:00:00Z".to_owned(),
            compensating_controls: BTreeSet::new(),
            selectors: ExceptionSelectors {
                finding_id: Some("finding".to_owned()),
                ..ExceptionSelectors::default()
            },
        });
        let selected = evaluate_one(&policy, finding("finding"), &inventory);
        assert_eq!(selected.outcome, PolicyOutcome::Deny);
        assert_eq!(selected.exception_id, None);
    }

    #[test]
    fn exception_requires_every_exact_selector_to_match() {
        let inventory = inventory(Some("MIT"), Scope::Runtime, "pkg:cargo/example@1");
        let mut policy = policy(vec![rule("deny", 0, PolicyOutcome::Deny)]);
        policy.exceptions.push(PolicyException {
            id: "exception-1".to_owned(),
            owner: "security".to_owned(),
            reason: "temporary acceptance".to_owned(),
            ticket: "SEC-1".to_owned(),
            expires_at: "2026-07-22T12:00:00Z".to_owned(),
            compensating_controls: BTreeSet::from(["isolated workload".to_owned()]),
            selectors: ExceptionSelectors {
                finding_id: Some("finding".to_owned()),
                purl: Some("pkg:cargo/example@1".to_owned()),
                advisory_id: Some("wrong-advisory".to_owned()),
                ..ExceptionSelectors::default()
            },
        });
        assert_eq!(
            evaluate_one(&policy, finding("finding"), &inventory).outcome,
            PolicyOutcome::Deny
        );
        policy.exceptions[0].selectors.advisory_id = Some("GHSA-abcd-1234".to_owned());
        let selected = evaluate_one(&policy, finding("finding"), &inventory);
        assert_eq!(selected.outcome, PolicyOutcome::Allow);
        assert_eq!(selected.exception_id.as_deref(), Some("exception-1"));
    }

    #[test]
    fn rejects_malformed_and_broad_exceptions() {
        let mut broad = policy(Vec::new());
        broad.exceptions.push(PolicyException {
            id: "broad".to_owned(),
            owner: "security".to_owned(),
            reason: "reason".to_owned(),
            ticket: "SEC-1".to_owned(),
            expires_at: "2026-07-22T12:00:00Z".to_owned(),
            compensating_controls: BTreeSet::new(),
            selectors: ExceptionSelectors::default(),
        });
        assert!(matches!(
            broad.validate(),
            Err(PolicyError::BroadException(_))
        ));
        broad.exceptions[0].selectors.purl = Some("pkg:cargo/*".to_owned());
        assert!(matches!(
            broad.validate(),
            Err(PolicyError::NonExactExceptionSelector { .. })
        ));
        broad.exceptions[0].selectors.purl = Some("pkg:cargo/example@1".to_owned());
        broad.exceptions[0].expires_at = "tomorrow".to_owned();
        assert!(matches!(
            broad.validate(),
            Err(PolicyError::InvalidExpiry { .. })
        ));
    }

    #[test]
    fn license_scope_and_glob_rules_are_conjunctive() {
        let inventory = inventory(
            Some("GPL-3.0-only"),
            Scope::Runtime,
            "pkg:cargo/example@1.2.3",
        );
        let mut deny = rule("copyleft-runtime", 10, PolicyOutcome::Deny);
        deny.selectors.kinds.insert(FindingKind::Vulnerability);
        deny.selectors.minimum_severity = Some(Severity::High);
        deny.selectors.confidence.insert(Confidence::High);
        deny.selectors
            .applicability
            .insert(ApplicabilityStatus::Affected);
        deny.selectors.risk = Some(RiskRange {
            minimum: Some(7_000),
            maximum: Some(8_000),
        });
        deny.selectors
            .license_expressions
            .insert("GPL-3.0-only".to_owned());
        deny.selectors.scopes.insert(Scope::Runtime);
        deny.selectors
            .purls
            .insert("pkg:cargo/example@*".to_owned());
        deny.selectors.rule_ids.insert("CVE-2026-*".to_owned());
        deny.selectors.advisory_ids.insert("GHSA-*".to_owned());
        assert_eq!(
            evaluate_one(&policy(vec![deny.clone()]), finding("finding"), &inventory).outcome,
            PolicyOutcome::Deny
        );
        deny.selectors.license_expressions.insert("MIT".to_owned());
        deny.selectors.license_expressions.remove("GPL-3.0-only");
        assert_eq!(
            evaluate_one(&policy(vec![deny]), finding("finding"), &inventory).outcome,
            PolicyOutcome::Allow
        );
    }

    #[test]
    fn fail_closed_unknowns_deny_without_matching_rules() {
        let inventory = inventory(None, Scope::Runtime, "pkg:cargo/example@1");
        let mut finding = finding("finding");
        finding.applicability = None;
        let policy = Policy {
            version: 1,
            fail_closed: FailClosed {
                unknown_applicability: true,
                unknown_licenses: true,
            },
            default_outcome: PolicyOutcome::Allow,
            rules: Vec::new(),
            exceptions: Vec::new(),
        };
        let selected = evaluate_one(&policy, finding, &inventory);
        assert_eq!(selected.outcome, PolicyOutcome::Deny);
        assert_eq!(selected.policy_id.as_str(), "fail-closed-applicability");
    }

    #[test]
    fn future_exception_applies_but_only_to_selected_policy() {
        let inventory = inventory(Some("MIT"), Scope::Runtime, "pkg:cargo/example@1");
        let mut policy = policy(vec![rule("deny", 0, PolicyOutcome::Deny)]);
        policy.exceptions.push(PolicyException {
            id: "exception-1".to_owned(),
            owner: "security".to_owned(),
            reason: "temporary acceptance".to_owned(),
            ticket: "SEC-1".to_owned(),
            expires_at: "2026-07-21T12:00:01Z".to_owned(),
            compensating_controls: BTreeSet::new(),
            selectors: ExceptionSelectors {
                policy_id: Some("another-policy".to_owned()),
                finding_id: Some("finding".to_owned()),
                ..ExceptionSelectors::default()
            },
        });
        assert_eq!(
            evaluate_one(&policy, finding("finding"), &inventory).outcome,
            PolicyOutcome::Deny
        );
        policy.exceptions[0].selectors.policy_id = Some("deny".to_owned());
        assert_eq!(
            evaluate_one(&policy, finding("finding"), &inventory).outcome,
            PolicyOutcome::Allow
        );
    }

    #[test]
    fn validation_rejects_duplicate_ids_invalid_ranges_and_globs() {
        let duplicate = policy(vec![
            rule("duplicate", 0, PolicyOutcome::Warn),
            rule("duplicate", 1, PolicyOutcome::Deny),
        ]);
        assert!(matches!(
            duplicate.validate(),
            Err(PolicyError::DuplicateRuleId(_))
        ));

        let mut invalid_range = rule("range", 0, PolicyOutcome::Deny);
        invalid_range.selectors.risk = Some(RiskRange {
            minimum: Some(9_000),
            maximum: Some(8_000),
        });
        assert!(matches!(
            policy(vec![invalid_range]).validate(),
            Err(PolicyError::InvalidRiskRange { .. })
        ));

        let mut invalid_glob = rule("glob", 0, PolicyOutcome::Deny);
        invalid_glob.selectors.purls.insert("[".to_owned());
        assert!(matches!(
            policy(vec![invalid_glob]).validate(),
            Err(PolicyError::InvalidGlob { .. })
        ));
    }

    #[test]
    fn evaluation_is_deterministic_across_input_and_rule_order() {
        let inventory = inventory(Some("MIT"), Scope::Runtime, "pkg:cargo/example@1");
        let findings_a = BTreeMap::from([
            (FindingId::new("b").unwrap(), finding("b")),
            (FindingId::new("a").unwrap(), finding("a")),
        ]);
        let mut rules = vec![
            rule("z", 5, PolicyOutcome::Warn),
            rule("a", 5, PolicyOutcome::Deny),
        ];
        let first = policy(rules.clone())
            .evaluate(&findings_a, &inventory, now())
            .unwrap();
        rules.reverse();
        let second = policy(rules)
            .evaluate(&findings_a, &inventory, now())
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.summary.denied, 2);
    }
}
