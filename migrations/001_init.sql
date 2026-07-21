CREATE TABLE IF NOT EXISTS scan_runs (
    run_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(run_id)) > 0),
    schema_version TEXT NOT NULL CHECK (length(trim(schema_version)) > 0),
    started_at TEXT NOT NULL CHECK (length(trim(started_at)) > 0),
    completed_at TEXT,
    scanner_version TEXT,
    asset_id TEXT NOT NULL CHECK (length(trim(asset_id)) > 0),
    finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
    report_json TEXT NOT NULL CHECK (json_valid(report_json))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at DESC, run_id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_asset ON scan_runs(asset_id, started_at DESC, run_id DESC);

CREATE TABLE IF NOT EXISTS scan_assets (
    run_id TEXT PRIMARY KEY NOT NULL,
    asset_id TEXT NOT NULL CHECK (length(trim(asset_id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
    version TEXT,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    asset_json TEXT NOT NULL CHECK (json_valid(asset_json)),
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_scan_assets_identity ON scan_assets(asset_id, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_assets_kind ON scan_assets(kind, run_id);

CREATE TABLE IF NOT EXISTS scan_components (
    run_id TEXT NOT NULL,
    component_id TEXT NOT NULL CHECK (length(trim(component_id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    version TEXT NOT NULL,
    purl TEXT NOT NULL CHECK (length(trim(purl)) > 0),
    scope TEXT NOT NULL CHECK (length(trim(scope)) > 0),
    component_json TEXT NOT NULL CHECK (json_valid(component_json)),
    PRIMARY KEY (run_id, component_id),
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_scan_components_purl ON scan_components(purl, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_components_name ON scan_components(name, version, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_components_scope ON scan_components(scope, run_id);

CREATE TABLE IF NOT EXISTS scan_dependency_edges (
    run_id TEXT NOT NULL,
    from_component_id TEXT NOT NULL,
    to_component_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (length(trim(scope)) > 0),
    optional INTEGER NOT NULL CHECK (optional IN (0, 1)),
    edge_json TEXT NOT NULL CHECK (json_valid(edge_json)),
    PRIMARY KEY (run_id, from_component_id, to_component_id, scope),
    FOREIGN KEY (run_id, from_component_id) REFERENCES scan_components(run_id, component_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, to_component_id) REFERENCES scan_components(run_id, component_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS scan_findings (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL CHECK (length(trim(finding_id)) > 0),
    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
    severity TEXT NOT NULL CHECK (length(trim(severity)) > 0),
    confidence TEXT NOT NULL CHECK (length(trim(confidence)) > 0),
    status TEXT NOT NULL CHECK (length(trim(status)) > 0),
    rule_id TEXT NOT NULL CHECK (length(trim(rule_id)) > 0),
    advisory_id TEXT,
    component_id TEXT,
    location_id TEXT,
    first_seen TEXT,
    last_seen TEXT,
    finding_json TEXT NOT NULL CHECK (json_valid(finding_json)),
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, component_id) REFERENCES scan_components(run_id, component_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_scan_findings_finding_id ON scan_findings(finding_id, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_kind_severity ON scan_findings(kind, severity, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_rule ON scan_findings(rule_id, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_advisory ON scan_findings(advisory_id, run_id) WHERE advisory_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_findings_component ON scan_findings(component_id, run_id) WHERE component_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_findings_status ON scan_findings(status, run_id);

CREATE TABLE IF NOT EXISTS scan_evidence (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    PRIMARY KEY (run_id, finding_id, ordinal),
    FOREIGN KEY (run_id, finding_id) REFERENCES scan_findings(run_id, finding_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS scan_remediations (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    remediation_json TEXT NOT NULL CHECK (json_valid(remediation_json)),
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id, finding_id) REFERENCES scan_findings(run_id, finding_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS scan_policy_decisions (
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    policy_id TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    finding_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'warn', 'deny')),
    exception_id TEXT,
    decision_json TEXT NOT NULL CHECK (json_valid(decision_json)),
    PRIMARY KEY (run_id, ordinal),
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, finding_id) REFERENCES scan_findings(run_id, finding_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_scan_policy_outcome ON scan_policy_decisions(outcome, run_id);
CREATE INDEX IF NOT EXISTS idx_scan_policy_id ON scan_policy_decisions(policy_id, run_id);

CREATE TABLE IF NOT EXISTS policy_documents (
    document_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(document_id)) > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    document_json TEXT NOT NULL CHECK (json_valid(document_json)),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    updated_by TEXT NOT NULL CHECK (length(trim(updated_by)) > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS policy_exceptions (
    exception_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(exception_id)) > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    document_json TEXT NOT NULL CHECK (json_valid(document_json)),
    expires_at TEXT,
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    updated_by TEXT NOT NULL CHECK (length(trim(updated_by)) > 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_policy_exceptions_expiry ON policy_exceptions(expires_at, exception_id);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(trim(event_id)) > 0),
    occurred_at TEXT NOT NULL CHECK (length(trim(occurred_at)) > 0),
    actor TEXT NOT NULL CHECK (length(trim(actor)) > 0),
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    resource_type TEXT NOT NULL CHECK (length(trim(resource_type)) > 0),
    resource_id TEXT NOT NULL CHECK (length(trim(resource_id)) > 0),
    details_json TEXT NOT NULL CHECK (json_valid(details_json))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at DESC, sequence DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id, sequence DESC);

CREATE TABLE IF NOT EXISTS retention_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL CHECK (length(trim(occurred_at)) > 0),
    cutoff_at TEXT NOT NULL CHECK (length(trim(cutoff_at)) > 0),
    deleted_runs INTEGER NOT NULL CHECK (deleted_runs >= 0),
    details_json TEXT NOT NULL CHECK (json_valid(details_json))
) STRICT;
