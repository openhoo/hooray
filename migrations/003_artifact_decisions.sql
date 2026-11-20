-- Reserve an attempt before scanning. A newer, unfinished attempt blocks
-- consumption of an old allow, even across crashes or concurrent processes.
CREATE TABLE artifact_gate_attempts (
    attempt_id INTEGER PRIMARY KEY CHECK(attempt_id>0),
    artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64 AND policy_sha256 NOT GLOB '*[^0-9a-f]*'),
    started_at TEXT NOT NULL CHECK(length(started_at)>0)
) STRICT;
CREATE INDEX artifact_gate_identity ON artifact_gate_attempts(artifact_sha256,policy_sha256,attempt_id DESC);

CREATE TABLE artifact_gate_decisions (
    attempt_id INTEGER PRIMARY KEY REFERENCES artifact_gate_attempts(attempt_id),
    run_id TEXT UNIQUE NOT NULL REFERENCES scan_runs(run_id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK(length(scope)>0),
    scanner_version TEXT NOT NULL CHECK(length(scanner_version)>0),
    publisher_source TEXT NOT NULL CHECK(length(publisher_source)>0),
    publisher_revision TEXT NOT NULL CHECK(length(publisher_revision)>0),
    publisher_sha256 TEXT NOT NULL CHECK(length(publisher_sha256)=64 AND publisher_sha256 NOT GLOB '*[^0-9a-f]*'),
    outcome TEXT NOT NULL CHECK(outcome IN ('allow','deny','unknown')),
    reason TEXT NOT NULL CHECK(length(reason)>0),
    component_purl TEXT,
    matched_advisories INTEGER CHECK(matched_advisories >= 0),
    policy_allowed INTEGER NOT NULL CHECK(policy_allowed >= 0),
    policy_warned INTEGER NOT NULL CHECK(policy_warned >= 0),
    policy_denied INTEGER NOT NULL CHECK(policy_denied >= 0),
    completed_at TEXT NOT NULL CHECK(length(completed_at)>0),
    CHECK(outcome != 'allow' OR (component_purl IS NOT NULL AND matched_advisories IS 0 AND policy_denied = 0))
) STRICT;
CREATE TRIGGER artifact_gate_attempt_no_update BEFORE UPDATE ON artifact_gate_attempts
BEGIN SELECT RAISE(ABORT,'artifact gate attempts are immutable'); END;
CREATE TRIGGER artifact_gate_attempt_no_delete BEFORE DELETE ON artifact_gate_attempts
BEGIN SELECT RAISE(ABORT,'artifact gate attempts are immutable'); END;
CREATE TRIGGER artifact_gate_decision_no_update BEFORE UPDATE ON artifact_gate_decisions
BEGIN SELECT RAISE(ABORT,'artifact gate decisions are immutable'); END;
CREATE TRIGGER artifact_gate_decision_no_delete BEFORE DELETE ON artifact_gate_decisions
BEGIN SELECT RAISE(ABORT,'artifact gate decisions are immutable'); END;
-- REPLACE can bypass DELETE triggers when recursive_triggers is disabled.
-- Explicit collision checks also cover the second UNIQUE key on a decision.
CREATE TRIGGER artifact_gate_attempt_no_replace BEFORE INSERT ON artifact_gate_attempts
WHEN EXISTS(SELECT 1 FROM artifact_gate_attempts WHERE attempt_id=NEW.attempt_id)
BEGIN SELECT RAISE(ABORT,'artifact gate attempts are immutable'); END;
CREATE TRIGGER artifact_gate_decision_no_replace BEFORE INSERT ON artifact_gate_decisions
WHEN EXISTS(SELECT 1 FROM artifact_gate_decisions WHERE attempt_id=NEW.attempt_id OR run_id=NEW.run_id)
BEGIN SELECT RAISE(ABORT,'artifact gate decisions are immutable'); END;
