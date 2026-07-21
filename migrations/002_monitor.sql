CREATE TABLE IF NOT EXISTS monitor_targets (
    target_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(target_id)) > 0),
    source TEXT NOT NULL CHECK (length(trim(source)) > 0),
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
    next_due_at TEXT NOT NULL CHECK (length(trim(next_due_at)) > 0),
    source_fingerprint TEXT,
    inventory_json TEXT CHECK (inventory_json IS NULL OR json_valid(inventory_json)),
    advisory_digest TEXT,
    policy_digest TEXT,
    finding_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(finding_ids_json) AND json_type(finding_ids_json) = 'array'),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_monitor_targets_due ON monitor_targets(next_due_at, target_id);

CREATE TABLE IF NOT EXISTS monitor_cursors (
    name TEXT PRIMARY KEY NOT NULL CHECK (length(trim(name)) > 0),
    cursor TEXT,
    etag TEXT,
    last_modified TEXT,
    advisory_digest TEXT,
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS monitor_events (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(event_id)) > 0),
    target_id TEXT NOT NULL CHECK (length(trim(target_id)) > 0),
    dedupe_key TEXT NOT NULL UNIQUE CHECK (length(trim(dedupe_key)) > 0),
    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TEXT,
    delivered_at TEXT,
    dead_lettered_at TEXT,
    last_error TEXT,
    FOREIGN KEY (target_id) REFERENCES monitor_targets(target_id) ON DELETE CASCADE,
    CHECK (delivered_at IS NULL OR dead_lettered_at IS NULL)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_monitor_events_delivery ON monitor_events(next_attempt_at, created_at, event_id)
    WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_monitor_events_target ON monitor_events(target_id, created_at DESC, event_id DESC);
