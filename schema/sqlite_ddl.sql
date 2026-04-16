-- =============================================================================
-- cti-graph — SQLite DDL
-- =============================================================================
-- Adapted from SAGE Spanner DDL for local-first SQLite storage.
-- STIX entities use stix_id as PRIMARY KEY (upsert idempotency).
-- Internal data (Asset etc.) use UUID as PRIMARY KEY.
-- Spanner ARRAY<STRING> → TEXT (JSON array serialised by repository layer).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- NODE TABLES — External data (STIX-derived)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ThreatActor (
  stix_id        TEXT NOT NULL PRIMARY KEY,
  stix_type      TEXT NOT NULL,              -- "threat-actor" | "intrusion-set"
  name           TEXT NOT NULL,
  aliases        TEXT,                       -- JSON array
  sophistication TEXT,                       -- minimal/intermediate/advanced/expert
  motivation     TEXT,                       -- financial/espionage/hacktivism etc.
  tags           TEXT,                       -- JSON array: PIR matching tags
  first_seen     TEXT,                       -- ISO 8601
  last_seen      TEXT,
  stix_modified  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS TTP (
  stix_id             TEXT NOT NULL PRIMARY KEY,
  attack_technique_id TEXT,                  -- T1059.001 etc.
  tactic              TEXT,                  -- initial-access/execution/persistence etc.
  name                TEXT NOT NULL,
  description         TEXT,
  platforms           TEXT,                  -- JSON array
  detection_difficulty INTEGER,              -- Summiting the Pyramid level (1-5)
  stix_modified       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Vulnerability (
  stix_id            TEXT NOT NULL PRIMARY KEY,
  cve_id             TEXT,                   -- CVE-2025-55182 etc.
  description        TEXT,
  cvss_score         REAL,
  epss_score         REAL,                   -- exploitation probability (0.0-1.0)
  affected_platforms TEXT,                   -- JSON array
  published_date     TEXT,
  stix_modified      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS MalwareTool (
  stix_id       TEXT NOT NULL PRIMARY KEY,
  stix_type     TEXT NOT NULL,               -- "malware" | "tool"
  name          TEXT NOT NULL,
  description   TEXT,
  capabilities  TEXT,                        -- JSON array
  stix_modified TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Observable (
  stix_id       TEXT NOT NULL PRIMARY KEY,
  obs_type      TEXT NOT NULL,               -- ip/domain/hash/email/url
  value         TEXT NOT NULL,
  confidence    INTEGER,                     -- 0-100
  tlp           TEXT,                        -- white/green/amber (red excluded at ingestion)
  first_seen    TEXT,
  last_seen     TEXT,
  stix_modified TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Incident (
  stix_id           TEXT NOT NULL PRIMARY KEY,
  name              TEXT NOT NULL,
  description       TEXT,
  occurred_at       TEXT,
  resolved_at       TEXT,
  severity          TEXT,                    -- low/medium/high/critical
  kill_chain_phases TEXT,                    -- JSON array
  diamond_model     TEXT,                    -- JSON object
  source            TEXT NOT NULL DEFAULT 'ir_feedback',
  stix_modified     TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- NODE TABLES — Internal data (UUID PK)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS SecurityControl (
  id           TEXT NOT NULL PRIMARY KEY,
  name         TEXT NOT NULL,
  control_type TEXT,                         -- edr/waf/siem/firewall/iam etc.
  coverage     TEXT                          -- JSON array
);

CREATE TABLE IF NOT EXISTS Asset (
  id                       TEXT NOT NULL PRIMARY KEY,
  name                     TEXT NOT NULL,
  asset_type               TEXT,             -- server/endpoint/saas/storage/network-device
  environment              TEXT,             -- onprem/aws/gcp
  criticality              REAL NOT NULL DEFAULT 5.0,
  pir_adjusted_criticality REAL,
  owner                    TEXT,
  network_segment          TEXT,             -- e.g. DMZ, Corporate LAN
  network_cidr             TEXT,             -- e.g. 10.0.1.0/24
  network_zone             TEXT,             -- dmz/internal/cloud-public/ot
  exposed_to_internet      INTEGER NOT NULL DEFAULT 0,  -- boolean
  tags                     TEXT,             -- JSON array
  last_updated             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Flow (TTP time-series)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS Uses (
  actor_stix_id  TEXT NOT NULL REFERENCES ThreatActor(stix_id),
  ttp_stix_id    TEXT NOT NULL REFERENCES TTP(stix_id),
  confidence     INTEGER,
  first_observed TEXT,
  last_observed  TEXT,
  stix_id        TEXT,
  PRIMARY KEY (actor_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS Exploits (
  ttp_stix_id  TEXT NOT NULL REFERENCES TTP(stix_id),
  vuln_stix_id TEXT NOT NULL REFERENCES Vulnerability(stix_id),
  stix_id      TEXT,
  PRIMARY KEY (ttp_stix_id, vuln_stix_id)
);

CREATE TABLE IF NOT EXISTS FollowedBy (
  src_ttp_stix_id   TEXT NOT NULL REFERENCES TTP(stix_id),
  dst_ttp_stix_id   TEXT NOT NULL REFERENCES TTP(stix_id),
  source            TEXT NOT NULL,           -- threat_intel | ir_feedback | manual_analysis
  weight            REAL NOT NULL DEFAULT 0.0,
  actor_stix_id     TEXT,
  evidence_stix_ids TEXT,                    -- JSON array
  last_calculated   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (src_ttp_stix_id, dst_ttp_stix_id, source)
);

CREATE TABLE IF NOT EXISTS IncidentUsesTTP (
  incident_stix_id TEXT NOT NULL REFERENCES Incident(stix_id),
  ttp_stix_id      TEXT NOT NULL REFERENCES TTP(stix_id),
  sequence_order   INTEGER,
  PRIMARY KEY (incident_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS MalwareUsesTTP (
  malware_stix_id TEXT NOT NULL REFERENCES MalwareTool(stix_id),
  ttp_stix_id     TEXT NOT NULL REFERENCES TTP(stix_id),
  confidence      INTEGER,
  first_observed  TEXT,
  last_observed   TEXT,
  stix_id         TEXT,
  PRIMARY KEY (malware_stix_id, ttp_stix_id)
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Attack Graph (asset connectivity)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS UsesTool (
  actor_stix_id  TEXT NOT NULL REFERENCES ThreatActor(stix_id),
  tool_stix_id   TEXT NOT NULL REFERENCES MalwareTool(stix_id),
  confidence     INTEGER,
  first_observed TEXT,
  last_observed  TEXT,
  stix_id        TEXT,
  PRIMARY KEY (actor_stix_id, tool_stix_id)
);

CREATE TABLE IF NOT EXISTS Targets (
  actor_stix_id TEXT NOT NULL REFERENCES ThreatActor(stix_id),
  asset_id      TEXT NOT NULL REFERENCES Asset(id),
  confidence    INTEGER,
  source        TEXT,                        -- pir_auto | manual | stix
  PRIMARY KEY (actor_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS TargetsAsset (
  ttp_stix_id  TEXT NOT NULL REFERENCES TTP(stix_id),
  asset_id     TEXT NOT NULL REFERENCES Asset(id),
  match_reason TEXT,
  PRIMARY KEY (ttp_stix_id, asset_id)
);

CREATE TABLE IF NOT EXISTS HasVulnerability (
  asset_id           TEXT NOT NULL REFERENCES Asset(id),
  vuln_stix_id       TEXT NOT NULL REFERENCES Vulnerability(stix_id),
  remediation_status TEXT NOT NULL DEFAULT 'open',
  detected_at        TEXT,
  PRIMARY KEY (asset_id, vuln_stix_id)
);

CREATE TABLE IF NOT EXISTS ConnectedTo (
  src_asset_id TEXT NOT NULL REFERENCES Asset(id),
  dst_asset_id TEXT NOT NULL REFERENCES Asset(id),
  protocol     TEXT,
  port         INTEGER,
  direction    TEXT NOT NULL DEFAULT 'bidirectional',
  allowed      INTEGER NOT NULL DEFAULT 1,   -- boolean
  PRIMARY KEY (src_asset_id, dst_asset_id)
);

CREATE TABLE IF NOT EXISTS ProtectedBy (
  asset_id   TEXT NOT NULL REFERENCES Asset(id),
  control_id TEXT NOT NULL REFERENCES SecurityControl(id),
  PRIMARY KEY (asset_id, control_id)
);

-- -----------------------------------------------------------------------------
-- EDGE TABLES — Observable (IoC)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS IndicatesTTP (
  observable_stix_id TEXT NOT NULL REFERENCES Observable(stix_id),
  ttp_stix_id        TEXT NOT NULL REFERENCES TTP(stix_id),
  confidence         INTEGER,
  stix_id            TEXT,
  PRIMARY KEY (observable_stix_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS IndicatesActor (
  observable_stix_id TEXT NOT NULL REFERENCES Observable(stix_id),
  actor_stix_id      TEXT NOT NULL REFERENCES ThreatActor(stix_id),
  confidence         INTEGER,
  stix_id            TEXT,
  PRIMARY KEY (observable_stix_id, actor_stix_id)
);

-- -----------------------------------------------------------------------------
-- PIR (Priority Intelligence Requirement)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS PIR (
  pir_id               TEXT NOT NULL PRIMARY KEY,
  intelligence_level   TEXT NOT NULL,        -- strategic | operational | tactical
  organizational_scope TEXT,
  decision_point       TEXT,
  description          TEXT NOT NULL,
  rationale            TEXT,
  recommended_action   TEXT,
  threat_actor_tags    TEXT,                 -- JSON array
  risk_composite       INTEGER,
  valid_from           TEXT,                 -- ISO 8601 date
  valid_until          TEXT,
  last_updated         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS PirPrioritizesActor (
  pir_id        TEXT NOT NULL REFERENCES PIR(pir_id),
  actor_stix_id TEXT NOT NULL REFERENCES ThreatActor(stix_id),
  overlap_ratio REAL,
  PRIMARY KEY (pir_id, actor_stix_id)
);

CREATE TABLE IF NOT EXISTS PirPrioritizesTTP (
  pir_id      TEXT NOT NULL REFERENCES PIR(pir_id),
  ttp_stix_id TEXT NOT NULL REFERENCES TTP(stix_id),
  PRIMARY KEY (pir_id, ttp_stix_id)
);

CREATE TABLE IF NOT EXISTS PirWeightsAsset (
  pir_id                 TEXT NOT NULL REFERENCES PIR(pir_id),
  asset_id               TEXT NOT NULL REFERENCES Asset(id),
  matched_tag            TEXT,
  criticality_multiplier REAL,
  PRIMARY KEY (pir_id, asset_id)
);

-- -----------------------------------------------------------------------------
-- INDEXES — query performance for common access patterns
-- -----------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_ttp_tactic ON TTP(tactic);
CREATE INDEX IF NOT EXISTS idx_ttp_technique ON TTP(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_cve ON Vulnerability(cve_id);
CREATE INDEX IF NOT EXISTS idx_observable_type_value ON Observable(obs_type, value);
CREATE INDEX IF NOT EXISTS idx_asset_internet ON Asset(exposed_to_internet);
CREATE INDEX IF NOT EXISTS idx_followedby_src ON FollowedBy(src_ttp_stix_id);
CREATE INDEX IF NOT EXISTS idx_followedby_dst ON FollowedBy(dst_ttp_stix_id);
CREATE INDEX IF NOT EXISTS idx_targets_asset ON Targets(asset_id);
CREATE INDEX IF NOT EXISTS idx_targets_actor ON Targets(actor_stix_id);
CREATE INDEX IF NOT EXISTS idx_uses_ttp ON Uses(ttp_stix_id);
CREATE INDEX IF NOT EXISTS idx_uses_actor ON Uses(actor_stix_id);
