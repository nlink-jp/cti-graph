"""Database repository abstraction layer.

Defines the Repository protocol for graph storage operations.
SQLite implementation is the default; future backends can implement the same protocol.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import structlog

logger = structlog.get_logger(__name__)

# Column definitions per table (order matters for inserts)
TABLE_COLUMNS: dict[str, list[str]] = {
    "ThreatActor": [
        "stix_id",
        "stix_type",
        "name",
        "aliases",
        "sophistication",
        "motivation",
        "tags",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "TTP": [
        "stix_id",
        "attack_technique_id",
        "tactic",
        "name",
        "description",
        "platforms",
        "detection_difficulty",
        "stix_modified",
    ],
    "Vulnerability": [
        "stix_id",
        "cve_id",
        "description",
        "cvss_score",
        "epss_score",
        "affected_platforms",
        "published_date",
        "stix_modified",
    ],
    "MalwareTool": [
        "stix_id",
        "stix_type",
        "name",
        "description",
        "capabilities",
        "stix_modified",
    ],
    "Observable": [
        "stix_id",
        "obs_type",
        "value",
        "confidence",
        "tlp",
        "first_seen",
        "last_seen",
        "stix_modified",
    ],
    "Incident": [
        "stix_id",
        "name",
        "description",
        "occurred_at",
        "resolved_at",
        "severity",
        "kill_chain_phases",
        "diamond_model",
        "source",
        "stix_modified",
    ],
    "SecurityControl": ["id", "name", "control_type", "coverage"],
    "Asset": [
        "id",
        "name",
        "asset_type",
        "environment",
        "criticality",
        "pir_adjusted_criticality",
        "owner",
        "network_segment",
        "network_cidr",
        "network_zone",
        "exposed_to_internet",
        "tags",
        "last_updated",
    ],
    "Uses": [
        "actor_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "UsesTool": [
        "actor_stix_id",
        "tool_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "Exploits": ["ttp_stix_id", "vuln_stix_id", "stix_id"],
    "MalwareUsesTTP": [
        "malware_stix_id",
        "ttp_stix_id",
        "confidence",
        "first_observed",
        "last_observed",
        "stix_id",
    ],
    "FollowedBy": [
        "src_ttp_stix_id",
        "dst_ttp_stix_id",
        "source",
        "weight",
        "actor_stix_id",
        "evidence_stix_ids",
        "last_calculated",
    ],
    "IncidentUsesTTP": ["incident_stix_id", "ttp_stix_id", "sequence_order"],
    "Targets": ["actor_stix_id", "asset_id", "confidence", "source"],
    "TargetsAsset": ["ttp_stix_id", "asset_id", "match_reason"],
    "HasVulnerability": ["asset_id", "vuln_stix_id", "remediation_status", "detected_at"],
    "ConnectedTo": ["src_asset_id", "dst_asset_id", "protocol", "port", "direction", "allowed"],
    "ProtectedBy": ["asset_id", "control_id"],
    "IndicatesTTP": ["observable_stix_id", "ttp_stix_id", "confidence", "stix_id"],
    "IndicatesActor": ["observable_stix_id", "actor_stix_id", "confidence", "stix_id"],
    "PIR": [
        "pir_id",
        "intelligence_level",
        "organizational_scope",
        "decision_point",
        "description",
        "rationale",
        "recommended_action",
        "threat_actor_tags",
        "risk_composite",
        "valid_from",
        "valid_until",
        "last_updated",
    ],
    "PirPrioritizesActor": ["pir_id", "actor_stix_id", "overlap_ratio"],
    "PirPrioritizesTTP": ["pir_id", "ttp_stix_id"],
    "PirWeightsAsset": ["pir_id", "asset_id", "matched_tag", "criticality_multiplier"],
}

# Columns storing JSON arrays (serialized as TEXT in SQLite)
_JSON_COLUMNS = frozenset(
    {
        "aliases",
        "tags",
        "platforms",
        "affected_platforms",
        "capabilities",
        "kill_chain_phases",
        "coverage",
        "evidence_stix_ids",
        "threat_actor_tags",
    }
)


@runtime_checkable
class GraphRepository(Protocol):
    """Protocol for graph storage backends."""

    def init_schema(self) -> None: ...
    def upsert_rows(self, table: str, rows: list[dict[str, Any]]) -> int: ...
    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]: ...
    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None: ...
    def fetch_all(self, table: str) -> list[dict[str, Any]]: ...
    def close(self) -> None: ...


class SQLiteRepository:
    """SQLite-based graph repository."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        schema_path = Path(__file__).parent.parent.parent.parent / "schema" / "sqlite_ddl.sql"
        sql = schema_path.read_text(encoding="utf-8")
        self._conn.executescript(sql)
        logger.info("schema_initialized")

    def upsert_rows(self, table: str, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0

        columns = TABLE_COLUMNS[table]
        placeholders = ", ".join(f":{col}" for col in columns)
        sql = f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"

        prepared = []
        for row in rows:
            params = {}
            for col in columns:
                val = row.get(col)
                if col in _JSON_COLUMNS and isinstance(val, (list, dict)):
                    val = json.dumps(val, ensure_ascii=False)
                if col == "diamond_model" and isinstance(val, dict):
                    val = json.dumps(val, ensure_ascii=False)
                params[col] = val
            prepared.append(params)

        self._conn.executemany(sql, prepared)
        self._conn.commit()
        logger.info("upserted", table=table, count=len(rows))
        return len(rows)

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        # Convert named params (:name → :name for sqlite, @name → :name from Spanner SQL)
        sql = sql.replace("@", ":")
        cursor = self._conn.execute(sql, params or {})
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = []
        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            # Deserialize JSON columns
            for col in columns:
                if col in _JSON_COLUMNS and isinstance(row_dict[col], str):
                    try:
                        row_dict[col] = json.loads(row_dict[col])
                    except (json.JSONDecodeError, TypeError):
                        pass
            rows.append(row_dict)
        return rows

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None:
        sql = sql.replace("@", ":")
        self._conn.execute(sql, params or {})
        self._conn.commit()

    def fetch_all(self, table: str) -> list[dict[str, Any]]:
        columns = TABLE_COLUMNS[table]
        sql = f"SELECT {', '.join(columns)} FROM {table}"
        return self.query(sql)

    def close(self) -> None:
        self._conn.close()
