"""Tests for SQLite repository."""

from __future__ import annotations

import pytest

from cti_graph.db.repository import TABLE_COLUMNS, SQLiteRepository


@pytest.fixture
def repo(tmp_path) -> SQLiteRepository:
    r = SQLiteRepository(tmp_path / "test.db")
    r.init_schema()
    return r


def test_init_schema_creates_tables(repo):
    tables = repo.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    table_names = {row["name"] for row in tables}
    for expected in TABLE_COLUMNS:
        assert expected in table_names, f"Missing table: {expected}"


def test_upsert_and_fetch_threat_actor(repo):
    rows = [
        {
            "stix_id": "threat-actor--test-001",
            "stix_type": "threat-actor",
            "name": "Test Actor",
            "aliases": ["Alias1", "Alias2"],
            "sophistication": "advanced",
            "motivation": "espionage",
            "tags": ["apt", "targets-japan"],
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2025-06-01T00:00:00+00:00",
            "stix_modified": "2025-06-01T00:00:00+00:00",
        }
    ]
    count = repo.upsert_rows("ThreatActor", rows)
    assert count == 1

    result = repo.fetch_all("ThreatActor")
    assert len(result) == 1
    actor = result[0]
    assert actor["name"] == "Test Actor"
    assert actor["aliases"] == ["Alias1", "Alias2"]
    assert actor["tags"] == ["apt", "targets-japan"]


def test_upsert_idempotent(repo):
    row = {
        "stix_id": "attack-pattern--test-001",
        "attack_technique_id": "T1566.001",
        "tactic": "initial-access",
        "name": "Spearphishing",
        "description": "Test",
        "platforms": ["Windows"],
        "detection_difficulty": None,
        "stix_modified": "2025-01-01T00:00:00+00:00",
    }
    repo.upsert_rows("TTP", [row])
    repo.upsert_rows("TTP", [row])

    result = repo.fetch_all("TTP")
    assert len(result) == 1


def test_upsert_updates_existing(repo):
    row1 = {
        "stix_id": "attack-pattern--test-001",
        "attack_technique_id": "T1566.001",
        "tactic": "initial-access",
        "name": "Old Name",
        "description": None,
        "platforms": [],
        "detection_difficulty": None,
        "stix_modified": "2025-01-01T00:00:00+00:00",
    }
    repo.upsert_rows("TTP", [row1])

    row2 = dict(row1)
    row2["name"] = "New Name"
    row2["stix_modified"] = "2025-06-01T00:00:00+00:00"
    repo.upsert_rows("TTP", [row2])

    result = repo.fetch_all("TTP")
    assert len(result) == 1
    assert result[0]["name"] == "New Name"


def test_upsert_empty_list(repo):
    count = repo.upsert_rows("TTP", [])
    assert count == 0


def test_query_with_params(repo):
    rows = [
        {
            "stix_id": f"attack-pattern--test-{i:03d}",
            "attack_technique_id": f"T{1000 + i}",
            "tactic": "execution" if i % 2 == 0 else "persistence",
            "name": f"TTP {i}",
            "description": None,
            "platforms": [],
            "detection_difficulty": None,
            "stix_modified": "2025-01-01T00:00:00+00:00",
        }
        for i in range(5)
    ]
    repo.upsert_rows("TTP", rows)

    result = repo.query(
        "SELECT * FROM TTP WHERE tactic = :tactic",
        {"tactic": "execution"},
    )
    assert len(result) == 3  # i=0,2,4


def test_upsert_edge_table(repo):
    # Insert nodes first (foreign key constraint)
    repo.upsert_rows(
        "ThreatActor",
        [
            {
                "stix_id": "threat-actor--a1",
                "stix_type": "threat-actor",
                "name": "Actor A",
                "aliases": [],
                "sophistication": None,
                "motivation": None,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
                "stix_modified": "2025-01-01T00:00:00+00:00",
            }
        ],
    )
    repo.upsert_rows(
        "TTP",
        [
            {
                "stix_id": "attack-pattern--t1",
                "attack_technique_id": "T1566",
                "tactic": "initial-access",
                "name": "Phishing",
                "description": None,
                "platforms": [],
                "detection_difficulty": None,
                "stix_modified": "2025-01-01T00:00:00+00:00",
            }
        ],
    )

    # Insert edge
    repo.upsert_rows(
        "Uses",
        [
            {
                "actor_stix_id": "threat-actor--a1",
                "ttp_stix_id": "attack-pattern--t1",
                "confidence": 90,
                "first_observed": "2024-01-01T00:00:00+00:00",
                "last_observed": "2025-01-01T00:00:00+00:00",
                "stix_id": "relationship--r1",
            }
        ],
    )

    result = repo.fetch_all("Uses")
    assert len(result) == 1
    assert result[0]["confidence"] == 90


def test_json_column_roundtrip(repo):
    repo.upsert_rows(
        "SecurityControl",
        [
            {
                "id": "ctrl-001",
                "name": "EDR",
                "control_type": "edr",
                "coverage": ["endpoint", "server"],
            }
        ],
    )
    result = repo.fetch_all("SecurityControl")
    assert result[0]["coverage"] == ["endpoint", "server"]


def test_close(tmp_path):
    repo = SQLiteRepository(tmp_path / "close_test.db")
    repo.init_schema()
    repo.close()
    # After close, operations should raise
    with pytest.raises(Exception):
        repo.fetch_all("TTP")
