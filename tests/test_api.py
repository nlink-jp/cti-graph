"""Tests for the FastAPI Analysis API."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cti_graph.api.app import create_app
from cti_graph.config import Config
from cti_graph.db.repository import SQLiteRepository
from cti_graph.etl.worker import ETLWorker
from cti_graph.pir.filter import PIRFilter
from cti_graph.stix.parser import load_bundle_from_file

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def populated_db(tmp_path) -> tuple[Config, SQLiteRepository]:
    """Create a DB populated with sample data including assets."""
    db_path = tmp_path / "test.db"
    cfg = Config(database={"path": str(db_path)})
    repo = SQLiteRepository(db_path)
    repo.init_schema()

    # Load sample STIX data
    pir = PIRFilter(
        [
            {
                "pir_id": "PIR-TEST",
                "description": "Test",
                "threat_actor_tags": ["apt", "espionage"],
                "asset_weight_rules": [
                    {"tag": "external-facing", "criticality_multiplier": 2.0},
                    {"tag": "endpoint", "criticality_multiplier": 1.5},
                ],
            }
        ]
    )

    # Insert assets
    assets = [
        {
            "id": "asset-web-01",
            "name": "WebServer",
            "asset_type": "server",
            "environment": "onprem",
            "criticality": 5.0,
            "pir_adjusted_criticality": None,
            "owner": "infra",
            "network_segment": "DMZ",
            "network_cidr": "10.0.1.0/24",
            "network_zone": "dmz",
            "exposed_to_internet": 1,
            "tags": ["external-facing", "endpoint"],
            "last_updated": "2025-01-01T00:00:00+00:00",
        },
    ]
    repo.upsert_rows("Asset", assets)

    # Run ETL
    objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
    worker = ETLWorker(repo, pir)
    worker.process_bundle(objects, asset_rows=assets)

    return cfg, repo


@pytest.fixture
def client(populated_db) -> TestClient:
    cfg, repo = populated_db
    app = create_app(cfg)
    # Override lifespan by setting state directly
    app.state.repo = repo
    with TestClient(app) as c:
        yield c
    repo.close()


class TestAttackPaths:
    def test_returns_results(self, client):
        resp = client.get("/attack-paths", params={"asset_id": "asset-web-01"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            assert "actor_name" in data[0]
            assert "ttp_name" in data[0]

    def test_empty_asset(self, client):
        resp = client.get("/attack-paths", params={"asset_id": "nonexistent"})
        assert resp.status_code == 200
        assert resp.json() == []


class TestChokePoints:
    def test_returns_results(self, client):
        resp = client.get("/choke-points")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            assert "choke_score" in data[0]
            assert data[0]["choke_score"] > 0


class TestActorTTPs:
    def test_returns_flow(self, client):
        resp = client.get(
            "/actor-ttps",
            params={"actor_id": "threat-actor--04f69fa3-0776-43ae-a37b-f37917028fb7"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            assert "weight" in data[0]
            assert "src_ttp_name" in data[0]


class TestAssetExposure:
    def test_returns_exposed(self, client):
        resp = client.get("/asset-exposure")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["asset_name"] == "WebServer"


class TestAuth:
    def test_no_auth_when_not_configured(self, populated_db):
        cfg, repo = populated_db
        app = create_app(cfg)
        app.state.repo = repo
        with TestClient(app) as c:
            resp = c.get("/choke-points")
            assert resp.status_code == 200

    def test_auth_required_when_configured(self, populated_db, monkeypatch):
        cfg, repo = populated_db
        monkeypatch.setenv("CTI_GRAPH_API_TOKEN", "secret-token-123")
        app = create_app(cfg)
        app.state.repo = repo
        with TestClient(app) as c:
            # No token
            resp = c.get("/choke-points")
            assert resp.status_code == 401

            # Wrong token
            resp = c.get("/choke-points", headers={"Authorization": "Bearer wrong"})
            assert resp.status_code == 403

            # Correct token
            resp = c.get("/choke-points", headers={"Authorization": "Bearer secret-token-123"})
            assert resp.status_code == 200
