"""Tests for ETL worker."""

from __future__ import annotations

from pathlib import Path

import pytest

from cti_graph.db.repository import SQLiteRepository
from cti_graph.etl.worker import ETLWorker, _build_ttp_vuln_data
from cti_graph.pir.filter import PIRFilter
from cti_graph.stix.parser import load_bundle_from_file

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def repo(tmp_path) -> SQLiteRepository:
    r = SQLiteRepository(tmp_path / "test.db")
    r.init_schema()
    return r


@pytest.fixture
def pir_filter():
    return PIRFilter(
        [
            {
                "pir_id": "PIR-TEST-001",
                "intelligence_level": "strategic",
                "description": "Test PIR",
                "threat_actor_tags": ["apt", "espionage"],
                "asset_weight_rules": [
                    {"tag": "endpoint", "criticality_multiplier": 1.5},
                    {"tag": "external-facing", "criticality_multiplier": 2.0},
                ],
            }
        ]
    )


@pytest.fixture
def sample_assets():
    return [
        {
            "id": "asset-web-01",
            "name": "WebServer",
            "asset_type": "server",
            "environment": "onprem",
            "criticality": 5.0,
            "pir_adjusted_criticality": None,
            "owner": "infra-team",
            "network_segment": "DMZ",
            "network_cidr": "10.0.1.0/24",
            "network_zone": "dmz",
            "exposed_to_internet": 1,
            "tags": ["external-facing", "endpoint"],
            "last_updated": "2025-01-01T00:00:00+00:00",
        },
    ]


class TestETLWorkerE2E:
    def test_process_sample_bundle(self, repo, pir_filter):
        """E2E test: load sample bundle, process through ETL, verify DB state."""
        objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
        worker = ETLWorker(repo, pir_filter)

        stats = worker.process_bundle(objects)

        # Actor should be ingested (tags include "apt" which matches PIR)
        assert stats["threat_actors"] == 1
        actors = repo.fetch_all("ThreatActor")
        assert len(actors) == 1
        assert actors[0]["name"] == "Test APT Group"

        # TTPs
        assert stats["ttps"] == 2
        ttps = repo.fetch_all("TTP")
        assert len(ttps) == 2

        # Vulnerability
        assert stats["vulnerabilities"] == 1

        # MalwareTool
        assert stats["malware_tools"] == 1

        # Observables (2 indicators, both should pass TLP filter at amber)
        assert stats["observables"] >= 1

        # Relationships
        assert stats["uses"] == 2
        assert stats["exploits"] == 1
        assert stats["indicates_actor"] == 1

        # FollowedBy(threat_intel) should be derived from Uses edges
        assert stats["followed_by"] >= 1
        fb_rows = repo.fetch_all("FollowedBy")
        assert len(fb_rows) >= 1
        assert all(0.0 < r["weight"] <= 1.0 for r in fb_rows)

    def test_process_with_assets(self, repo, pir_filter, sample_assets):
        """Test ETL with asset rows for Targets edge generation."""
        # Pre-load assets
        repo.upsert_rows("Asset", sample_assets)

        objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
        worker = ETLWorker(repo, pir_filter)

        stats = worker.process_bundle(objects, asset_rows=sample_assets)

        # Targets should be generated (actor has "apt" tag matching PIR)
        assert stats["targets"] >= 1

        # PIR criticality should be updated
        assert stats["pir_criticality_updated"] >= 1
        updated_assets = repo.fetch_all("Asset")
        assert len(updated_assets) == 1
        assert updated_assets[0]["pir_adjusted_criticality"] is not None
        assert updated_assets[0]["pir_adjusted_criticality"] > 5.0

        # TargetsAsset (TTP T1566 -> endpoint tag)
        assert stats["targets_asset"] >= 1

        # PIR cascade
        assert stats["pirs"] == 1
        assert stats["pir_prioritizes_actor"] >= 1

    def test_process_empty_bundle(self, repo):
        """Empty bundle should produce zero counts."""
        worker = ETLWorker(repo, PIRFilter.empty())
        stats = worker.process_bundle([])

        assert stats["threat_actors"] == 0
        assert stats["ttps"] == 0
        assert stats["followed_by"] == 0

    def test_pir_filters_irrelevant_actors(self, repo):
        """Actors not matching PIR tags should be excluded."""
        pir = PIRFilter(
            [
                {
                    "pir_id": "PIR-NARROW",
                    "description": "Only ransomware",
                    "threat_actor_tags": ["ransomware"],
                    "asset_weight_rules": [],
                }
            ]
        )
        objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
        worker = ETLWorker(repo, pir)

        stats = worker.process_bundle(objects)

        # Sample actor has ["apt", "espionage", "targets-japan"] — no "ransomware"
        assert stats["threat_actors"] == 0


class TestBuildTtpVulnData:
    def test_basic(self):
        exploits = [{"ttp_stix_id": "ttp-1", "vuln_stix_id": "vuln-1"}]
        vulns = [{"stix_id": "vuln-1", "cvss_score": 9.8, "epss_score": 0.95}]

        result = _build_ttp_vuln_data(exploits, vulns)
        assert result["ttp-1"]["cvss_score"] == 9.8
        assert result["ttp-1"]["epss_score"] == 0.95

    def test_max_scores_multiple_vulns(self):
        exploits = [
            {"ttp_stix_id": "ttp-1", "vuln_stix_id": "vuln-1"},
            {"ttp_stix_id": "ttp-1", "vuln_stix_id": "vuln-2"},
        ]
        vulns = [
            {"stix_id": "vuln-1", "cvss_score": 7.0, "epss_score": 0.5},
            {"stix_id": "vuln-2", "cvss_score": 9.0, "epss_score": 0.3},
        ]

        result = _build_ttp_vuln_data(exploits, vulns)
        assert result["ttp-1"]["cvss_score"] == 9.0
        assert result["ttp-1"]["epss_score"] == 0.5

    def test_empty(self):
        result = _build_ttp_vuln_data([], [])
        assert result == {}
