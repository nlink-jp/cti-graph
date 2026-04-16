"""Tests for PIR filter."""

from __future__ import annotations

import json

from cti_graph.pir.filter import PIRFilter

SAMPLE_PIR = {
    "pir_id": "PIR-2025-001",
    "intelligence_level": "strategic",
    "organizational_scope": "Security Team",
    "description": "Ransomware defense",
    "threat_actor_tags": ["ransomware", "financially-motivated"],
    "asset_weight_rules": [
        {"tag": "external-facing", "criticality_multiplier": 2.0},
        {"tag": "backup", "criticality_multiplier": 1.5},
    ],
    "risk_score": {"likelihood": 5, "impact": 5, "composite": 25},
    "valid_from": "2025-01-01",
    "valid_until": "2025-12-31",
}

SAMPLE_PIR_2 = {
    "pir_id": "PIR-2025-002",
    "intelligence_level": "operational",
    "description": "APT espionage",
    "threat_actor_tags": ["apt", "espionage"],
    "asset_weight_rules": [
        {"tag": "database", "criticality_multiplier": 1.8},
    ],
}


def _actor(stix_id, name, tags):
    return {"stix_id": stix_id, "name": name, "tags": tags}


def _asset(asset_id, name, tags, criticality=5.0):
    return {"id": asset_id, "name": name, "tags": tags, "criticality": criticality}


class TestIsRelevantActor:
    def test_no_pirs_accepts_all(self):
        pf = PIRFilter.empty()
        assert pf.is_relevant_actor(_actor("a1", "Any Actor", [])) is True

    def test_matching_tags(self):
        pf = PIRFilter([SAMPLE_PIR])
        assert pf.is_relevant_actor(_actor("a1", "LockBit", ["ransomware"])) is True

    def test_non_matching_tags(self):
        pf = PIRFilter([SAMPLE_PIR])
        assert pf.is_relevant_actor(_actor("a1", "SomeActor", ["apt", "espionage"])) is False

    def test_name_substring_fallback(self):
        pf = PIRFilter([SAMPLE_PIR])
        assert pf.is_relevant_actor(_actor("a1", "Ransomware Group X", [])) is True

    def test_multiple_pirs(self):
        pf = PIRFilter([SAMPLE_PIR, SAMPLE_PIR_2])
        assert pf.is_relevant_actor(_actor("a1", "APT29", ["apt"])) is True
        assert pf.is_relevant_actor(_actor("a2", "LockBit", ["ransomware"])) is True
        assert pf.is_relevant_actor(_actor("a3", "Unknown", ["hacktivism"])) is False


class TestBuildTargets:
    def test_generates_targets(self):
        pf = PIRFilter([SAMPLE_PIR])
        actors = [_actor("a1", "LockBit", ["ransomware", "financially-motivated"])]
        assets = [_asset("asset-1", "WebServer", ["external-facing"])]

        targets = pf.build_targets(actors, assets)
        assert len(targets) == 1
        t = targets[0]
        assert t["actor_stix_id"] == "a1"
        assert t["asset_id"] == "asset-1"
        assert t["confidence"] == 100  # 2/2 tags matched
        assert t["source"] == "pir_auto"

    def test_partial_tag_overlap(self):
        pf = PIRFilter([SAMPLE_PIR])
        actors = [_actor("a1", "LockBit", ["ransomware"])]  # 1 of 2 tags
        assets = [_asset("asset-1", "WebServer", ["external-facing"])]

        targets = pf.build_targets(actors, assets)
        assert len(targets) == 1
        assert targets[0]["confidence"] == 50

    def test_no_match(self):
        pf = PIRFilter([SAMPLE_PIR])
        actors = [_actor("a1", "APT", ["apt"])]
        assets = [_asset("asset-1", "DB", ["database"])]
        assert pf.build_targets(actors, assets) == []

    def test_highest_confidence_kept(self):
        pf = PIRFilter([SAMPLE_PIR, SAMPLE_PIR_2])
        actors = [_actor("a1", "Multi", ["ransomware", "apt"])]
        assets = [_asset("asset-1", "WebServer", ["external-facing", "database"])]

        targets = pf.build_targets(actors, assets)
        assert len(targets) == 1
        # PIR-2 gives 50% overlap (1/2 tags for apt), PIR-1 gives 50% (1/2 for ransomware)
        # Both give confidence=50, but only one edge per (actor, asset)
        assert targets[0]["confidence"] == 50


class TestUpdateAssetCriticality:
    def test_basic_multiplier(self):
        pf = PIRFilter([SAMPLE_PIR])
        assets = [_asset("asset-1", "WebServer", ["external-facing"], 5.0)]
        actors = []
        targets = []

        result = pf.update_asset_criticality(assets, actors, targets)
        assert result[0]["pir_adjusted_criticality"] == 10.0  # 5.0 * 2.0

    def test_actor_boost(self):
        pf = PIRFilter([SAMPLE_PIR])
        assets = [_asset("asset-1", "Backup", ["backup"], 4.0)]
        actors = [_actor("a1", "LockBit", ["ransomware"])]
        targets = [{"actor_stix_id": "a1", "asset_id": "asset-1"}]

        result = pf.update_asset_criticality(assets, actors, targets)
        # 4.0 * 1.5 (backup rule) * 1.5 (actor boost) = 9.0
        assert result[0]["pir_adjusted_criticality"] == 9.0

    def test_capped_at_10(self):
        pf = PIRFilter([SAMPLE_PIR])
        assets = [_asset("asset-1", "Web", ["external-facing"], 8.0)]
        actors = [_actor("a1", "LockBit", ["ransomware"])]
        targets = [{"actor_stix_id": "a1", "asset_id": "asset-1"}]

        result = pf.update_asset_criticality(assets, actors, targets)
        # 8.0 * 2.0 * 1.5 = 24.0 -> capped at 10.0
        assert result[0]["pir_adjusted_criticality"] == 10.0

    def test_no_pir_default(self):
        pf = PIRFilter.empty()
        assets = [_asset("asset-1", "Server", ["server"], 5.0)]

        result = pf.update_asset_criticality(assets, [], [])
        # No PIRs → multiplier=1.0, no boost → 5.0 * 1.0 * 1.0
        assert result[0]["pir_adjusted_criticality"] == 5.0


class TestPIRCascadeEdges:
    def test_pir_nodes(self):
        pf = PIRFilter([SAMPLE_PIR])
        nodes = pf.build_pir_nodes()
        assert len(nodes) == 1
        assert nodes[0]["pir_id"] == "PIR-2025-001"
        assert nodes[0]["intelligence_level"] == "strategic"
        assert nodes[0]["threat_actor_tags"] == ["ransomware", "financially-motivated"]
        assert nodes[0]["risk_composite"] == 25

    def test_pir_actor_edges(self):
        pf = PIRFilter([SAMPLE_PIR])
        actors = [_actor("a1", "LockBit", ["ransomware", "financially-motivated"])]

        edges = pf.build_pir_actor_edges(actors)
        assert len(edges) == 1
        assert edges[0]["overlap_ratio"] == 1.0

    def test_pir_ttp_edges(self):
        pf = PIRFilter([SAMPLE_PIR])
        pir_actor_edges = [{"pir_id": "PIR-2025-001", "actor_stix_id": "a1"}]
        uses_rows = [
            {"actor_stix_id": "a1", "ttp_stix_id": "ttp-1"},
            {"actor_stix_id": "a1", "ttp_stix_id": "ttp-2"},
        ]

        edges = pf.build_pir_ttp_edges(uses_rows, pir_actor_edges)
        assert len(edges) == 2
        ttp_ids = {e["ttp_stix_id"] for e in edges}
        assert ttp_ids == {"ttp-1", "ttp-2"}

    def test_pir_asset_edges(self):
        pf = PIRFilter([SAMPLE_PIR])
        assets = [_asset("asset-1", "WebServer", ["external-facing", "backup"])]

        edges = pf.build_pir_asset_edges(assets)
        assert len(edges) == 1
        # external-facing has higher multiplier (2.0 > 1.5)
        assert edges[0]["criticality_multiplier"] == 2.0
        assert edges[0]["matched_tag"] == "external-facing"


class TestFromFile:
    def test_load_single(self, tmp_path):
        path = tmp_path / "pir.json"
        path.write_text(json.dumps(SAMPLE_PIR))
        pf = PIRFilter.from_file(path)
        assert len(pf._pirs) == 1

    def test_load_list(self, tmp_path):
        path = tmp_path / "pirs.json"
        path.write_text(json.dumps([SAMPLE_PIR, SAMPLE_PIR_2]))
        pf = PIRFilter.from_file(path)
        assert len(pf._pirs) == 2
