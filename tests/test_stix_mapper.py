"""Tests for STIX mapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from cti_graph.stix.mapper import (
    StixMapper,
    build_followed_by_weights,
    build_ir_feedback_followed_by,
)
from cti_graph.stix.parser import classify_objects, load_bundle_from_file

FIXTURES = Path(__file__).parent / "fixtures"

# STIX IDs from sample_bundle.json (must be valid UUIDs for stix2 validation)
ACTOR_ID = "threat-actor--04f69fa3-0776-43ae-a37b-f37917028fb7"
TTP1_ID = "attack-pattern--15bd181c-f405-44bf-a8af-c77dd8538ccb"
TTP2_ID = "attack-pattern--0592a0fe-cb08-4448-96a5-733186a68637"
VULN_ID = "vulnerability--5ca55dce-7964-4100-bc5e-89c143cc144e"
MALWARE_ID = "malware--880bcbeb-5d80-4793-b34f-639c858a8c5e"
INDICATOR_ID = "indicator--54308dda-3c7d-409c-824c-b6b664511e4e"
REL_USES1_ID = "relationship--c504e532-33bc-44f0-bdc2-557160d1022b"
REL_USES2_ID = "relationship--d69bcef9-2472-40d8-934e-9bdb53d81976"
REL_EXPLOITS_ID = "relationship--bfbe6bde-a37a-41ca-aa8f-3062010c49d5"
REL_INDICATES_ID = "relationship--87af3d61-1259-4c7f-86bd-d581749158b8"


@pytest.fixture
def mapper():
    return StixMapper()


@pytest.fixture
def sample_objects():
    return load_bundle_from_file(FIXTURES / "sample_bundle.json")


@pytest.fixture
def by_type(sample_objects):
    return classify_objects(sample_objects)


# ------------------------------------------------------------------
# Node mappers
# ------------------------------------------------------------------


class TestMapThreatActor:
    def test_basic(self, mapper, by_type):
        actors = [mapper.map_threat_actor(o) for o in by_type["threat-actor"]]
        actors = [a for a in actors if a is not None]
        assert len(actors) == 1
        actor = actors[0]
        assert actor["name"] == "Test APT Group"
        assert actor["stix_type"] == "threat-actor"
        assert "TestGroup" in actor["aliases"]
        assert actor["sophistication"] == "advanced"
        assert actor["motivation"] == "espionage"
        assert "apt" in actor["tags"]

    def test_wrong_type(self, mapper):
        assert mapper.map_threat_actor({"type": "malware"}) is None


class TestMapTTP:
    def test_basic(self, mapper, by_type):
        ttps = [mapper.map_ttp(o) for o in by_type["attack-pattern"]]
        ttps = [t for t in ttps if t is not None]
        assert len(ttps) == 2

        phishing = next(t for t in ttps if "T1566" in (t["attack_technique_id"] or ""))
        assert phishing["name"] == "Spearphishing Attachment"
        assert phishing["tactic"] == "initial-access"
        assert "Windows" in phishing["platforms"]

    def test_technique_id_extraction(self, mapper, by_type):
        ttps = [mapper.map_ttp(o) for o in by_type.get("attack-pattern", [])]
        ttps = [t for t in ttps if t is not None]
        ids = {t["attack_technique_id"] for t in ttps}
        assert "T1566.001" in ids
        assert "T1059" in ids


class TestMapVulnerability:
    def test_basic(self, mapper, by_type):
        vulns = [mapper.map_vulnerability(o) for o in by_type["vulnerability"]]
        vulns = [v for v in vulns if v is not None]
        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln["cve_id"] == "CVE-2025-12345"
        assert vuln["cvss_score"] == 9.8


class TestMapMalwareTool:
    def test_basic(self, mapper, by_type):
        mts = [mapper.map_malware_tool(o) for o in by_type["malware"]]
        mts = [m for m in mts if m is not None]
        assert len(mts) == 1
        assert mts[0]["name"] == "TestRAT"
        assert mts[0]["stix_type"] == "malware"
        assert "remote-access" in mts[0]["capabilities"]


class TestMapObservable:
    def test_basic(self, mapper, by_type):
        indicators = by_type["indicator"]
        obs = [mapper.map_observable(o) for o in indicators]
        obs = [o for o in obs if o is not None]
        assert len(obs) == 2  # both indicators have extractable patterns

        ip_obs = next(o for o in obs if o["value"] == "192.0.2.1")
        assert ip_obs["obs_type"] == "ip"
        assert ip_obs["confidence"] == 85

    def test_unextractable_pattern(self, mapper):
        result = mapper.map_observable(
            {
                "type": "indicator",
                "pattern": "UNKNOWN_PATTERN",
                "modified": "2025-01-01T00:00:00Z",
            }
        )
        assert result is None


# ------------------------------------------------------------------
# Edge mappers
# ------------------------------------------------------------------


class TestMapRelationship:
    def test_uses_actor_ttp(self, mapper, by_type):
        rels = by_type["relationship"]
        uses_rel = next(r for r in rels if r["id"] == REL_USES1_ID)
        table, row = mapper.map_relationship(uses_rel)
        assert table == "Uses"
        assert row["actor_stix_id"] == ACTOR_ID
        assert row["ttp_stix_id"] == TTP1_ID
        assert row["confidence"] == 90

    def test_exploits(self, mapper, by_type):
        rels = by_type["relationship"]
        exploits_rel = next(r for r in rels if r["id"] == REL_EXPLOITS_ID)
        table, row = mapper.map_relationship(exploits_rel)
        assert table == "Exploits"
        assert row["ttp_stix_id"] == TTP1_ID
        assert row["vuln_stix_id"] == VULN_ID

    def test_indicates_actor(self, mapper, by_type):
        rels = by_type["relationship"]
        indicates_rel = next(r for r in rels if r["id"] == REL_INDICATES_ID)
        table, row = mapper.map_relationship(indicates_rel)
        assert table == "IndicatesActor"
        assert row["observable_stix_id"] == INDICATOR_ID
        assert row["confidence"] == 75

    def test_unknown_relationship(self, mapper):
        result = mapper.map_relationship(
            {
                "type": "relationship",
                "id": "relationship--unknown",
                "relationship_type": "derived-from",
                "source_ref": "identity--a",
                "target_ref": "identity--b",
            }
        )
        assert result is None


# ------------------------------------------------------------------
# FollowedBy weight calculation
# ------------------------------------------------------------------


class TestFollowedByWeights:
    def test_basic_weight_calculation(self):
        uses_rows = [
            {
                "actor_stix_id": "actor-1",
                "ttp_stix_id": "ttp-initial",
                "last_observed": None,
            },
            {
                "actor_stix_id": "actor-1",
                "ttp_stix_id": "ttp-exec",
                "last_observed": None,
            },
        ]
        phases = {
            "ttp-initial": "initial-access",
            "ttp-exec": "execution",
        }

        result = build_followed_by_weights(uses_rows, phases)
        assert len(result) == 1
        fb = result[0]
        assert fb["src_ttp_stix_id"] == "ttp-initial"
        assert fb["dst_ttp_stix_id"] == "ttp-exec"
        assert fb["source"] == "threat_intel"
        assert 0.0 < fb["weight"] <= 1.0

    def test_ir_multiplier(self):
        uses_rows = [
            {"actor_stix_id": "a1", "ttp_stix_id": "t1", "last_observed": None},
            {"actor_stix_id": "a1", "ttp_stix_id": "t2", "last_observed": None},
        ]
        phases = {"t1": "initial-access", "t2": "execution"}

        # Without IR feedback
        result_no_ir = build_followed_by_weights(uses_rows, phases)
        # With IR feedback
        result_with_ir = build_followed_by_weights(uses_rows, phases, ir_feedback_pairs={("t1", "t2")})

        w_no_ir = result_no_ir[0]["weight"]
        w_with_ir = result_with_ir[0]["weight"]
        assert w_with_ir >= w_no_ir

    def test_empty_uses(self):
        result = build_followed_by_weights([], {})
        assert result == []

    def test_evidence_capped_at_10(self):
        uses_rows = [{"actor_stix_id": f"a{i}", "ttp_stix_id": "t1", "last_observed": None} for i in range(15)] + [
            {"actor_stix_id": f"a{i}", "ttp_stix_id": "t2", "last_observed": None} for i in range(15)
        ]
        phases = {"t1": "initial-access", "t2": "execution"}

        result = build_followed_by_weights(uses_rows, phases)
        for fb in result:
            assert len(fb["evidence_stix_ids"]) <= 10


class TestIRFeedbackFollowedBy:
    def test_basic(self):
        incident_rows = [
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t1", "sequence_order": 0},
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t2", "sequence_order": 1},
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t3", "sequence_order": 2},
        ]
        rows, pairs = build_ir_feedback_followed_by(incident_rows)
        assert len(rows) == 2
        assert ("t1", "t2") in pairs
        assert ("t2", "t3") in pairs

    def test_skips_null_order(self):
        incident_rows = [
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t1", "sequence_order": 0},
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t2", "sequence_order": None},
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t3", "sequence_order": 1},
        ]
        rows, pairs = build_ir_feedback_followed_by(incident_rows)
        assert len(rows) == 1
        assert ("t1", "t3") in pairs

    def test_empty_input(self):
        rows, pairs = build_ir_feedback_followed_by([])
        assert rows == []
        assert pairs == set()

    def test_multiple_incidents(self):
        incident_rows = [
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t1", "sequence_order": 0},
            {"incident_stix_id": "inc-1", "ttp_stix_id": "t2", "sequence_order": 1},
            {"incident_stix_id": "inc-2", "ttp_stix_id": "t1", "sequence_order": 0},
            {"incident_stix_id": "inc-2", "ttp_stix_id": "t2", "sequence_order": 1},
        ]
        rows, pairs = build_ir_feedback_followed_by(incident_rows)
        assert len(rows) == 1  # same transition from two incidents
        fb = rows[0]
        assert fb["weight"] == 1.0  # 2/2 incidents
        assert fb["source"] == "ir_feedback"
