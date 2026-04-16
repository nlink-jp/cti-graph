"""Tests for TTP-Asset matcher."""

from __future__ import annotations

from cti_graph.analysis.ttp_asset_matcher import TECHNIQUE_TAG_MAP, build_ttp_asset_edges


def _ttp(stix_id, tech_id):
    return {"stix_id": stix_id, "attack_technique_id": tech_id}


def _asset(asset_id, tags, asset_type=None):
    return {"id": asset_id, "tags": tags, "asset_type": asset_type}


class TestBuildTtpAssetEdges:
    def test_basic_match(self):
        ttps = [_ttp("ttp-1", "T1190")]  # external-facing
        assets = [_asset("asset-1", ["external-facing"])]

        edges = build_ttp_asset_edges(ttps, assets)
        assert len(edges) == 1
        assert edges[0]["ttp_stix_id"] == "ttp-1"
        assert edges[0]["asset_id"] == "asset-1"
        assert edges[0]["match_reason"] == "external-facing"

    def test_sub_technique_falls_through(self):
        ttps = [_ttp("ttp-1", "T1566.001")]  # sub-technique of T1566 -> endpoint, email
        assets = [_asset("asset-1", ["endpoint"])]

        edges = build_ttp_asset_edges(ttps, assets)
        assert len(edges) == 1
        assert edges[0]["match_reason"] == "endpoint"

    def test_asset_type_used_as_signal(self):
        ttps = [_ttp("ttp-1", "T1543")]  # server, endpoint
        assets = [_asset("asset-1", [], asset_type="server")]

        edges = build_ttp_asset_edges(ttps, assets)
        assert len(edges) == 1
        assert edges[0]["match_reason"] == "server"

    def test_no_match(self):
        ttps = [_ttp("ttp-1", "T1190")]  # external-facing
        assets = [_asset("asset-1", ["database"])]

        edges = build_ttp_asset_edges(ttps, assets)
        assert edges == []

    def test_unknown_technique(self):
        ttps = [_ttp("ttp-1", "T9999")]  # not in map
        assets = [_asset("asset-1", ["external-facing"])]

        edges = build_ttp_asset_edges(ttps, assets)
        assert edges == []

    def test_no_technique_id(self):
        ttps = [_ttp("ttp-1", None)]
        assets = [_asset("asset-1", ["external-facing"])]

        edges = build_ttp_asset_edges(ttps, assets)
        assert edges == []

    def test_multiple_assets_matched(self):
        ttps = [_ttp("ttp-1", "T1078")]  # identity, ad, sso
        assets = [
            _asset("asset-1", ["identity"]),
            _asset("asset-2", ["ad"]),
            _asset("asset-3", ["database"]),  # no match
        ]

        edges = build_ttp_asset_edges(ttps, assets)
        assert len(edges) == 2
        matched_assets = {e["asset_id"] for e in edges}
        assert matched_assets == {"asset-1", "asset-2"}

    def test_technique_tag_map_coverage(self):
        # Verify the map has reasonable coverage
        assert len(TECHNIQUE_TAG_MAP) >= 30
        assert "T1190" in TECHNIQUE_TAG_MAP
        assert "T1566" in TECHNIQUE_TAG_MAP
        assert "T1078" in TECHNIQUE_TAG_MAP
        assert "T1486" in TECHNIQUE_TAG_MAP
