"""ETL worker — transforms STIX bundles and writes them to SQLite graph.

Processing flow:
  1. Classify STIX objects by type
  2. PIR filter (skip actors below relevance threshold)
  3. Node upsert (ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident)
  4. Edge upsert (Uses, MalwareUsesTTP, UsesTool, Exploits, Indicates*, IncidentUsesTTP)
  5. Derive FollowedBy(ir_feedback) from IncidentUsesTTP
  6. Generate Targets edges via PIR tag matching
  7. Update pir_adjusted_criticality
  8. Build TargetsAsset via TTP-Asset matcher
  9. Build PIR cascade edges (TAP, PTTP, PirWeightsAsset)
  10. Calculate FollowedBy(threat_intel) weights (4-factor)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from cti_graph.analysis.ttp_asset_matcher import build_ttp_asset_edges
from cti_graph.config import TLP_LEVELS
from cti_graph.db.repository import GraphRepository
from cti_graph.pir.filter import PIRFilter
from cti_graph.stix.mapper import (
    StixMapper,
    build_followed_by_weights,
    build_ir_feedback_followed_by,
)

logger = structlog.get_logger(__name__)


class ETLWorker:
    """Processes STIX objects and writes the results to the graph repository."""

    def __init__(
        self,
        repo: GraphRepository,
        pir_filter: PIRFilter,
        tlp_max_level: str = "amber",
    ) -> None:
        self._repo = repo
        self._pir = pir_filter
        self._tlp_max = TLP_LEVELS.get(tlp_max_level, 2)
        self._mapper = StixMapper()

    def process_bundle(
        self,
        objects: list[dict[str, Any]],
        asset_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, int]:
        """Process STIX objects and return ingestion counts.

        Args:
            objects: Result of stix/parser.py parse_bundle()
            asset_rows: Internal asset data for Targets edge generation.
                        Targets edges are skipped when omitted.
        """
        by_type: dict[str, list[dict]] = defaultdict(list)
        for obj in objects:
            by_type[obj["type"]].append(obj)

        stats: dict[str, int] = {}

        # --- ThreatActor (PIR-filtered) ---
        actor_rows = []
        for obj in by_type["threat-actor"] + by_type["intrusion-set"]:
            row = self._mapper.map_threat_actor(obj)
            if row and self._pir.is_relevant_actor(row):
                actor_rows.append(row)
        stats["threat_actors"] = self._repo.upsert_rows("ThreatActor", actor_rows)

        # --- TTP ---
        ttp_rows = [r for obj in by_type["attack-pattern"] if (r := self._mapper.map_ttp(obj))]
        stats["ttps"] = self._repo.upsert_rows("TTP", ttp_rows)
        ttp_phase_map = {r["stix_id"]: r["tactic"] or "" for r in ttp_rows}

        # --- Vulnerability ---
        vuln_rows = [r for obj in by_type["vulnerability"] if (r := self._mapper.map_vulnerability(obj))]
        stats["vulnerabilities"] = self._repo.upsert_rows("Vulnerability", vuln_rows)

        # --- MalwareTool ---
        mt_rows = [r for obj in by_type["malware"] + by_type["tool"] if (r := self._mapper.map_malware_tool(obj))]
        stats["malware_tools"] = self._repo.upsert_rows("MalwareTool", mt_rows)

        # --- Observable (TLP-filtered) ---
        obs_rows = []
        for obj in by_type["indicator"]:
            row = self._mapper.map_observable(obj)
            if row and self._passes_tlp(row.get("tlp", "white")):
                obs_rows.append(row)
        stats["observables"] = self._repo.upsert_rows("Observable", obs_rows)

        # --- Incident ---
        incident_rows = [r for obj in by_type["incident"] if (r := self._mapper.map_incident(obj))]
        stats["incidents"] = self._repo.upsert_rows("Incident", incident_rows)

        # --- Relationships ---
        uses_rows: list[dict] = []
        malware_uses_ttp_rows: list[dict] = []
        uses_tool_rows: list[dict] = []
        exploits_rows: list[dict] = []
        ind_ttp_rows: list[dict] = []
        ind_actor_rows: list[dict] = []
        incident_ttp_rows: list[dict] = []

        for obj in by_type["relationship"]:
            result = self._mapper.map_relationship(obj)
            if not result:
                continue
            table, row = result
            if table == "Uses":
                uses_rows.append(row)
            elif table == "MalwareUsesTTP":
                malware_uses_ttp_rows.append(row)
            elif table == "UsesTool":
                uses_tool_rows.append(row)
            elif table == "Exploits":
                exploits_rows.append(row)
            elif table == "IndicatesTTP":
                ind_ttp_rows.append(row)
            elif table == "IndicatesActor":
                ind_actor_rows.append(row)

        for obj in by_type["incident"]:
            incident_ttp_rows.extend(self._mapper.map_incident_ttp_edges(obj))

        # Filter edges referencing non-ingested entities (FK safety)
        ingested_actors = {r["stix_id"] for r in actor_rows}
        ingested_ttps = {r["stix_id"] for r in ttp_rows}
        ingested_vulns = {r["stix_id"] for r in vuln_rows}
        ingested_mt = {r["stix_id"] for r in mt_rows}
        ingested_obs = {r["stix_id"] for r in obs_rows}
        ingested_incidents = {r["stix_id"] for r in incident_rows}

        uses_rows = [
            r for r in uses_rows if r["actor_stix_id"] in ingested_actors and r["ttp_stix_id"] in ingested_ttps
        ]
        malware_uses_ttp_rows = [
            r
            for r in malware_uses_ttp_rows
            if r["malware_stix_id"] in ingested_mt and r["ttp_stix_id"] in ingested_ttps
        ]
        uses_tool_rows = [
            r for r in uses_tool_rows if r["actor_stix_id"] in ingested_actors and r["tool_stix_id"] in ingested_mt
        ]
        exploits_rows = [
            r for r in exploits_rows if r["ttp_stix_id"] in ingested_ttps and r["vuln_stix_id"] in ingested_vulns
        ]
        ind_ttp_rows = [
            r for r in ind_ttp_rows if r["observable_stix_id"] in ingested_obs and r["ttp_stix_id"] in ingested_ttps
        ]
        ind_actor_rows = [
            r
            for r in ind_actor_rows
            if r["observable_stix_id"] in ingested_obs and r["actor_stix_id"] in ingested_actors
        ]
        incident_ttp_rows = [
            r
            for r in incident_ttp_rows
            if r["incident_stix_id"] in ingested_incidents and r["ttp_stix_id"] in ingested_ttps
        ]

        stats["uses"] = self._repo.upsert_rows("Uses", uses_rows)
        stats["malware_uses_ttp"] = self._repo.upsert_rows("MalwareUsesTTP", malware_uses_ttp_rows)
        stats["uses_tool"] = self._repo.upsert_rows("UsesTool", uses_tool_rows)
        stats["exploits"] = self._repo.upsert_rows("Exploits", exploits_rows)
        stats["indicates_ttp"] = self._repo.upsert_rows("IndicatesTTP", ind_ttp_rows)
        stats["indicates_actor"] = self._repo.upsert_rows("IndicatesActor", ind_actor_rows)
        stats["incident_uses_ttp"] = self._repo.upsert_rows("IncidentUsesTTP", incident_ttp_rows)

        # --- FollowedBy(ir_feedback) ---
        ir_fb_rows, ir_feedback_pairs = build_ir_feedback_followed_by(incident_ttp_rows)
        stats["followed_by_ir"] = self._repo.upsert_rows("FollowedBy", ir_fb_rows)

        # --- Targets (PIR tag matching) ---
        targets_rows: list[dict] = []
        if asset_rows:
            targets_rows = self._pir.build_targets(actor_rows, asset_rows)
            stats["targets"] = self._repo.upsert_rows("Targets", targets_rows)

            updated_assets = self._pir.update_asset_criticality(asset_rows, actor_rows, targets_rows)
            stats["pir_criticality_updated"] = self._repo.upsert_rows("Asset", updated_assets)
        else:
            stats["targets"] = 0
            stats["pir_criticality_updated"] = 0

        # --- TargetsAsset (TTP -> Asset) ---
        if asset_rows:
            ttp_asset_rows = build_ttp_asset_edges(ttp_rows, asset_rows)
            stats["targets_asset"] = self._repo.upsert_rows("TargetsAsset", ttp_asset_rows)
        else:
            stats["targets_asset"] = 0

        # --- PIR cascade edges ---
        stats["pirs"] = self._repo.upsert_rows("PIR", self._pir.build_pir_nodes())
        pir_actor_edges = self._pir.build_pir_actor_edges(actor_rows)
        stats["pir_prioritizes_actor"] = self._repo.upsert_rows("PirPrioritizesActor", pir_actor_edges)
        stats["pir_prioritizes_ttp"] = self._repo.upsert_rows(
            "PirPrioritizesTTP", self._pir.build_pir_ttp_edges(uses_rows, pir_actor_edges)
        )
        if asset_rows:
            stats["pir_weights_asset"] = self._repo.upsert_rows(
                "PirWeightsAsset", self._pir.build_pir_asset_edges(asset_rows)
            )
        else:
            stats["pir_weights_asset"] = 0

        # --- FollowedBy(threat_intel): 4-factor weight ---
        ttp_vuln_data = _build_ttp_vuln_data(exploits_rows, vuln_rows)
        fb_rows = build_followed_by_weights(
            uses_rows,
            ttp_phase_map,
            ttp_vuln_data=ttp_vuln_data,
            ir_feedback_pairs=ir_feedback_pairs,
        )
        stats["followed_by"] = self._repo.upsert_rows("FollowedBy", fb_rows)

        logger.info("etl_complete", **stats)
        return stats

    def _passes_tlp(self, tlp: str) -> bool:
        return TLP_LEVELS.get(tlp, 0) <= self._tlp_max


def _build_ttp_vuln_data(
    exploits_rows: list[dict],
    vuln_rows: list[dict],
) -> dict[str, dict]:
    """Build TTP -> vulnerability data dict from Exploits edges and Vulnerability nodes.

    When multiple vulnerabilities link to the same TTP, maximum scores are used.
    """
    vuln_map = {r["stix_id"]: r for r in vuln_rows}
    result: dict[str, dict] = {}

    for edge in exploits_rows:
        ttp_id = edge["ttp_stix_id"]
        vuln = vuln_map.get(edge["vuln_stix_id"], {})
        cvss = vuln.get("cvss_score")
        epss = vuln.get("epss_score")

        existing = result.get(ttp_id, {})
        new_cvss = max(filter(None, [existing.get("cvss_score"), cvss]), default=None)
        new_epss = max(filter(None, [existing.get("epss_score"), epss]), default=None)
        result[ttp_id] = {"cvss_score": new_cvss, "epss_score": new_epss}

    return result
