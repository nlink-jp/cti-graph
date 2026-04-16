"""PIR (Priority Intelligence Requirement) filtering and asset weighting.

Responsibilities:
1. Filter incoming STIX actors by PIR tag relevance.
2. Generate Targets edges from PIR tag matching.
3. Update Asset.pir_adjusted_criticality based on matching PIR rules.
4. Build PIR cascade edges (TAP, PTTP, PirWeightsAsset).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class PIRFilter:
    """Filter and weight objects according to PIR JSON definitions."""

    def __init__(self, pir_list: list[dict[str, Any]]) -> None:
        self._pirs = pir_list

    @classmethod
    def from_file(cls, path: Path) -> PIRFilter:
        with path.open() as f:
            data = json.load(f)
        pirs = data if isinstance(data, list) else [data]
        for pir in pirs:
            logger.info("pir_loaded", pir_id=pir.get("pir_id"))
        return cls(pirs)

    @classmethod
    def empty(cls) -> PIRFilter:
        """Create a PIRFilter with no PIRs (accepts all actors)."""
        return cls([])

    # ------------------------------------------------------------------
    # ThreatActor filtering
    # ------------------------------------------------------------------

    def is_relevant_actor(self, actor_row: dict) -> bool:
        """Return True if the actor matches any PIR's threat_actor_tags.

        Returns True for all actors when no PIRs are loaded.
        """
        if not self._pirs:
            return True

        actor_tags: set[str] = set(actor_row.get("tags") or [])
        actor_name: str = (actor_row.get("name") or "").lower()

        for pir in self._pirs:
            pir_tags: set[str] = set(pir.get("threat_actor_tags", []))
            if pir_tags & actor_tags:
                return True
            if any(t.lower() in actor_name for t in pir_tags):
                return True

        return False

    # ------------------------------------------------------------------
    # Asset weighting
    # ------------------------------------------------------------------

    def update_asset_criticality(
        self,
        asset_rows: list[dict],
        actor_rows: list[dict],
        targets_rows: list[dict],
    ) -> list[dict]:
        """Compute pir_adjusted_criticality taking Targets edges into account.

        Formula:
          pir_adjusted_criticality =
            base_criticality
            x MAX(matching PIR rules' criticality_multiplier)
            x (1.5 if any Targets-linked actor matches a PIR, else 1.0)
            capped at 10.0
        """
        actor_map = {a["stix_id"]: a for a in actor_rows}

        asset_to_actors: dict[str, set[str]] = defaultdict(set)
        for t in targets_rows:
            asset_to_actors[t["asset_id"]].add(t["actor_stix_id"])

        result = []
        for asset in asset_rows:
            base = asset.get("criticality", 5.0) or 5.0
            asset_tags: set[str] = set(asset.get("tags") or [])

            max_multiplier = 1.0
            has_pir_actor_target = False

            for pir in self._pirs:
                pir_actor_tags: set[str] = set(pir.get("threat_actor_tags", []))

                for rule in pir.get("asset_weight_rules", []):
                    if rule["tag"] in asset_tags:
                        max_multiplier = max(max_multiplier, rule["criticality_multiplier"])

                for actor_id in asset_to_actors.get(asset["id"], set()):
                    actor = actor_map.get(actor_id)
                    if actor and set(actor.get("tags") or []) & pir_actor_tags:
                        has_pir_actor_target = True

            targets_multiplier = 1.5 if has_pir_actor_target else 1.0
            adjusted = min(base * max_multiplier * targets_multiplier, 10.0)
            result.append({**asset, "pir_adjusted_criticality": adjusted})

        return result

    # ------------------------------------------------------------------
    # Targets edge generation
    # ------------------------------------------------------------------

    def build_targets(
        self,
        actor_rows: list[dict],
        asset_rows: list[dict],
    ) -> list[dict]:
        """Generate Targets edges from PIR tag matching.

        For each PIR, matched actors x matched assets produce edges.
        Confidence = actor-PIR tag overlap ratio (0-100).
        Highest confidence kept for duplicate (actor, asset) pairs.
        """
        targets: dict[tuple[str, str], dict] = {}

        for pir in self._pirs:
            pir_actor_tags: set[str] = set(pir.get("threat_actor_tags", []))
            pir_asset_tags: set[str] = {rule["tag"] for rule in pir.get("asset_weight_rules", [])}
            if not pir_actor_tags or not pir_asset_tags:
                continue

            matched_actors = [a for a in actor_rows if set(a.get("tags") or []) & pir_actor_tags]
            matched_assets = [a for a in asset_rows if set(a.get("tags") or []) & pir_asset_tags]

            for actor in matched_actors:
                actor_overlap = len(set(actor.get("tags") or []) & pir_actor_tags)
                confidence = min(int(actor_overlap / len(pir_actor_tags) * 100), 100)
                for asset in matched_assets:
                    key = (actor["stix_id"], asset["id"])
                    if key not in targets or targets[key]["confidence"] < confidence:
                        targets[key] = {
                            "actor_stix_id": actor["stix_id"],
                            "asset_id": asset["id"],
                            "confidence": confidence,
                            "source": "pir_auto",
                        }

        return list(targets.values())

    # ------------------------------------------------------------------
    # PIR as first-class graph node — row builders for upsert
    # ------------------------------------------------------------------

    def build_pir_nodes(self) -> list[dict]:
        """Return one PIR row per loaded PIR."""
        rows: list[dict] = []
        for pir in self._pirs:
            rows.append(
                {
                    "pir_id": pir["pir_id"],
                    "intelligence_level": pir.get("intelligence_level", "operational"),
                    "organizational_scope": pir.get("organizational_scope"),
                    "decision_point": pir.get("decision_point"),
                    "description": pir.get("description", ""),
                    "rationale": pir.get("rationale"),
                    "recommended_action": pir.get("recommended_action"),
                    "threat_actor_tags": list(pir.get("threat_actor_tags", [])),
                    "risk_composite": (pir.get("risk_score") or {}).get("composite"),
                    "valid_from": pir.get("valid_from"),
                    "valid_until": pir.get("valid_until"),
                }
            )
        return rows

    def build_pir_actor_edges(self, actor_rows: list[dict]) -> list[dict]:
        """PIR -> ThreatActor edges (TAP layer)."""
        edges: list[dict] = []
        for pir in self._pirs:
            pir_tags = set(pir.get("threat_actor_tags", []))
            if not pir_tags:
                continue
            for actor in actor_rows:
                actor_tags = set(actor.get("tags") or [])
                overlap = pir_tags & actor_tags
                if not overlap:
                    continue
                edges.append(
                    {
                        "pir_id": pir["pir_id"],
                        "actor_stix_id": actor["stix_id"],
                        "overlap_ratio": round(len(overlap) / len(pir_tags), 4),
                    }
                )
        return edges

    def build_pir_ttp_edges(
        self,
        uses_rows: list[dict],
        pir_actor_edges: list[dict],
    ) -> list[dict]:
        """PIR -> TTP edges (PTTP layer), derived transitively via Uses."""
        pir_to_actors: dict[str, set[str]] = defaultdict(set)
        for edge in pir_actor_edges:
            pir_to_actors[edge["pir_id"]].add(edge["actor_stix_id"])

        actor_to_ttps: dict[str, set[str]] = defaultdict(set)
        for u in uses_rows:
            actor_to_ttps[u["actor_stix_id"]].add(u["ttp_stix_id"])

        seen: set[tuple[str, str]] = set()
        edges: list[dict] = []
        for pir_id, actor_ids in pir_to_actors.items():
            for actor_id in actor_ids:
                for ttp_id in actor_to_ttps.get(actor_id, set()):
                    key = (pir_id, ttp_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({"pir_id": pir_id, "ttp_stix_id": ttp_id})
        return edges

    def build_pir_asset_edges(self, asset_rows: list[dict]) -> list[dict]:
        """PIR -> Asset edges with highest criticality_multiplier."""
        best: dict[tuple[str, str], dict] = {}
        for pir in self._pirs:
            rules = pir.get("asset_weight_rules", [])
            if not rules:
                continue
            for asset in asset_rows:
                asset_tags = set(asset.get("tags") or [])
                best_match: tuple[float, str] | None = None
                for rule in rules:
                    tag = rule.get("tag")
                    if tag in asset_tags:
                        mult = float(rule.get("criticality_multiplier", 1.0))
                        if best_match is None or mult > best_match[0]:
                            best_match = (mult, tag)
                if best_match is None:
                    continue
                key = (pir["pir_id"], asset["id"])
                mult, tag = best_match
                existing = best.get(key)
                if existing is None or (existing["criticality_multiplier"] or 0) < mult:
                    best[key] = {
                        "pir_id": pir["pir_id"],
                        "asset_id": asset["id"],
                        "matched_tag": tag,
                        "criticality_multiplier": mult,
                    }
        return list(best.values())
