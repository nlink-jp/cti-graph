"""STIX 2.1 bundle parsing and pre-processing.

Loads STIX bundles from JSON files, validates with the stix2 library,
and applies TLP filtering before passing to the mapper.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import stix2
import structlog

from cti_graph.config import TLP_LEVELS

logger = structlog.get_logger(__name__)

# Object types processed by the ETL pipeline
SUPPORTED_TYPES = frozenset(
    {
        "threat-actor",
        "intrusion-set",
        "attack-pattern",
        "vulnerability",
        "malware",
        "tool",
        "indicator",
        "relationship",
        "incident",
    }
)


def parse_bundle(bundle_dict: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a STIX 2.1 bundle and return supported objects as plain dicts.

    Objects that fail stix2 validation are skipped with a warning.
    """
    raw_objects = bundle_dict.get("objects", [])
    result: list[dict[str, Any]] = []

    for raw in raw_objects:
        obj_type = raw.get("type", "")
        obj_id = raw.get("id", "unknown")

        if obj_type not in SUPPORTED_TYPES:
            continue

        try:
            parsed = _parse_object(raw)
            result.append(parsed)
        except Exception as exc:
            logger.warning("parse_failed", stix_id=obj_id, error=str(exc))

    logger.info("parsed", total=len(raw_objects), accepted=len(result))
    return result


def load_bundle_from_file(path: Path) -> list[dict[str, Any]]:
    """Load and parse a STIX bundle from a JSON file."""
    with path.open() as f:
        bundle = json.load(f)
    return parse_bundle(bundle)


def load_bundles_from_dir(
    directory: Path,
    tlp_max: str = "amber",
) -> list[dict[str, Any]]:
    """Load all STIX bundles from a directory, applying TLP filtering.

    Only processes .json files. Subdirectories are not traversed.
    """
    max_level = TLP_LEVELS.get(tlp_max, 2)
    all_objects: list[dict[str, Any]] = []

    for path in sorted(directory.glob("*.json")):
        try:
            objects = load_bundle_from_file(path)
            all_objects.extend(objects)
        except Exception as exc:
            logger.warning("load_failed", path=str(path), error=str(exc))

    # Apply TLP filtering to indicator objects
    filtered = []
    for obj in all_objects:
        if obj.get("type") == "indicator":
            tlp = _extract_tlp(obj)
            if TLP_LEVELS.get(tlp, 0) > max_level:
                continue
        filtered.append(obj)

    logger.info(
        "loaded_dir",
        directory=str(directory),
        total=len(all_objects),
        after_tlp_filter=len(filtered),
    )
    return filtered


def classify_objects(
    objects: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Classify STIX objects by type for ETL processing."""
    by_type: dict[str, list[dict[str, Any]]] = {}
    for obj in objects:
        obj_type = obj.get("type", "")
        by_type.setdefault(obj_type, []).append(obj)
    return by_type


def _parse_object(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate via stix2 library and return as plain dict."""
    parsed = stix2.parse(json.dumps(raw), allow_custom=True)
    return json.loads(parsed.serialize())


# Well-known STIX 2.1 TLP marking definition IDs
_TLP_MARKING_IDS: dict[str, str] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}


def _extract_tlp(obj: dict[str, Any]) -> str:
    """Extract TLP level from object_marking_refs."""
    for ref in obj.get("object_marking_refs", []):
        level = _TLP_MARKING_IDS.get(ref)
        if level:
            return level
        # Fallback: substring match for non-standard marking definitions
        ref_lower = ref.lower()
        for lvl in ("red", "amber", "green", "white"):
            if lvl in ref_lower:
                return lvl
    return "white"
