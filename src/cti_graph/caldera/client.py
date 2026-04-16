"""MITRE Caldera REST API client.

Generates and synchronises Adversary profiles in MITRE Caldera
from threat actor TTP attack flows.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_ADVERSARY_ENDPOINT = "/api/v2/adversaries"
_ABILITY_ENDPOINT = "/api/v2/abilities"


def get_adversaries(caldera_url: str, api_key: str) -> list[dict[str, Any]]:
    """Return the list of Adversary profiles registered in Caldera."""
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                f"{caldera_url.rstrip('/')}{_ADVERSARY_ENDPOINT}",
                headers={"KEY": api_key},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.error("caldera_get_adversaries_failed", error=str(exc))
        return []


def create_adversary(
    caldera_url: str,
    api_key: str,
    name: str,
    description: str,
    atomic_ordering: list[str],
) -> dict[str, Any] | None:
    """Create a new Adversary profile in Caldera."""
    payload = {
        "name": name,
        "description": description,
        "atomic_ordering": atomic_ordering,
        "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc",
    }
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(
                f"{caldera_url.rstrip('/')}{_ADVERSARY_ENDPOINT}",
                json=payload,
                headers={"KEY": api_key},
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info("caldera_adversary_created", name=name, adversary_id=result.get("id"))
            return result
    except Exception as exc:
        logger.error("caldera_create_adversary_failed", name=name, error=str(exc))
        return None


def update_adversary(
    caldera_url: str,
    api_key: str,
    adversary_id: str,
    atomic_ordering: list[str],
) -> bool:
    """Update the Ability list of an existing Adversary profile."""
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.patch(
                f"{caldera_url.rstrip('/')}{_ADVERSARY_ENDPOINT}/{adversary_id}",
                json={"atomic_ordering": atomic_ordering},
                headers={"KEY": api_key},
            )
            resp.raise_for_status()
            logger.info("caldera_adversary_updated", adversary_id=adversary_id)
            return True
    except Exception as exc:
        logger.error("caldera_update_adversary_failed", adversary_id=adversary_id, error=str(exc))
        return False


def fetch_ability_map(caldera_url: str, api_key: str) -> dict[str, list[str]]:
    """Fetch Caldera abilities and build ATT&CK technique ID -> ability ID mapping.

    Returns {technique_id: [ability_id, ...]} where technique_id is e.g. "T1566.001".
    """
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{caldera_url.rstrip('/')}{_ABILITY_ENDPOINT}",
                headers={"KEY": api_key},
            )
            resp.raise_for_status()
            abilities = resp.json()
    except Exception as exc:
        logger.error("caldera_fetch_abilities_failed", error=str(exc))
        return {}

    mapping: dict[str, list[str]] = {}
    for ability in abilities:
        ability_id = ability.get("ability_id", "")
        technique_id = ability.get("technique_id", "")
        if ability_id and technique_id:
            mapping.setdefault(technique_id, []).append(ability_id)

    logger.info("caldera_ability_map_built", techniques=len(mapping), abilities=len(abilities))
    return mapping


def resolve_ability_ids(
    ttp_rows: list[dict[str, Any]],
    ability_map: dict[str, list[str]],
    repo: Any = None,
) -> list[str]:
    """Resolve TTP STIX IDs to Caldera Ability IDs via ATT&CK technique mapping.

    For each TTP in the attack flow, looks up the ATT&CK technique ID
    (from the TTP table via repo) and maps it to Caldera abilities.
    Falls back to the first available ability for each technique.

    Args:
        ttp_rows: TTP flow rows with src/dst_ttp_stix_id
        ability_map: {technique_id: [ability_id, ...]} from fetch_ability_map()
        repo: GraphRepository for TTP technique ID lookup (optional)

    Returns:
        Ordered list of Caldera Ability IDs
    """
    # Deduplicate TTP STIX IDs while preserving order
    seen: set[str] = set()
    ordered_ttps: list[str] = []
    for row in ttp_rows:
        for key in ("src_ttp_stix_id", "dst_ttp_stix_id"):
            stix_id = row.get(key, "")
            if stix_id and stix_id not in seen:
                seen.add(stix_id)
                ordered_ttps.append(stix_id)

    # Build stix_id -> technique_id lookup from DB
    ttp_technique_map: dict[str, str] = {}
    if repo is not None:
        for stix_id in ordered_ttps:
            rows = repo.query(
                "SELECT attack_technique_id FROM TTP WHERE stix_id = :stix_id",
                {"stix_id": stix_id},
            )
            if rows and rows[0].get("attack_technique_id"):
                ttp_technique_map[stix_id] = rows[0]["attack_technique_id"]

    # Resolve to ability IDs
    ability_ids: list[str] = []
    unresolved: list[str] = []
    for stix_id in ordered_ttps:
        technique_id = ttp_technique_map.get(stix_id, "")
        abilities = ability_map.get(technique_id, [])
        if abilities:
            ability_ids.append(abilities[0])  # first available ability
        else:
            unresolved.append(stix_id)

    if unresolved:
        logger.warning("caldera_unresolved_ttps", count=len(unresolved), stix_ids=unresolved[:5])

    return ability_ids


def sync_actor_ttps(
    caldera_url: str,
    api_key: str,
    actor_stix_id: str,
    ttp_rows: list[dict[str, Any]],
    repo: Any = None,
) -> dict[str, Any]:
    """Sync an actor's TTP flow as a Caldera Adversary profile.

    Resolves TTP STIX IDs to Caldera Ability IDs via the Ability API.
    Updates the profile if it already exists, creates a new one otherwise.

    Args:
        caldera_url: Caldera server URL
        api_key: REST API key
        actor_stix_id: ThreatActor STIX ID
        ttp_rows: Return value of get_actor_ttps() (src/dst TTP pairs)
        repo: GraphRepository for TTP technique ID lookup (optional)

    Returns:
        {"action": "created"|"updated"|"skipped", "adversary_id": ..., "ability_count": N}
    """
    # Fetch ability mapping from Caldera
    ability_map = fetch_ability_map(caldera_url, api_key)
    ability_ids = resolve_ability_ids(ttp_rows, ability_map, repo=repo)

    if not ability_ids:
        # Fallback: use TTP STIX IDs directly (placeholder for environments
        # where Caldera abilities are not yet configured)
        seen: set[str] = set()
        for row in ttp_rows:
            for key in ("src_ttp_stix_id", "dst_ttp_stix_id"):
                stix_id = row.get(key, "")
                if stix_id and stix_id not in seen:
                    seen.add(stix_id)
                    ability_ids.append(stix_id)
        logger.warning("caldera_fallback_stix_ids", count=len(ability_ids))

    profile_name = f"cti-graph-{actor_stix_id}"
    description = f"Auto-generated by cti-graph from {actor_stix_id}"

    existing = get_adversaries(caldera_url, api_key)
    for adv in existing:
        if adv.get("name") == profile_name:
            adv_id = adv["adversary_id"]
            updated = update_adversary(caldera_url, api_key, adv_id, ability_ids)
            return {
                "action": "updated" if updated else "skipped",
                "adversary_id": adv_id,
                "ability_count": len(ability_ids),
            }

    created = create_adversary(caldera_url, api_key, profile_name, description, ability_ids)
    if created:
        return {
            "action": "created",
            "adversary_id": created.get("adversary_id", ""),
            "ability_count": len(ability_ids),
        }

    return {"action": "skipped", "adversary_id": "", "ability_count": 0}
