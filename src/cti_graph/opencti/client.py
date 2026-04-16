"""OpenCTI STIX bundle fetch client.

Fetches STIX 2.1 bundles from an OpenCTI instance via the pycti library.
Falls back to direct REST API when pycti is not available.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


def fetch_stix_bundle(
    url: str,
    token: str,
    object_types: list[str] | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Fetch STIX objects from OpenCTI via GraphQL API.

    Args:
        url: OpenCTI API URL (e.g. https://opencti.internal)
        token: API token
        object_types: STIX types to fetch (None = all supported)
        limit: Maximum objects per type

    Returns:
        List of STIX 2.1 objects as plain dicts
    """
    if not url or not token:
        logger.warning("opencti_skip", reason="URL or token not configured")
        return []

    try:
        return _fetch_via_pycti(url, token, object_types, limit)
    except ImportError:
        logger.info("opencti_pycti_unavailable", fallback="rest_api")
        return _fetch_via_rest(url, token, limit)


def _fetch_via_pycti(
    url: str,
    token: str,
    object_types: list[str] | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Fetch STIX objects using pycti library."""
    from pycti import OpenCTIApiClient  # noqa: PLC0415

    client = OpenCTIApiClient(url, token)

    types = object_types or [
        "Threat-Actor-Individual",
        "Threat-Actor-Group",
        "Intrusion-Set",
        "Attack-Pattern",
        "Vulnerability",
        "Malware",
        "Tool",
        "Indicator",
        "Incident",
    ]

    all_objects: list[dict[str, Any]] = []

    for obj_type in types:
        try:
            bundle = client.stix2.export_list(entity_type=obj_type, first=limit)
            if bundle and "objects" in bundle:
                all_objects.extend(bundle["objects"])
        except Exception as exc:
            logger.warning("opencti_fetch_type_failed", type=obj_type, error=str(exc))

    logger.info("opencti_fetched", total=len(all_objects))
    return all_objects


def _fetch_via_rest(
    url: str,
    token: str,
    limit: int,
) -> list[dict[str, Any]]:
    """Fetch STIX objects using direct REST API (fallback)."""
    graphql_url = f"{url.rstrip('/')}/graphql"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    query = """
    query StixObjects($first: Int) {
      stixCoreObjects(first: $first) {
        edges {
          node {
            standard_id
            entity_type
            ... on StixObject {
              toStix
            }
          }
        }
      }
    }
    """

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                graphql_url,
                json={"query": query, "variables": {"first": limit}},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        edges = data.get("data", {}).get("stixCoreObjects", {}).get("edges", [])
        objects = []
        for edge in edges:
            stix = edge.get("node", {}).get("toStix")
            if stix:
                objects.append(stix)

        logger.info("opencti_rest_fetched", total=len(objects))
        return objects

    except Exception as exc:
        logger.error("opencti_rest_failed", error=str(exc))
        return []
