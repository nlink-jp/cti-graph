"""IR Feedback — similar incident search.

Computes a hybrid similarity score to rank incidents.

  hybrid_score = alpha x jaccard_ttp + (1 - alpha) x transition_coverage

- jaccard_ttp: Jaccard similarity of two TTP sets
- transition_coverage: fraction of reference TTPs reachable from query
  TTPs within max_hops on the FollowedBy graph
"""

from __future__ import annotations

from collections import deque
from typing import Any

import structlog

from cti_graph.db.repository import GraphRepository

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Graph construction utilities
# ---------------------------------------------------------------------------


def build_followedby_graph(
    followedby_rows: list[dict[str, Any]],
) -> dict[str, set[str]]:
    """Build a directed graph from FollowedBy edges.

    Returns {src_stix_id: {dst_stix_id, ...}}.
    """
    graph: dict[str, set[str]] = {}
    for row in followedby_rows:
        src = row["src_ttp_stix_id"]
        dst = row["dst_ttp_stix_id"]
        graph.setdefault(src, set()).add(dst)
    return graph


def bfs_reachable(
    graph: dict[str, set[str]],
    start_nodes: set[str],
    max_hops: int,
) -> set[str]:
    """Return all nodes reachable from start_nodes within max_hops via BFS."""
    visited: set[str] = set(start_nodes)
    frontier: deque[tuple[str, int]] = deque((n, 0) for n in start_nodes)

    while frontier:
        node, depth = frontier.popleft()
        if depth >= max_hops:
            continue
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                frontier.append((neighbor, depth + 1))

    return visited


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------


def jaccard_ttp(set_a: set[str], set_b: set[str]) -> float:
    """Return the Jaccard similarity of two TTP sets."""
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def transition_coverage(
    incident_ttps: set[str],
    ref_ttps: set[str],
    followedby_graph: dict[str, set[str]],
    max_hops: int = 2,
) -> float:
    """Return the fraction of ref_ttps reachable from incident_ttps."""
    if not ref_ttps:
        return 1.0
    reachable = bfs_reachable(followedby_graph, incident_ttps, max_hops)
    covered = len(ref_ttps & reachable)
    return covered / len(ref_ttps)


def hybrid_score(
    incident_ttps: set[str],
    ref_ttps: set[str],
    followedby_graph: dict[str, set[str]],
    alpha: float = 0.5,
    max_hops: int = 2,
) -> float:
    """Compute hybrid similarity score.

    hybrid_score = alpha x jaccard_ttp + (1 - alpha) x transition_coverage
    """
    j = jaccard_ttp(incident_ttps, ref_ttps)
    t = transition_coverage(incident_ttps, ref_ttps, followedby_graph, max_hops)
    return alpha * j + (1.0 - alpha) * t


# ---------------------------------------------------------------------------
# Repository integration
# ---------------------------------------------------------------------------


def find_similar_incidents(
    repo: GraphRepository,
    incident_id: str,
    top_k: int = 5,
    alpha: float = 0.5,
    max_hops: int = 2,
) -> list[dict[str, Any]]:
    """Return incidents most similar to the specified incident, ordered by score."""
    # Get query incident's TTPs
    query_rows = repo.query(
        "SELECT ttp_stix_id FROM IncidentUsesTTP WHERE incident_stix_id = :incident_id",
        {"incident_id": incident_id},
    )
    query_ttps = {r["ttp_stix_id"] for r in query_rows}
    if not query_ttps:
        logger.warning("find_similar_incidents_empty", incident_id=incident_id)
        return []

    # Build FollowedBy graph
    fb_rows = repo.fetch_all("FollowedBy")
    graph = build_followedby_graph(fb_rows)

    # Get all incidents and their TTPs
    all_rows = repo.query("SELECT incident_stix_id, ttp_stix_id FROM IncidentUsesTTP")
    incident_ttps_map: dict[str, set[str]] = {}
    for r in all_rows:
        incident_ttps_map.setdefault(r["incident_stix_id"], set()).add(r["ttp_stix_id"])

    results = []
    for ref_id, ref_ttps in incident_ttps_map.items():
        if ref_id == incident_id:
            continue
        j = jaccard_ttp(query_ttps, ref_ttps)
        t = transition_coverage(query_ttps, ref_ttps, graph, max_hops)
        score = alpha * j + (1.0 - alpha) * t
        results.append(
            {
                "incident_id": ref_id,
                "hybrid_score": round(score, 4),
                "jaccard_ttp": round(j, 4),
                "transition_coverage": round(t, 4),
                "shared_ttps": sorted(query_ttps & ref_ttps),
            }
        )

    results.sort(key=lambda x: x["hybrid_score"], reverse=True)
    return results[:top_k]
