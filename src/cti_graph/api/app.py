"""FastAPI Analysis API for cti-graph.

Exposes SQLite graph query results as a REST API.

Authentication:
  Set CTI_GRAPH_API_TOKEN to require a Bearer token on every request.
  When unset, no auth is enforced.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request

from cti_graph.analysis.similarity import find_similar_incidents
from cti_graph.config import Config, load_config
from cti_graph.db.repository import SQLiteRepository

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    config: Config = app.state.config
    repo = SQLiteRepository(config.db_path)
    repo.init_schema()
    app.state.repo = repo
    if not config.api_auth_token:
        logger.warning("api_auth_disabled", reason="CTI_GRAPH_API_TOKEN not set")
    logger.info("api_started", db_path=str(config.db_path))
    yield
    repo.close()
    logger.info("api_stopped")


def create_app(config: Config | None = None) -> FastAPI:
    """Create a FastAPI application with the given config."""
    application = FastAPI(title="cti-graph Analysis API", version="0.1.0", lifespan=lifespan)
    application.state.config = config or load_config()

    application.add_api_route("/attack-paths", get_attack_paths, dependencies=[Depends(_verify_auth)])
    application.add_api_route("/choke-points", get_choke_points, dependencies=[Depends(_verify_auth)])
    application.add_api_route("/actor-ttps", get_actor_ttps, dependencies=[Depends(_verify_auth)])
    application.add_api_route("/asset-exposure", get_asset_exposure, dependencies=[Depends(_verify_auth)])
    application.add_api_route("/similar-incidents", get_similar_incidents, dependencies=[Depends(_verify_auth)])

    return application


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def _verify_auth(request: Request) -> None:
    """Verify Bearer token if CTI_GRAPH_API_TOKEN is configured."""
    config: Config = request.app.state.config
    if not config.api_auth_token:
        return
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header[7:]
    if not secrets.compare_digest(token, config.api_auth_token):
        raise HTTPException(status_code=403, detail="Invalid API token")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def get_attack_paths(
    request: Request,
    asset_id: str = Query(..., description="Asset ID"),
    limit: int = Query(10, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Return attack paths reaching the specified asset, ordered by confidence."""
    repo: SQLiteRepository = request.app.state.repo
    return repo.query(
        """
        SELECT
            t.actor_stix_id,
            ta.name AS actor_name,
            u.ttp_stix_id,
            ttp.name AS ttp_name,
            u.confidence
        FROM Targets t
        JOIN ThreatActor ta ON ta.stix_id = t.actor_stix_id
        JOIN Uses u ON u.actor_stix_id = t.actor_stix_id
        JOIN TTP ttp ON ttp.stix_id = u.ttp_stix_id
        WHERE t.asset_id = :asset_id
        ORDER BY u.confidence DESC
        LIMIT :limit
        """,
        {"asset_id": asset_id, "limit": limit},
    )


def get_choke_points(
    request: Request,
    top_n: int = Query(20, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Return choke-point assets ordered by score descending."""
    repo: SQLiteRepository = request.app.state.repo
    return repo.query(
        """
        SELECT
            a.id AS asset_id,
            a.name AS asset_name,
            a.pir_adjusted_criticality,
            COUNT(DISTINCT t.actor_stix_id) AS targeting_actor_count,
            COALESCE(a.pir_adjusted_criticality, a.criticality)
                * COUNT(DISTINCT t.actor_stix_id) AS choke_score
        FROM Asset a
        JOIN Targets t ON t.asset_id = a.id
        GROUP BY a.id, a.name, a.pir_adjusted_criticality, a.criticality
        ORDER BY choke_score DESC
        LIMIT :top_n
        """,
        {"top_n": top_n},
    )


def get_actor_ttps(
    request: Request,
    actor_id: str = Query(..., description="ThreatActor STIX ID"),
) -> list[dict[str, Any]]:
    """Return the TTP attack flow for the specified actor."""
    repo: SQLiteRepository = request.app.state.repo
    return repo.query(
        """
        SELECT
            fb.src_ttp_stix_id,
            src.name AS src_ttp_name,
            fb.dst_ttp_stix_id,
            dst.name AS dst_ttp_name,
            fb.weight,
            fb.source
        FROM Uses u
        JOIN FollowedBy fb ON fb.src_ttp_stix_id = u.ttp_stix_id
        JOIN TTP src ON src.stix_id = fb.src_ttp_stix_id
        JOIN TTP dst ON dst.stix_id = fb.dst_ttp_stix_id
        WHERE u.actor_stix_id = :actor_id
        ORDER BY fb.weight DESC
        """,
        {"actor_id": actor_id},
    )


def get_asset_exposure(
    request: Request,
) -> list[dict[str, Any]]:
    """Return externally-exposed assets and their reachable TTP counts."""
    repo: SQLiteRepository = request.app.state.repo
    return repo.query(
        """
        SELECT
            a.id AS asset_id,
            a.name AS asset_name,
            COALESCE(a.pir_adjusted_criticality, a.criticality) AS pir_adjusted_criticality,
            COUNT(DISTINCT t.actor_stix_id) AS targeting_actor_count,
            COUNT(DISTINCT u.ttp_stix_id) AS reachable_ttp_count
        FROM Asset a
        LEFT JOIN Targets t ON t.asset_id = a.id
        LEFT JOIN Uses u ON u.actor_stix_id = t.actor_stix_id
        WHERE a.exposed_to_internet = 1
        GROUP BY a.id, a.name, a.pir_adjusted_criticality, a.criticality
        ORDER BY pir_adjusted_criticality DESC
        """
    )


def get_similar_incidents(
    request: Request,
    incident_id: str = Query(..., description="Incident STIX ID"),
    top_k: int = Query(5, ge=1, le=20),
    alpha: float = Query(0.5, ge=0.0, le=1.0),
    max_hops: int = Query(2, ge=1, le=4),
) -> list[dict[str, Any]]:
    """Return past incidents most similar to the given incident."""
    repo: SQLiteRepository = request.app.state.repo
    return find_similar_incidents(repo, incident_id, top_k=top_k, alpha=alpha, max_hops=max_hops)
