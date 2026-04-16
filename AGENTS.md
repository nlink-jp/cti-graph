# AGENTS.md — cti-graph

## Project Summary

Local-first threat intelligence attack graph analysis platform.
Inspired by SAGE (sw33t-b1u/sage), using SQLite instead of Spanner.

## Build & Test

```bash
uv sync                        # Install dependencies
make test                      # uv run pytest tests/ -v
make lint                      # ruff check + format check
make format                    # ruff fix + format
make build                     # uv build --out-dir dist/
```

## CLI

```bash
cti-graph init-db              # Create SQLite DB
cti-graph etl --bundle FILE    # Ingest STIX bundle
cti-graph etl --pir FILE       # With PIR filtering
cti-graph serve                # Start API server (127.0.0.1:8080)
cti-graph version              # Show version
```

## Project Structure

```
src/cti_graph/
├── __init__.py          # Version
├── cli.py               # Click CLI entry point
├── config.py            # Pydantic config (TOML + env)
├── db/
│   └── repository.py    # SQLite repository (Protocol + impl)
├── stix/
│   ├── parser.py        # STIX bundle loading + TLP filter
│   └── mapper.py        # STIX→DB row mapping + FollowedBy weights
├── pir/
│   └── filter.py        # PIR filtering + Targets + criticality
├── etl/
│   └── worker.py        # Full ETL orchestration
├── analysis/
│   ├── similarity.py    # Incident similarity (Jaccard + BFS)
│   └── ttp_asset_matcher.py  # TTP→Asset edge derivation
├── api/
│   └── app.py           # FastAPI REST API (5 endpoints)
├── opencti/
│   └── client.py        # OpenCTI STIX fetch
├── caldera/
│   └── client.py        # Caldera adversary sync
└── notify/
    └── slack.py          # Slack webhook notifications
```

## Key Design Decisions

- **SQLite over Spanner** — Local-first, zero cloud dependency
- **Repository Pattern** — GraphRepository protocol for backend swaps
- **stix2 validation** — IDs must be valid UUIDs (stix2 library requirement)
- **TLP enforcement** — RED objects never stored (filtered at ingestion)
- **FollowedBy 4-factor** — base_prob × activity × exploit_ease × ir_multiplier
- **FK-safe ETL** — Edge rows filtered to reference only ingested entities

## Gotchas

- STIX IDs must be valid UUIDs (`type--uuid4`), enforced by stix2 library
- SQLite `check_same_thread=False` required for FastAPI serving
- TLP marking definitions use well-known STIX IDs, not substring matching
- PIR with no threat_actor_tags accepts all actors (permissive default)
