# CLAUDE.md — cti-graph

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Project overview

Local-first threat intelligence attack graph analysis platform.
Inspired by SAGE (sw33t-b1u/sage); SQLite instead of Spanner.

- **Series:** cybersecurity-series
- **Lang:** Python 3.12+
- **DB:** SQLite (WAL mode, foreign keys enabled)
- **API:** FastAPI + uvicorn

## Build & test

```bash
uv sync                     # Install
make test                   # uv run pytest tests/ -v
make lint                   # ruff check + format check
make build                  # uv build --out-dir dist/
cti-graph init-db            # Create DB
cti-graph etl --bundle FILE  # Ingest STIX
cti-graph serve              # Start API
```

## Project-specific rules

### STIX ID format

The stix2 library enforces valid UUID v4 format for all STIX IDs:
`<type>--<uuid4>` (e.g. `threat-actor--04f69fa3-0776-43ae-a37b-f37917028fb7`).
Test fixtures must use real UUIDs, not shorthand like `threat-actor--test-001`.

### TLP marking definitions

Use well-known STIX 2.1 marking definition IDs for TLP extraction.
Do **not** rely on substring matching (the UUID doesn't contain "red" etc.):

| TLP | Marking Definition ID |
|-----|----------------------|
| WHITE | `marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9` |
| GREEN | `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da` |
| AMBER | `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82` |
| RED | `marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed` |

### FollowedBy weight formula

```
weight = base_prob × activity_score × exploit_ease × ir_multiplier
```

- `base_prob`: actor transition count / total actors (0.0–1.0)
- `activity_score`: 90-day observation rate × 2.0 (0.0–2.0)
- `exploit_ease`: CVSS/EPSS derived, 1.0 if no CVE
- `ir_multiplier`: 1.5 if IR-confirmed, else 1.0
- Final weight capped at 1.0

### PIR behaviour

- No PIRs loaded → all actors accepted (permissive default)
- TLP RED objects are **never** stored (filtered at ingestion)
- Asset criticality formula: `base × max_multiplier × actor_boost`, capped at 10.0

### SQLite threading

`check_same_thread=False` is required in `SQLiteRepository` for FastAPI
serving (uvicorn runs handlers in a thread pool).

### Caldera integration

Current implementation uses STIX TTP IDs as Caldera Ability ID placeholders.
A `TECHNIQUE_ABILITY_MAP` is needed for production use. See `caldera/client.py`.
