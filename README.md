# cti-graph

Local-first threat intelligence attack graph analysis platform.

Inspired by [SAGE](https://github.com/sw33t-b1u/sage) — adapted for
local SQLite storage instead of Google Cloud Spanner.

## Overview

cti-graph ingests STIX 2.1 threat intelligence data, builds an attack
graph with weighted TTP transitions, and exposes analysis results via a
REST API.

### Key Features

- **STIX 2.1 ingestion** — Parse bundles, validate with stix2 library, TLP filtering
- **PIR-driven prioritisation** — Filter actors and weight assets by Priority Intelligence Requirements
- **FollowedBy weights** — 4-factor formula: base probability × activity × exploit ease × IR multiplier
- **Choke-point detection** — Identify high-risk assets by criticality × actor targeting count
- **Incident similarity** — Hybrid scoring with Jaccard TTP + BFS transition coverage
- **TTP→Asset matching** — 30+ ATT&CK technique-to-asset-tag mappings
- **REST API** — FastAPI endpoints with Bearer token authentication
- **External integrations** — OpenCTI, MITRE Caldera, Slack webhooks

## Quick Start

```bash
# Install
uv sync

# Initialise database
cti-graph init-db

# Ingest STIX data
cti-graph etl --bundle path/to/bundle.json
cti-graph etl --bundle path/to/bundle.json --pir path/to/pir.json

# Start API server
cti-graph serve
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `cti-graph init-db` | Create SQLite database with graph schema |
| `cti-graph etl --bundle FILE` | Ingest a single STIX bundle |
| `cti-graph etl --pir FILE` | Ingest with PIR filtering |
| `cti-graph serve` | Start FastAPI analysis server |
| `cti-graph version` | Show version |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/attack-paths?asset_id=...` | Attack paths reaching an asset |
| GET | `/choke-points?top_n=20` | High-risk choke-point assets |
| GET | `/actor-ttps?actor_id=...` | TTP attack flow for an actor |
| GET | `/asset-exposure` | Internet-exposed asset risk |
| GET | `/similar-incidents?incident_id=...` | Similar incident search |

Set `CTI_GRAPH_API_TOKEN` to enable Bearer token authentication.

## Configuration

Configuration file: `~/.config/cti-graph/config.toml`
(override with `CTI_GRAPH_CONFIG` env var)

```toml
[database]
path = ""  # default: ~/.local/share/cti-graph/graph.db

[stix]
landing_dir = ""  # default: ~/.local/share/cti-graph/stix/
tlp_max = "amber"  # red objects never stored

[opencti]
url = ""
token_env = "OPENCTI_TOKEN"

[caldera]
url = ""
api_key_env = "CALDERA_API_KEY"

[notification]
slack_webhook_env = "SLACK_WEBHOOK_URL"
choke_point_threshold = 0.1

[api]
host = "127.0.0.1"
port = 8080
token_env = "CTI_GRAPH_API_TOKEN"
```

## Graph Data Model

**Node tables (8):** ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident, Asset, SecurityControl

**Edge tables (17):** Uses, UsesTool, Exploits, MalwareUsesTTP, FollowedBy, IncidentUsesTTP, Targets, TargetsAsset, HasVulnerability, ConnectedTo, ProtectedBy, IndicatesTTP, IndicatesActor, PIR, PirPrioritizesActor, PirPrioritizesTTP, PirWeightsAsset

## Development

```bash
make test      # Run tests
make lint      # Check linting
make format    # Fix formatting
make build     # Build distribution
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

This project is inspired by [SAGE](https://github.com/sw33t-b1u/sage),
licensed under Apache-2.0.
