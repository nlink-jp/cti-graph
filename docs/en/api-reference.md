# API Reference

cti-graph exposes a FastAPI REST API on `127.0.0.1:8080` (configurable).

## Authentication

Set `CTI_GRAPH_API_TOKEN` environment variable to enable Bearer token
authentication. When unset, all endpoints are open.

```
Authorization: Bearer <token>
```

Responses:
- `401` — Missing or malformed Authorization header
- `403` — Invalid token

---

## Endpoints

### GET /attack-paths

Return attack paths reaching a specific asset.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `asset_id` | string | yes | — | Asset ID |
| `limit` | int | no | 10 | Max results (1–100) |

**Response:** `200 OK`

```json
[
  {
    "actor_stix_id": "threat-actor--04f69fa3-...",
    "actor_name": "APT Group",
    "ttp_stix_id": "attack-pattern--15bd181c-...",
    "ttp_name": "Spearphishing Attachment",
    "confidence": 90
  }
]
```

---

### GET /choke-points

Return choke-point assets ordered by score.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `top_n` | int | no | 20 | Max results (1–100) |

**Response:** `200 OK`

```json
[
  {
    "asset_id": "asset-web-01",
    "asset_name": "WebServer",
    "pir_adjusted_criticality": 10.0,
    "targeting_actor_count": 3,
    "choke_score": 30.0
  }
]
```

**Scoring:** `choke_score = pir_adjusted_criticality × targeting_actor_count`

---

### GET /actor-ttps

Return the TTP attack flow for a specific actor.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `actor_id` | string | yes | — | ThreatActor STIX ID |

**Response:** `200 OK`

```json
[
  {
    "src_ttp_stix_id": "attack-pattern--15bd181c-...",
    "src_ttp_name": "Spearphishing Attachment",
    "dst_ttp_stix_id": "attack-pattern--0592a0fe-...",
    "dst_ttp_name": "Command and Scripting Interpreter",
    "weight": 0.49,
    "source": "threat_intel"
  }
]
```

Ordered by `weight` descending.

---

### GET /asset-exposure

Return internet-exposed assets with targeting and TTP counts.

**Parameters:** None.

**Response:** `200 OK`

```json
[
  {
    "asset_id": "asset-web-01",
    "asset_name": "WebServer",
    "pir_adjusted_criticality": 10.0,
    "targeting_actor_count": 2,
    "reachable_ttp_count": 12
  }
]
```

Only returns assets where `exposed_to_internet = true`.

---

### GET /similar-incidents

Find historical incidents most similar to a given incident.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `incident_id` | string | yes | — | Incident STIX ID |
| `top_k` | int | no | 5 | Max results (1–20) |
| `alpha` | float | no | 0.5 | Weight for Jaccard component (0.0–1.0) |
| `max_hops` | int | no | 2 | BFS depth on FollowedBy graph (1–4) |

**Response:** `200 OK`

```json
[
  {
    "incident_id": "incident--abc123...",
    "hybrid_score": 0.83,
    "jaccard_ttp": 0.67,
    "transition_coverage": 1.0,
    "shared_ttps": ["attack-pattern--15bd181c-..."]
  }
]
```

**Scoring:** `hybrid_score = α × jaccard_ttp + (1 - α) × transition_coverage`
