# cti-graph — Architecture Guide

## 1. Purpose and Scope

cti-graph operationalises the threat intelligence cycle by integrating
external CTI data (STIX 2.1) with internal asset information. It builds
a weighted attack graph, detects choke points, and exposes analysis
results via a REST API.

**In scope:** STIX ingestion, PIR-driven prioritisation, attack graph
analysis, choke-point detection, incident similarity, API serving.

**Out of scope:** Real-time SIEM detection, endpoint protection,
vulnerability scanning (cti-graph consumes data from these systems).

---

## 2. System Architecture

```
INPUT                         ETL                      ANALYSIS
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ STIX Bundles │──parse──▶│ ETL Worker   │──upsert─▶│ SQLite DB    │
│ (JSON files) │         │              │         │ (25 tables)  │
├──────────────┤         │ ■ STIX map   │         └──────┬───────┘
│ PIR JSON     │──load──▶│ ■ TLP filter │                │
├──────────────┤         │ ■ PIR filter │         ┌──────▼───────┐
│ Asset JSON   │──feed──▶│ ■ Weights    │         │ FastAPI API  │
└──────────────┘         │ ■ Targets    │         │ 5 endpoints  │
                         └──────────────┘         └──────┬───────┘
                                                         │
                                              ┌──────────┼──────────┐
                                              ▼          ▼          ▼
                                          Caldera    Slack      Clients
```

### Data Flow

1. **Input:** STIX 2.1 bundles (files or OpenCTI), PIR definitions, asset inventory
2. **ETL:** Classify → TLP filter → PIR filter → upsert nodes → upsert edges → derive FollowedBy → generate Targets → update criticality → PIR cascade
3. **Storage:** SQLite with WAL mode, 8 node tables + 17 edge tables
4. **Analysis:** REST API queries the graph for attack paths, choke points, actor TTP flows, asset exposure, and incident similarity

---

## 3. Graph Data Model

### Co-existing Sub-graphs

The graph contains two sub-graphs cross-linked via the `Targets` edge:

- **Attack Flow:** TTP time-series transitions with weighted `FollowedBy` edges
- **Attack Graph:** Asset connectivity and vulnerability exposure

### Node Tables (8)

| Table | PK | Source |
|-------|-----|--------|
| ThreatActor | stix_id | STIX threat-actor / intrusion-set |
| TTP | stix_id | STIX attack-pattern |
| Vulnerability | stix_id | STIX vulnerability |
| MalwareTool | stix_id | STIX malware / tool |
| Observable | stix_id | STIX indicator (IoC extraction) |
| Incident | stix_id | STIX incident (IR feedback) |
| Asset | UUID | Internal asset inventory |
| SecurityControl | UUID | Internal security controls |

### Edge Tables (17)

**Attack Flow:** Uses, MalwareUsesTTP, Exploits, FollowedBy, IncidentUsesTTP

**Attack Graph:** UsesTool, Targets, TargetsAsset, HasVulnerability, ConnectedTo, ProtectedBy

**Observable:** IndicatesTTP, IndicatesActor

**PIR Cascade:** PIR, PirPrioritizesActor, PirPrioritizesTTP, PirWeightsAsset

---

## 4. Key Algorithms

### 4.1 FollowedBy Weight (4-Factor)

```
weight = base_prob × activity_score × exploit_ease × ir_multiplier
```

| Factor | Range | Calculation |
|--------|-------|-------------|
| base_prob | 0.0–1.0 | actors making this transition / total actors |
| activity_score | 0.0–2.0 | 90-day observation rate average × 2.0 |
| exploit_ease | 0.0–1.5 | CVSS/10 × 0.5 + EPSS × 0.5 (1.0 if no CVE) |
| ir_multiplier | 1.0–1.5 | 1.5 if IR-confirmed, else 1.0 |

Final weight capped at 1.0.

### 4.2 Choke-Point Score

```
choke_score = pir_adjusted_criticality × targeting_actor_count
```

### 4.3 PIR Asset Criticality

```
pir_adjusted_criticality = base × max(multipliers) × actor_boost
```

- `max(multipliers)`: highest matching `asset_weight_rules[].criticality_multiplier`
- `actor_boost`: 1.5 if any Targets-linked actor matches a PIR, else 1.0
- Capped at 10.0

### 4.4 Incident Similarity (Hybrid Score)

```
hybrid_score = α × jaccard_ttp + (1 - α) × transition_coverage
```

- `jaccard_ttp`: |A ∩ B| / |A ∪ B| of TTP sets
- `transition_coverage`: fraction of reference TTPs reachable via BFS (max_hops) on FollowedBy graph

### 4.5 TTP→Asset Matching

Coarse-grained mapping from ATT&CK technique ID prefix to asset tags
(30+ entries in `TECHNIQUE_TAG_MAP`). Fail-closed: no edge if technique
not in map.

---

## 5. Design Decisions

### Why SQLite instead of Spanner?

SAGE uses Google Cloud Spanner for scalability and graph queries.
cti-graph targets local-first use cases where cloud dependencies
are undesirable. SQLite provides:
- Zero setup, single-file database
- WAL mode for concurrent read/write
- Foreign key enforcement
- Sufficient performance for org-scale threat intel graphs

### Why Repository Pattern?

`GraphRepository` protocol allows swapping SQLite for another backend
(e.g. DuckDB, PostgreSQL) without changing ETL or analysis code.

### Why stix2 library for validation?

Ensures STIX object integrity at ingestion. Catches malformed objects
before they enter the graph. Trade-off: requires valid UUID v4 IDs.

### Why TLP marking definition IDs instead of substring matching?

Standard STIX TLP marking definition UUIDs don't contain the TLP level
name as a substring. Lookup by well-known ID is correct and fast.

---

## 6. Rejected Alternatives

| Alternative | Reason rejected |
|-------------|----------------|
| NetworkX for graph analysis | Overkill for SQL-queryable patterns; adds dependency |
| Neo4j | Requires separate server; not local-first |
| Spanner (original SAGE) | Cloud dependency; cost; complexity |
| In-memory graph only | No persistence across runs |
| Raw dict parsing (no stix2) | Misses validation; fragile |
