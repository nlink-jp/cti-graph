# PIR JSON Schema

Priority Intelligence Requirements (PIR) define what threat intelligence
is most relevant to the organisation. cti-graph uses PIR definitions to
filter actors, weight assets, and generate Targets edges.

## Schema

PIR can be a single object or an array of objects.

```json
{
  "pir_id": "PIR-2025-001",
  "intelligence_level": "strategic",
  "organizational_scope": "Security Team",
  "decision_point": "Investment in ransomware defense",
  "description": "Strengthen defenses against ransomware groups targeting our infrastructure",
  "rationale": "Likelihood=5, Impact=5 — financial impact critical",
  "recommended_action": "Implement backup isolation, EDR at scale",
  "threat_actor_tags": ["ransomware", "financially-motivated"],
  "asset_weight_rules": [
    { "tag": "external-facing", "criticality_multiplier": 2.0 },
    { "tag": "backup", "criticality_multiplier": 1.5 },
    { "tag": "database", "criticality_multiplier": 1.8 }
  ],
  "risk_score": {
    "likelihood": 5,
    "impact": 5,
    "composite": 25
  },
  "valid_from": "2025-01-01",
  "valid_until": "2025-12-31"
}
```

## Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pir_id` | string | yes | Unique identifier (e.g. `PIR-2025-001`) |
| `intelligence_level` | string | no | `strategic` / `operational` / `tactical` (default: `operational`) |
| `organizational_scope` | string | no | Team or department scope |
| `decision_point` | string | no | Decision this PIR supports |
| `description` | string | yes | What this PIR covers |
| `rationale` | string | no | Why this PIR exists |
| `recommended_action` | string | no | Suggested response |
| `threat_actor_tags` | string[] | yes | Tags to match against actor labels |
| `asset_weight_rules` | object[] | no | Asset criticality multiplier rules |
| `asset_weight_rules[].tag` | string | yes | Asset tag to match |
| `asset_weight_rules[].criticality_multiplier` | float | yes | Multiplier (typically 1.0–3.0) |
| `risk_score` | object | no | Risk assessment |
| `risk_score.composite` | int | no | Stored as `risk_composite` in DB |
| `valid_from` | string | no | ISO 8601 date |
| `valid_until` | string | no | ISO 8601 date |

## How PIR Affects Processing

### Actor Filtering

Actors whose `labels` (stored as `tags`) intersect any PIR's
`threat_actor_tags` are accepted. Actors with no matching tags are
skipped. When no PIRs are loaded, all actors are accepted.

### Targets Edge Generation

For each PIR, matched actors × matched assets (by `asset_weight_rules`
tags) produce Targets edges. Confidence = tag overlap ratio (0–100).

### Asset Criticality

```
pir_adjusted_criticality = base_criticality
    × MAX(matching rules' criticality_multiplier)
    × (1.5 if any Targets-linked actor matches a PIR, else 1.0)
```

Capped at 10.0.

### Available Tags

**Actor tags (examples):**

| Category | Tags |
|----------|------|
| Nation-state | `apt-china`, `apt-russia`, `apt-north-korea`, `apt-iran` |
| Motivation | `espionage`, `financially-motivated`, `hacktivism`, `destructive` |
| Target | `ot-targeting`, `critical-infrastructure`, `cloud-targeting` |
| Crime | `ransomware`, `raas`, `cybercriminal`, `initial-access-broker` |

**Asset tags (examples):**

| Tag | Typical Multiplier | Description |
|-----|-------------------|-------------|
| `external-facing` | 1.5–2.0 | Internet-exposed services |
| `database` | 1.8 | Data stores |
| `backup` | 1.5 | Backup systems |
| `identity` / `ad` | 2.0–2.5 | Authentication infrastructure |
| `cloud` | 1.5 | Cloud resources |
| `ot` | 2.0 | Operational technology |
| `endpoint` | 1.5 | User endpoints |
