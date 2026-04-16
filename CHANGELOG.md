# Changelog

## [0.1.1] - 2026-04-16

### Added
- Architecture guide, PIR JSON schema spec, API reference (docs/en + docs/ja)
- Project-level CLAUDE.md with STIX UUID, TLP marking ID, and design rules
- Caldera TTP→Ability mapping via Ability API (`fetch_ability_map`, `resolve_ability_ids`)
- 5 new tests (total: 124)

## [0.1.0] - 2026-04-16

### Added
- SQLite DDL schema (25 tables, 11 indexes)
- STIX 2.1 parser with stix2 validation and TLP filtering
- STIX mapper with node/edge mappers and FollowedBy 4-factor weight calculation
- PIR filter with actor relevance, Targets generation, and asset criticality update
- TTP-Asset matcher with 30+ ATT&CK technique-to-asset-tag mappings
- Full ETL pipeline with FK-safe edge filtering
- Incident similarity analysis (Jaccard + BFS transition coverage)
- FastAPI REST API (5 endpoints with Bearer token auth)
- OpenCTI client (pycti + REST fallback)
- Caldera client (adversary profile sync)
- Slack webhook notifications (choke-point score changes)
- CLI with init-db, etl, serve, version subcommands
- 119 tests
