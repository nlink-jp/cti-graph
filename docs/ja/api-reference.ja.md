# API リファレンス

cti-graph は `127.0.0.1:8080`（設定変更可能）で FastAPI REST API を提供。

## 認証

`CTI_GRAPH_API_TOKEN` 環境変数を設定すると Bearer トークン認証が有効になる。

```
Authorization: Bearer <token>
```

## エンドポイント

### GET /attack-paths

特定アセットへの攻撃パスを返す。

| パラメータ | 型 | 必須 | デフォルト | 説明 |
|-----------|-----|------|-----------|------|
| `asset_id` | string | はい | — | アセット ID |
| `limit` | int | いいえ | 10 | 最大結果数 (1–100) |

### GET /choke-points

チョークポイント資産をスコア降順で返す。

| パラメータ | 型 | 必須 | デフォルト | 説明 |
|-----------|-----|------|-----------|------|
| `top_n` | int | いいえ | 20 | 最大結果数 (1–100) |

スコア: `choke_score = pir_adjusted_criticality × targeting_actor_count`

### GET /actor-ttps

特定アクターの TTP 攻撃フローを返す。

| パラメータ | 型 | 必須 | デフォルト | 説明 |
|-----------|-----|------|-----------|------|
| `actor_id` | string | はい | — | ThreatActor STIX ID |

### GET /asset-exposure

インターネット公開アセットとそのリスクを返す。パラメータなし。

### GET /similar-incidents

類似インシデントを検索。

| パラメータ | 型 | 必須 | デフォルト | 説明 |
|-----------|-----|------|-----------|------|
| `incident_id` | string | はい | — | Incident STIX ID |
| `top_k` | int | いいえ | 5 | 最大結果数 (1–20) |
| `alpha` | float | いいえ | 0.5 | Jaccard 重み (0.0–1.0) |
| `max_hops` | int | いいえ | 2 | BFS 深度 (1–4) |

スコア: `hybrid_score = α × jaccard_ttp + (1 - α) × transition_coverage`
