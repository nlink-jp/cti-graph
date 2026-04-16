# PIR JSON スキーマ

PIR（Priority Intelligence Requirements）は組織にとって最も関連性の高い脅威インテリジェンスを定義する。cti-graph は PIR を使ってアクターのフィルタリング、アセットの重み付け、Targets エッジの生成を行う。

## スキーマ

単一オブジェクトまたは配列。

```json
{
  "pir_id": "PIR-2025-001",
  "intelligence_level": "strategic",
  "organizational_scope": "セキュリティチーム",
  "decision_point": "ランサムウェア防御への投資",
  "description": "インフラを標的とするランサムウェアグループへの防御強化",
  "rationale": "可能性=5, 影響=5 — 財務的影響が重大",
  "recommended_action": "バックアップ分離、EDR 大規模導入",
  "threat_actor_tags": ["ransomware", "financially-motivated"],
  "asset_weight_rules": [
    { "tag": "external-facing", "criticality_multiplier": 2.0 },
    { "tag": "backup", "criticality_multiplier": 1.5 }
  ],
  "risk_score": { "likelihood": 5, "impact": 5, "composite": 25 },
  "valid_from": "2025-01-01",
  "valid_until": "2025-12-31"
}
```

## フィールド一覧

| フィールド | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `pir_id` | string | はい | 一意識別子 |
| `intelligence_level` | string | いいえ | `strategic` / `operational` / `tactical` |
| `threat_actor_tags` | string[] | はい | アクターのラベルとマッチするタグ |
| `asset_weight_rules` | object[] | いいえ | アセット重要度乗数ルール |
| `asset_weight_rules[].tag` | string | はい | マッチ対象のアセットタグ |
| `asset_weight_rules[].criticality_multiplier` | float | はい | 乗数（通常 1.0–3.0） |
| `risk_score.composite` | int | いいえ | DB に `risk_composite` として格納 |
| `valid_from` / `valid_until` | string | いいえ | ISO 8601 日付 |

## PIR が処理に与える影響

### アクターフィルタリング

アクターの `tags` が PIR の `threat_actor_tags` と交差すれば採用。PIR 未設定時は全アクター採用。

### Targets エッジ生成

マッチしたアクター × マッチしたアセットの直積で生成。Confidence = タグ重複率 (0–100)。

### アセット重要度

```
pir_adjusted_criticality = base × max(乗数) × actor_boost (上限 10.0)
```
