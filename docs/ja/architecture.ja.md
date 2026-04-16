# cti-graph — アーキテクチャガイド

## 1. 目的とスコープ

cti-graph は脅威インテリジェンスサイクルを運用する基盤。外部 CTI データ（STIX 2.1）と内部アセット情報を統合し、重み付き攻撃グラフの構築・チョークポイント検出・分析結果の REST API 提供を行う。

**対象範囲:** STIX 取り込み、PIR 駆動の優先順位付け、攻撃グラフ分析、チョークポイント検出、インシデント類似度、API サーバー。

**対象外:** リアルタイム SIEM 検知、エンドポイント保護、脆弱性スキャン（これらのデータを受け取る側）。

---

## 2. システム構成

```
入力                          ETL                       分析
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ STIX バンドル │──parse──▶│ ETL Worker   │──upsert─▶│ SQLite DB    │
│ (JSON)       │         │              │         │ (25テーブル) │
├──────────────┤         │ ■ STIX変換   │         └──────┬───────┘
│ PIR JSON     │──load──▶│ ■ TLPフィルタ│                │
├──────────────┤         │ ■ PIRフィルタ│         ┌──────▼───────┐
│ Asset JSON   │──feed──▶│ ■ 重み計算   │         │ FastAPI API  │
└──────────────┘         │ ■ Targets生成│         │ 5エンドポイント│
                         └──────────────┘         └──────┬───────┘
                                                         │
                                              ┌──────────┼──────────┐
                                              ▼          ▼          ▼
                                          Caldera    Slack      クライアント
```

---

## 3. グラフデータモデル

### 共存するサブグラフ

`Targets` エッジで結合される 2 つのサブグラフ:

- **Attack Flow:** 重み付き `FollowedBy` エッジによる TTP 時系列遷移
- **Attack Graph:** アセット間接続性と脆弱性エクスポージャー

### ノードテーブル (8)

| テーブル | PK | ソース |
|---------|-----|--------|
| ThreatActor | stix_id | STIX threat-actor / intrusion-set |
| TTP | stix_id | STIX attack-pattern |
| Vulnerability | stix_id | STIX vulnerability |
| MalwareTool | stix_id | STIX malware / tool |
| Observable | stix_id | STIX indicator (IoC 抽出) |
| Incident | stix_id | STIX incident (IR フィードバック) |
| Asset | UUID | 内部アセットインベントリ |
| SecurityControl | UUID | 内部セキュリティ制御 |

### エッジテーブル (17)

**Attack Flow:** Uses, MalwareUsesTTP, Exploits, FollowedBy, IncidentUsesTTP

**Attack Graph:** UsesTool, Targets, TargetsAsset, HasVulnerability, ConnectedTo, ProtectedBy

**Observable:** IndicatesTTP, IndicatesActor

**PIR カスケード:** PIR, PirPrioritizesActor, PirPrioritizesTTP, PirWeightsAsset

---

## 4. 主要アルゴリズム

### 4.1 FollowedBy 重み (4 因子)

```
weight = base_prob × activity_score × exploit_ease × ir_multiplier
```

| 因子 | 範囲 | 計算 |
|------|------|------|
| base_prob | 0.0–1.0 | この遷移を行うアクター数 / 総アクター数 |
| activity_score | 0.0–2.0 | 90 日間の観測率平均 × 2.0 |
| exploit_ease | 0.0–1.5 | CVSS/10 × 0.5 + EPSS × 0.5 (CVE なし時 1.0) |
| ir_multiplier | 1.0–1.5 | IR 確認済みなら 1.5、それ以外 1.0 |

最終重みは 1.0 で上限キャップ。

### 4.2 チョークポイントスコア

```
choke_score = pir_adjusted_criticality × targeting_actor_count
```

### 4.3 PIR 資産重要度

```
pir_adjusted_criticality = base × max(multipliers) × actor_boost
```

10.0 で上限キャップ。

### 4.4 インシデント類似度

```
hybrid_score = α × jaccard_ttp + (1 - α) × transition_coverage
```

### 4.5 TTP→Asset マッチング

ATT&CK テクニック ID プレフィックス → アセットタグの粗粒度マッピング（30+ エントリ）。マップにないテクニックはエッジ非生成（fail-closed）。

---

## 5. 設計判断

| 判断 | 理由 |
|------|------|
| SQLite（Spanner ではなく） | ローカルファースト、クラウド依存ゼロ、セットアップ不要 |
| Repository Pattern | バックエンド差替可能（DuckDB, PostgreSQL 等） |
| stix2 ライブラリ検証 | STIX オブジェクトの整合性保証 |
| TLP マーキング定義 ID ルックアップ | 標準 STIX UUID にレベル名が含まれないため |

## 6. 却下した代替案

| 代替案 | 却下理由 |
|--------|---------|
| NetworkX | SQL クエリで十分なパターン; 依存追加不要 |
| Neo4j | サーバー別途必要; ローカルファーストでない |
| Spanner (SAGE 原版) | クラウド依存; コスト; 複雑性 |
| メモリ内グラフのみ | 永続性なし |
