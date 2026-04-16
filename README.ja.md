# cti-graph

ローカルファーストの脅威インテリジェンス攻撃グラフ分析プラットフォーム。

[SAGE](https://github.com/sw33t-b1u/sage) にインスパイアされ、Google Cloud Spanner の代わりに
ローカル SQLite ストレージを使用するよう設計。

## 概要

cti-graph は STIX 2.1 脅威インテリジェンスデータを取り込み、重み付きTTP遷移を持つ
攻撃グラフを構築し、分析結果を REST API で提供します。

### 主な機能

- **STIX 2.1 取り込み** — バンドル解析、stix2 ライブラリによる検証、TLP フィルタリング
- **PIR 駆動の優先順位付け** — Priority Intelligence Requirements によるアクターフィルタとアセット重み付け
- **FollowedBy 重み** — 4 因子計算: 基本確率 × 活動度 × 悪用容易性 × IR 乗数
- **チョークポイント検出** — 重要度 × 標的アクター数による高リスク資産の特定
- **インシデント類似度** — Jaccard TTP + BFS 遷移カバレッジのハイブリッドスコア
- **TTP→Asset マッチング** — 30 以上の ATT&CK テクニック-アセットタグ対応
- **REST API** — Bearer トークン認証付き FastAPI エンドポイント
- **外部連携** — OpenCTI、MITRE Caldera、Slack Webhook

## クイックスタート

```bash
# インストール
uv sync

# データベース初期化
cti-graph init-db

# STIX データ取り込み
cti-graph etl --bundle path/to/bundle.json
cti-graph etl --bundle path/to/bundle.json --pir path/to/pir.json

# API サーバー起動
cti-graph serve
```

## CLI コマンド

| コマンド | 説明 |
|---------|------|
| `cti-graph init-db` | グラフスキーマで SQLite データベースを作成 |
| `cti-graph etl --bundle FILE` | 単一 STIX バンドルを取り込み |
| `cti-graph etl --pir FILE` | PIR フィルタリング付きで取り込み |
| `cti-graph serve` | FastAPI 分析サーバーを起動 |
| `cti-graph version` | バージョン表示 |

## API エンドポイント

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/attack-paths?asset_id=...` | アセットへの攻撃パス |
| GET | `/choke-points?top_n=20` | 高リスクチョークポイント資産 |
| GET | `/actor-ttps?actor_id=...` | アクターの TTP 攻撃フロー |
| GET | `/asset-exposure` | インターネット公開資産のリスク |
| GET | `/similar-incidents?incident_id=...` | 類似インシデント検索 |

`CTI_GRAPH_API_TOKEN` を設定すると Bearer トークン認証が有効になります。

## 設定

設定ファイル: `~/.config/cti-graph/config.toml`
（`CTI_GRAPH_CONFIG` 環境変数で上書き可能）

```toml
[database]
path = ""  # デフォルト: ~/.local/share/cti-graph/graph.db

[stix]
landing_dir = ""  # デフォルト: ~/.local/share/cti-graph/stix/
tlp_max = "amber"  # red オブジェクトは保存しない

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

## グラフデータモデル

**ノードテーブル (8):** ThreatActor, TTP, Vulnerability, MalwareTool, Observable, Incident, Asset, SecurityControl

**エッジテーブル (17):** Uses, UsesTool, Exploits, MalwareUsesTTP, FollowedBy, IncidentUsesTTP, Targets, TargetsAsset, HasVulnerability, ConnectedTo, ProtectedBy, IndicatesTTP, IndicatesActor, PIR, PirPrioritizesActor, PirPrioritizesTTP, PirWeightsAsset

## 開発

```bash
make test      # テスト実行
make lint      # Lint チェック
make format    # フォーマット修正
make build     # ビルド
```

## ライセンス

Apache-2.0 — 詳細は [LICENSE](LICENSE) を参照。

本プロジェクトは Apache-2.0 ライセンスの [SAGE](https://github.com/sw33t-b1u/sage) に
インスパイアされています。
