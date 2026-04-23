# auth.proxy

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（[認証・トークン発行](https://github.com/o3co/auth.provider) / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）の外に位置する任意の境界ゲートで、不正／失効トークンをダウンストリーム到達前に遮断します。

トークン検証リバースプロキシ。イントロスペクション結果のキャッシュ機能付き。クライアントとダウンストリームサービスの間に配置する。

このコンポーネントはオプション。auth.policy-verifier と protobuf.interceptors は JWT を直接検証するため、auth.proxy なしでもシステムは動作する。導入するメリット:

- **イントロスペクションベースの検証** — 失効したトークンを即座に検出可能。JWT ローカル検証のみの場合はトークンの有効期限まで検出できない
- **キャッシュ** — イントロスペクション結果をキャッシュ（デフォルト 30 秒 TTL）し、auth.provider への負荷を軽減
- **検証の集約** — ダウンストリームサービスは認証ロジックを実装せずに検証済みリクエストを受け取れる

## 動作

1. `Authorization: Bearer <token>` ヘッダーを検出（ない場合はそのまま通過 — パブリック API に対応）
2. トークンの SHA-256 ハッシュでインメモリキャッシュを確認
3. キャッシュミス時、プロバイダーの `POST /oauth/introspect` を呼び出す
4. `active: false` なら `401` を返し、`active: true` ならリクエストをダウンストリームに転送

## 機能

- イントロスペクション結果のキャッシュ（デフォルト 30 秒 TTL）でプロバイダーの負荷を軽減
- `express-http-proxy` による透過的なリクエスト転送
- Authorization ヘッダーをダウンストリームサービスに転送
- HOCON 設定 + Zod バリデーション

## セットアップ

```bash
pnpm install
pnpm run build
pnpm run start
```

## 開発

```bash
pnpm run debug    # tsx watch モード
```

## Docker

```bash
make docker       # ランタイムイメージのビルド
```

## 設定

| 環境変数 | 説明 |
| --- | --- |
| `HTTP_PORT` | HTTP リッスンポート（デフォルト: 80） |
| `HTTP_HOSTNAME` | HTTP リッスンホスト名（デフォルト: 0.0.0.0） |
| `HTTP_PATH_PREFIX` | プロキシルートのパスプレフィックス（デフォルト: /） |
| `HTTP_BODY_LIMIT_SIZE` | リクエストボディサイズ上限（デフォルト: 10mb） |
| `CLIENT_ID` | イントロスペクション認証のクライアント ID（`CLIENT_SECRET` とペアで設定／両方未設定も可） |
| `CLIENT_SECRET` | イントロスペクション認証のクライアントシークレット（`CLIENT_ID` とペアで設定／両方未設定も可） |
| `INTROSPECT_URL` | イントロスペクションエンドポイント URL |
| `INTROSPECT_CACHE_TTL_SEC` | キャッシュ TTL（秒、デフォルト: 30） |
| `UPSTREAM_BASEURL` | アップストリームサービスのベース URL |
| `CORS_ORIGIN_PATTERN` | CORS オリジン正規表現パターン（任意） |

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 トークン発行
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf option ベースの認可 interceptor

## ライセンス

Apache License 2.0
