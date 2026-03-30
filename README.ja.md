# auth.proxy

トークン検証リバースプロキシ。イントロスペクション結果のキャッシュ機能付き。クライアントとダウンストリームサービスの間に配置する。

このコンポーネントはオプション。auth.policy-verifier と grpc.authz は JWT を直接検証するため、auth.proxy なしでもシステムは動作する。導入するメリット:

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
| `INTROSPECT_URL` | イントロスペクションエンドポイント URL |
| `INTROSPECT_CACHE_TTL_SEC` | キャッシュ TTL（秒） |
| `ENDPOINT_BASEURL` | ダウンストリームサービスのベース URL |

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 トークン発行
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC 認可ミドルウェア

## ライセンス

Apache License 2.0
