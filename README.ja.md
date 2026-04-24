# auth.proxy

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（[認証・トークン発行](https://github.com/o3co/auth.provider) / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）の外に位置する任意の境界ゲートです。

クライアントとダウンストリームサービスの間に配置するリバースプロキシ。デプロイ時に `auth.mode` で選択した 2 つの排他モードのいずれかで動作する。

## 動作モード

`auth.mode` は必須項目 — `"validation"` または `"injection"` を明示する必要がある。省略またはタイポがあるとプロキシは起動に失敗する。HOCON（`auth.mode = "validation"`）または `AUTH_MODE` 環境変数で設定する。

### バリデーションモード（`auth.mode = "validation"`）

受信した `Authorization: Bearer <token>` ヘッダーをプロバイダーのイントロスペクションエンドポイントで検証する。Bearer ヘッダーがないリクエストはそのまま転送する（パブリックエンドポイントは引き続き到達可能）。

フロー:

1. `Authorization: Bearer <token>` ヘッダーを検出（ない場合はそのまま通過）。
2. トークンの SHA-256 ハッシュをキーにインメモリキャッシュを確認。
3. キャッシュミス時、プロバイダーの `POST /oauth/introspect` を呼び出す。
4. `active: false` なら `401` を返し、`active: true` ならリクエストを転送する。

JWT ローカル検証との比較:

- 失効したトークンを即座に検出可能。
- イントロスペクション結果をキャッシュ（デフォルト 30 秒 TTL）し、プロバイダーの負荷を軽減。
- ダウンストリームサービスは認証ロジックを実装せずに検証済みリクエストを受け取れる。

### インジェクションモード（`auth.mode = "injection"`）

受信したセッションクッキーを `Authorization: Bearer` トークンに変換してアップストリームへ送出する。OWASP OAuth 2.0 BCP Token Handler Pattern を実現 — ブラウザはアクセストークンを保持しない。

フロー:

1. `auth.injection.sessionCookieName` で指定されたセッションクッキーを抽出。
2. クッキーがない場合はリクエストをそのまま転送（認証が必要かどうかはサービス層が判断）。
3. キャッシュヒット時は、キャッシュした Bearer を注入して転送。
4. キャッシュミス時は、`grant_type=session` でプロバイダーの `POST /oauth/token` を呼び出してアクセストークンを取得。同一クッキーの並行ミスは 1 回のプロバイダー呼び出しに集約（single-flight）。
5. `Authorization: Bearer <token>` を注入してアップストリームに転送。

#### キャッシュ動作

- インメモリ、インスタンス単位。再起動やスケールアウト時はキャッシュがコールドになる。ロールアウト時のピーク負荷 ≈ `インスタンス数 × アクティブセッション数`。
- TTL: `min(auth.injection.tokenCache.ttlSeconds, provider.expires_in) - safetyMarginSeconds`。デフォルト 60 秒 − 5 秒の安全マージン。

#### セッション失効の遅延

プロバイダー側でログアウトした後も、プロキシは最大 `tokenCache.ttlSeconds`（安全マージンを引いた値）の間、キャッシュしたトークンを返し続ける可能性がある。失効の遅延を短くするには `ttlSeconds` を下げる（例: `10`）。トレードオフ: プロバイダーの負荷が増加する。

#### スコープ境界

1 インスタンスは 1 つの OAuth スコープドメインを担当する。`auth.injection.clientId` と `auth.injection.scope` はデプロイ時に固定する。複数のスコープドメインを扱う場合は、インスタンスを複数用意する。

#### CSRF の責務境界

プロキシは透過的な付加レイヤー。Bearer を注入するが、CSRF は強制しない。`SameSite=Lax` クッキー、同一オリジンデプロイ、アップストリームサービス側の CSRF 保護と組み合わせて使用する。

#### クッキー転送

セッションのグラント呼び出しでプロバイダーに転送されるのは `auth.injection.sessionCookieName` で指定されたクッキーのみ。その他のクッキー（アナリティクス、CSRF トークン、サードパーティ）はプロバイダーに到達しない。

#### 脅威モデル — プロセスメモリ

アクティブなアクセストークンはプロセスメモリに保持される。プロキシプロセスのメモリに読み取りアクセスできる攻撃者は、キャッシュしたトークンをすべて抽出できる。標準的なホストセキュリティプラクティスを適用すること（コンテナ分離、最小イメージ、不要な `ptrace` ケーパビリティの排除）。

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

共通環境変数:

| 環境変数 | 説明 |
| --- | --- |
| `AUTH_MODE` | **必須。** `"validation"` または `"injection"`。 |
| `HTTP_PORT` | HTTP リッスンポート（デフォルト: 80）。 |
| `HTTP_HOSTNAME` | HTTP リッスンホスト名（デフォルト: 0.0.0.0）。 |
| `HTTP_PATH_PREFIX` | プロキシルートのパスプレフィックス（デフォルト: /）。 |
| `HTTP_BODY_LIMIT_SIZE` | リクエストボディサイズ上限（デフォルト: 10mb）。 |
| `UPSTREAM_BASEURL` | アップストリームサービスのベース URL。 |
| `CORS_ORIGIN_PATTERN` | CORS オリジン正規表現パターン（任意）。 |

バリデーションモード:

| 環境変数 | 説明 |
| --- | --- |
| `CLIENT_ID` | イントロスペクション認証のクライアント ID（`CLIENT_SECRET` とペアで設定／両方未設定も可）。 |
| `CLIENT_SECRET` | イントロスペクション認証のクライアントシークレット（`CLIENT_ID` とペアで設定／両方未設定も可）。 |
| `INTROSPECT_URL` | イントロスペクションエンドポイント URL。 |
| `INTROSPECT_CACHE_TTL_SEC` | キャッシュ TTL（秒、デフォルト: 30）。 |
| `INTROSPECT_CACHE_MAX_ENTRIES` | キャッシュ最大エントリ数（デフォルト: 10000）。 |
| `INTROSPECT_TIMEOUT_MS` | イントロスペクション HTTP タイムアウト（デフォルト: 5000）。 |

インジェクションモード:

| 環境変数 | 説明 |
| --- | --- |
| `INJECTION_PROVIDER_ORIGIN` | プロバイダーオリジン — `scheme://host[:port]`、パス／クエリ／フラグメント／userinfo 不可、http または https のみ（デフォルト: `http://localhost:3000`）。 |
| `INJECTION_CLIENT_ID` | **必須。** OAuth `client_id`。 |
| `INJECTION_SCOPE` | **必須。** OAuth `scope` 文字列（スペース区切り）。 |
| `INJECTION_SESSION_COOKIE_NAME` | セッションクッキー名（デフォルト: `connect.sid`）。 |
| `INJECTION_TOKEN_CACHE_TTL_SEC` | トークンキャッシュ TTL（秒、デフォルト: 60）。 |
| `INJECTION_TOKEN_CACHE_MAX_ENTRIES` | トークンキャッシュ最大エントリ数（デフォルト: 10000）。 |
| `INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC` | クロックドリフト安全マージン（秒、デフォルト: 5）。 |
| `INJECTION_TIMEOUT_MS` | プロバイダー HTTP タイムアウト（デフォルト: 5000）。 |

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 トークン発行。
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器。
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト。
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf option ベースの認可 interceptor。

## ライセンス

Apache License 2.0
