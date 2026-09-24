# auth.proxy

最終更新: 2026-09-24

[![CI](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.proxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/o3co/auth.proxy/graph/badge.svg)](https://codecov.io/gh/o3co/auth.proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（[認証・トークン発行](https://github.com/o3co/auth.provider) / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）の外に位置する任意の境界ゲートです。

クライアントとダウンストリームサービスの間に配置するリバースプロキシ。デプロイ時に `auth.mode` で選択した 2 つの排他モードのいずれかで動作する。

## 責務と役割

**役割。** auth.proxy は auth スタックの境界に置く*任意の*ゲートであり、3 層のいずれでもない。認証とトークン発行は [auth.provider](https://github.com/o3co/auth.provider)、認可判定は [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) が担い、その実施はダウンストリームサービス — あるいはその内部の [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — が行う。転送先のアップストリームを除けば、プロキシが呼び出すサービスは auth.provider だけである。

1 つのデプロイは 2 つのモードのいずれかで動作する:

- **[バリデーション](#バリデーションモードauthmode--validation)** — リソースサーバーの前段。受信した `Authorization: Bearer` トークンを auth.provider のイントロスペクションエンドポイントで検査し、結果をキャッシュし、リクエストを転送または拒否する。
- **[インジェクション](#インジェクションモードauthmode--injection)** — ブラウザ向け（BFF）サービスの前段。ブラウザのセッションクッキーを auth.provider のトークンエンドポイントでアクセストークンに交換し、`Authorization: Bearer` として注入する。ブラウザはトークンを保持しない。オプトインで、[外部 JWT をファーストパーティトークンに交換](#外部クレデンシャル交換authinjectionexchange)することもできる。

**担うもの:**

- リクエストごとの判定 — 転送・拒否・注入 — と、拒否応答のワイヤー上の形（バリデーションモードの RFC 6750 `WWW-Authenticate` チャレンジを含む）
- プロバイダーへの呼び出し: `POST /oauth/introspect`、セッショングラントと jwt-bearer 交換のための `POST /oauth/token`、およびプロキシ自身のクライアント認証（[`client_secret_basic`](#イントロスペクションのクライアント識別)）
- インスタンス単位・インメモリのプロバイダー応答キャッシュと、並行ミスを集約する single-flight
- 自身の設定スキーマ、ロギング、グレースフルシャットダウン

**担わないもの:**

- トークン発行、ログインとセッション、発行者の信頼、アイデンティティのマッピング、イントロスペクションが何を `active` と答えるか — [auth.provider](https://github.com/o3co/auth.provider)
- 認可判定 — [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — とその実施（ダウンストリームサービス側に残る）
- アップストリームに渡されたトークンの検証: アップストリームは引き続き自分で検証しなければならない（[受信 Authorization ヘッダー](#受信-authorization-ヘッダー)を参照）
- CSRF 保護（[CSRF の責務境界](#csrf-の責務境界)を参照）
- 発行済み・キャッシュ済みトークンへの失効の伝播（[アクセストークンの寿命と失効](#アクセストークンの寿命と失効)を参照）
- プロバイダーのレート制限予算（[プロバイダーのレート制限](#プロバイダーのレート制限)を参照）

**別サービスである理由。** スタックの[アーキテクチャ](https://github.com/o3co/auth/blob/develop/docs/architecture.md#migration-path)では、各コンポーネントは独立した HTTP サービスとして動作し、互いには設定上のエンドポイント URL だけでつながる。プロキシに必要なのはプロバイダーのエンドポイントだけで、アプリケーションコードを変えずに任意のトークン検証リバースプロキシ（例: Envoy の ext_authz）に置き換えられる。サービスの前段にいるからこそ、ダウンストリームサービスは自前で認証ロジックを実装せずに検証済みリクエストを受け取れ、インジェクションモードはアクセストークンをブラウザから遠ざけられる（OWASP Token Handler Pattern）。任意のコンポーネントなので、デプロイから外すこともできる。

**ソースマップ。** 各ソースディレクトリの README は、そのディレクトリの責務・役割・不変条件を述べる。個々のファイルが何をするかは、そのファイルのヘッダコメントにある。入口は [`src/README.md`](src/README.md)（ソースツリー）、[`config/README.md`](config/README.md)（設定スキーマ）、各モジュールの README — [`src/express`](src/express/README.md)、[`src/oauth`](src/oauth/README.md)、[`src/modes/injection`](src/modes/injection/README.md)、[`src/modes/validation`](src/modes/validation/README.md)。（いずれも英語のみ。）

## 動作モード

`auth.mode` は必須項目 — `"validation"` または `"injection"` を明示する必要がある。省略またはタイポがあるとプロキシは起動に失敗する。HOCON（`auth.mode = "validation"`）または `AUTH_MODE` 環境変数で設定する。

### バリデーションモード（`auth.mode = "validation"`）

受信した `Authorization: Bearer <token>` ヘッダーをプロバイダーのイントロスペクションエンドポイントで検証する。`Authorization` ヘッダーが無い、または空のリクエストはそのまま転送する（パブリックエンドポイントは引き続き到達可能）。`Authorization` が `Bearer <token>` 以外 — 別のスキーム、小文字の `bearer`、使えるトークンの無い `Bearer` — のリクエストは `400 Invalid Token Type` で拒否する（下のチャレンジ表を参照）。

フロー:

1. `Authorization: Bearer <token>` ヘッダーを検出（`Authorization` ヘッダーが無い、または空の場合はそのまま通過。それ以外の `Authorization` は `400`）。
2. トークンの SHA-256 ハッシュをキーにインメモリキャッシュを確認。
3. キャッシュミス時、プロバイダーの `POST /oauth/introspect` を呼び出す。そこからのリダイレクトは追従しない — エンドポイントは設定値である — ので、`502 Provider Configuration Error` を返す。同一トークンの並行ミスは、インジェクションモードと同じく 1 回のプロバイダー呼び出しに集約する（single-flight）。
4. `active: false` なら `401` を返し、`active: true` ならリクエストを転送する。

`VALIDATION_REALM` を設定しない場合と設定した場合（ここでは `api`）のチャレンジ:

| 拒否 | realm なし | realm あり |
| --- | --- | --- |
| `401`: プロキシが受け付けないアクセストークン（RFC 6750 §3） | `Bearer error="invalid_token"` | `Bearer realm="api", error="invalid_token"` |
| `400`: 読み取れないほど不正な `Bearer` クレデンシャル（`Bearer`、`Bearer  t`） | `Bearer error="invalid_request"` | `Bearer realm="api", error="invalid_request"` |
| `400`: 別の方式（`Basic …`、またはこのプロキシが受け付けない小文字の `bearer`） — §3.1 のとおりエラーコードなし | なし | `Bearer realm="api"` |

`500` と `502` にはチャレンジを付けない。呼び出し元のクレデンシャルについての表明ではなく、プロキシまたはプロバイダーの障害だからである。インジェクションモードはどの経路でもチャレンジを返さない。これは意図的で、その呼び出し元が持つのは Bearer トークンではなくセッションクッキーだからである。

知っておくべき限界が 2 つある。ブラウザはクロスオリジンではこのヘッダーを読めない — `WWW-Authenticate` は CORS セーフリストに含まれず、このプロキシは `Access-Control-Expose-Headers` を設定しない — ので、別オリジンの SPA に見えるのはステータスとボディだけである。また `invalid_token` はクライアントに新しいトークンを取得して再試行するよう促す（§3.1）が、後述の audience のケースではそれは役に立たない。`aud` がこのプロキシのクライアントを指していないためにプロバイダーが `active: false` と答えるトークンは、どれだけ新しくても同じように拒否される。

**ログ。** プロバイダーの失敗は、それが答えたリクエストごとに 1 回ログする — 1 回のプロバイダー呼び出しを共有したリクエスト（single-flight）はそれぞれがログする。リクエスト ID を `requestId`、エラーを `error` に入れ、次のいずれかのイベントとしてログする:

| イベント | レベル | 条件 |
| --- | --- | --- |
| `validation.token_unauthorized` | info | プロバイダーが呼び出し元のトークンについて `401` を返した（`401 Invalid Token`）。 |
| `validation.provider_config_error` | error | プロバイダーがプロキシ自身のクライアント資格情報を拒否した、またはエンドポイントがリダイレクトした（`502 Provider Configuration Error`）。 |
| `validation.provider_error` | error | それ以外のプロバイダーの失敗 — `5xx`、`429`、その他の `4xx`、イントロスペクション応答ではない応答、タイムアウト、ネットワークエラー（`502 Bad Gateway`）。 |
| `validation.unexpected_error` | error | それ以外に投げられたもの（`500 Internal Server Error`）。 |

プロバイダーが拒否したトークンはプロキシではなく呼び出し元の問題なので、`injection.session_unauthorized` と同じレベルでログし、error レベルの行に対するアラートは発火しない。`active: false` の応答はログしない。

JWT ローカル検証との比較:

- 失効したトークンを検出できる（イントロスペクションキャッシュ TTL の範囲内）。失効を検出できる検証方式はこれだけ（[アクセストークンの寿命と失効](#アクセストークンの寿命と失効)を参照）。
- イントロスペクション結果をキャッシュ（デフォルト 30 秒 TTL）し、プロバイダーの負荷を軽減。
- ダウンストリームサービスは認証ロジックを実装せずに検証済みリクエストを受け取れる。

バリデーションが扱うのは、束縛されていない（unbound）Bearer トークンである。`cnf` を含む応答、または `token_type` が Bearer 以外の応答は 401 で拒否する。イントロスペクションだけでは、受信リクエストについて DPoP 鍵やクライアント証明書の所持は検証できない。キャッシュエントリは応答に含まれる数値の `exp` を越えて生存せず、イントロスペクション中に期限切れになったトークンは即座に拒否する。`exp` が無い場合は設定した TTL を使い、不正な `exp` はプロバイダー応答のエラーとして扱う。TTL 0 はキャッシュを無効にする。

#### イントロスペクションのクライアント識別

`CLIENT_ID` / `CLIENT_SECRET` は任意項目だが、設定するかしないかで「プロバイダーがどのトークンを `active` と答えるか」が変わる。

**クライアント認証あり（両方設定）。** プロキシは HTTP Basic で `POST /oauth/introspect` に認証する。このときプロバイダーは、イントロスペクション対象トークンの audience を**呼び出し元クライアント自身の識別子に固定する**。`aud` がこのクライアントを指していないトークンは `active: false` で返る。エラーも診断情報も出ない — ワイヤー上では audience 不一致と偽造・期限切れトークンが区別できないため、実際には完全に有効なトークンに対してプロキシが `401` を返す。

したがって、プロキシが名乗るクライアントは、検証対象トークンの audience と紐付いている必要がある。方法は 2 つ:

- そのクライアントの `allowedAudiences` に該当 audience を登録する、または
- リソース URI 自体をそのクライアントの `client_id` にする。

`https://api.example.com/orders` の前段に置いたプロキシが無関係な `client_id` で認証している場合、RFC 8707 `resource` audience 付きで発行されたトークンにはすべて `401` を返す — resource indicator を使っている環境では、それは受け取る全リクエストを意味する。

**プロバイダーの `401` が意味するもの。** RFC 7662 §2.3 ではイントロスペクション要求は認証されるので、プロバイダーの `401` は、その要求が載せていたクレデンシャルに対する答えである。クライアント資格情報が無い場合、そのクレデンシャルは受信トークン*そのもの*であり、`401` は呼び出し元についての答え — `401 Invalid Token` — になる。資格情報がある場合、クレデンシャルはプロキシ自身の Basic ヘッダーであり、`401` が拒否したのは*プロキシ*で、呼び出し元のトークンは検査すらされていない。これは `502 Provider Configuration Error` とし、呼び出し元の `validation.token_unauthorized`（info）ではなく `validation.provider_config_error`（`introspect refused the proxy's client credentials`）として error でログする。直すのはオペレーターだからである。インジェクション経路も同じ状況を `provider_config_error` 502 として報告する — 交換は当初から、セッショングラントは #95 F47 以降。したがって設定を誤ったデプロイは、クライアントやゲートウェイが `401` よりも積極的に再試行するステータスを返し、それが[プロバイダーのレート制限](#プロバイダーのレート制限)で述べるインスタンス単位のイントロスペクション予算を消費する。直すべきは資格情報であって、再試行ポリシーではない。

> `auth.provider` 側の対応変更で、この固定は他のグラントがすでに使っている上限、すなわち `allowedAudiences ∪ {clientId}` に拡張される。それが入るまでは、クライアント認証ありの場合に active となるのは `aud` が呼び出し元の `client_id` と完全一致するトークンだけ。

**クライアント認証なし（両方未設定）。** プロキシは受信トークン自体をイントロスペクションの資格情報として提示する。`buildAuthHeader` が `Authorization: Bearer <token>` を出し、ボディにも同じトークンを載せる（プロバイダーは両者の一致を要求する）。この経路では呼び出し元クライアントが特定されないため、**audience の固定は適用されず**、どの audience 向けのトークンでもトークン自体の妥当性だけで判定される。

引き換えに失うもの:

- **プロバイダーが `aud` を検査しなくなる。** プロバイダーはその欠落を記録した上でクレームを返す。プロキシ側も `aud` を見ていないので、*別の*リソースサーバー向けに発行されたトークンがここを通ってしまう。アップストリームサービスが自分で `aud` を検査しないなら、これは confused deputy の穴になる — `CLIENT_ID` / `CLIENT_SECRET` を設定して audience を登録するか、アップストリームで `aud` を検査すること。
- **プロバイダーの監査ログにクライアント識別が残らない。**
- 署名・issuer・トークン種別・有効期限・失効 denylist は引き続き検査されるので、失効済み／偽造トークンは変わらず `active: false` になる。

レート制限はこの選択に影響されない — どちらでもプロキシの IP でキーイングされる（[プロバイダーのレート制限](#プロバイダーのレート制限)を参照）。

**予約文字を含む資格情報。** RFC 6749 §2.3.1 は、`client_id` とシークレットを `:` で連結して base64 する*前に*、それぞれを `application/x-www-form-urlencoded` でエンコードすることを要求する。そうしないと、どちらかに含まれる `:` が資格情報を誤った位置で再分割し、プロバイダーは設定したのとは別のペアを読むことになる。`buildAuthHeader` はこれを行っており（`clientSecretBasic`、`src/oauth/client-secret-basic.mts`）、プロバイダー側も対応する form-urlencoded デコーダで復号するため、予約文字を含む資格情報もバイト単位でラウンドトリップする。環境変数には生の値を設定すること（自分で事前エンコードしない）。

### インジェクションモード（`auth.mode = "injection"`）

受信したセッションクッキーを `Authorization: Bearer` トークンに変換してアップストリームへ送出する。OWASP OAuth 2.0 BCP Token Handler Pattern を実現 — ブラウザはアクセストークンを保持しない。

フロー:

1. `auth.injection.sessionCookieName` で指定されたセッションクッキーを抽出。
2. クッキーがない場合はリクエストをそのまま転送（認証が必要かどうかはサービス層が判断）。クッキーはあるが拒否された場合（[クッキー転送](#クッキー転送)を参照）も同じく転送するが、ログに残す。
3. キャッシュヒット時は、キャッシュした Bearer を注入して転送。
4. キャッシュミス時は、`grant_type=session` でプロバイダーの `POST /oauth/token` を呼び出してアクセストークンを取得。同一クッキーの並行ミスは 1 回のプロバイダー呼び出しに集約（single-flight）。
5. `Authorization: Bearer <token>` を注入してアップストリームに転送。

オプトインで、`Authorization: Bearer <JWT>` として提示された外部クレデンシャルをファーストパーティトークンに交換することもできる — [外部クレデンシャル交換](#外部クレデンシャル交換authinjectionexchange)を参照。

#### キャッシュ動作

- インメモリ、インスタンス単位。再起動やスケールアウト時はキャッシュがコールドになる。ロールアウト時のピーク負荷 ≈ `インスタンス数 × アクティブセッション数`。
- TTL: `min(auth.injection.tokenCache.ttlSeconds, provider.expires_in) - safetyMarginSeconds`。レスポンス到着時ではなくグラントリクエストを送った時点から数えるので、プロバイダーの応答が遅くてもエントリがトークンの有効期限を越えることはない。デフォルト 60 秒 − 5 秒の安全マージン。その時点より後にレスポンスが届いたグラントはキャッシュしない。
- キャッシュミスは、インスタンス全体で共有するレート制限バケットを消費する。TTL を下げる前に[プロバイダーのレート制限](#プロバイダーのレート制限)を読むこと。

#### アクセストークンの寿命と失効

JWT をオフライン検証するダウンストリームサービスにとって、プロバイダー側でのログアウト後のリプレイ露出を決めるのは**アクセストークン自身の寿命**である。トークンをイントロスペクションするダウンストリームサービスは、追跡セッションの無効化をより早く観測できる。

UserSession の追跡が設定されている場合、プロバイダーの `session` グラントは、ブラウザのユーザーと subject が一致する有効な追跡セッションを要求し、その `sid` をアクセストークンに刻む。リフレッシュトークンは発行しないので、リフレッシュトークンの `family_id` も無い。`POST /session/logout` は、ブラウザセッションを破棄する前に、追跡中の UserSession と関連するフェデレーション状態を無効化する。追跡セッションの無効化が成功すると、イントロスペクションは `active: false` を返し、userinfo はそのトークンを拒否する。ストアの失敗は、プロバイダーの運用手順書にあるとおりにログされる。

`tokenCache.ttlSeconds` が縛るのは、プロキシがすでに保持しているトークンを、プロバイダーに再確認せずに再注入し続ける時間である。値を下げれば、ログアウト済みセッションでの*新しい*リクエストがプロバイダーに到達するのが早くなる。認証されていないブラウザセッションには `401` が、ブラウザセッションは残っているが追跡レコードが無い・失効済み・不整合な場合には `400 invalid_grant` が返る。インジェクションプロキシはどちらの拒否も既存の `401 session_required` 応答に対応付ける。キャッシュ TTL を短くしても、すでに転送したトークンは回収されず、このプロキシが `/oauth/token` を呼ぶ回数が増える（[プロバイダーのレート制限](#プロバイダーのレート制限)を参照）。

運用上の指針:

- **BFF 構成ではプロバイダーのアクセストークン寿命を短く保つ。** `oauth.accessToken.expiresIn` がオフライン検証側でのリプレイ露出を縛る。クッキー → トークン交換はプロキシが担うので、寿命を短くしても、ブラウザセッションが有効な間に増えるのはグラント呼び出しだけである。
- **JWT をオフライン検証するダウンストリームサービスは、ログアウトを知る手段が一切ない。** オフライン検証が見るのは署名・`iss`・`aud`・`exp` だけで、そのどれもセッション終了で変化しない。そうしたサービスにとって失効ウィンドウ＝トークン寿命であり、短縮する手立てはない。
- **失効を観測できるのはイントロスペクションによる検証だけ。** リソースサーバー（あるいはその前段の `auth.mode = "validation"` プロキシ）が `POST /oauth/introspect` を呼べば、キャッシュミスのたびにプロバイダーへ問い合わせるので、プロバイダーが保証をやめたトークンはそのイントロスペクションキャッシュ TTL 以内に `active: false` となる。

バリデーションプロキシも、イントロスペクションキャッシュの各エントリをトークンの `exp` で上限付けする。イントロスペクション TTL を 0 にするとキャッシュを通らなくなり、同じトークンについて他のリクエストと並行していないリクエストは、それぞれ追跡セッションについてプロバイダーに問い合わせる。1 つのトークンに対する並行リクエストは引き続き 1 回の呼び出しを共有する — single-flight は TTL とは独立である — ので、バーストはその最初のリクエストに対するプロバイダーの答えを受け取る。この設定はバリデーションモードのもので、インジェクションプロキシのトークンキャッシュやオフライン検証側の動作は変えない。

#### スコープ境界

1 インスタンスは 1 つの OAuth スコープドメインを担当する。`auth.injection.clientId` と `auth.injection.scope` はデプロイ時に固定する。交換の `clientId`・`scope`・`audience`・`resource` も同様。複数のスコープドメインを扱う場合は、インスタンスを複数用意する。

プロバイダーの `400 invalid_grant` 応答は `401 session_required` に対応付ける。失効したセッションは、プロキシの設定障害に見えるのではなく、認証を促すことになる。その他のプロバイダー 400 応答は設定エラーとしての対応付けのままである。逆に、プロバイダーの `401` は `session_required` だが、`error` が `invalid_client` の場合は別である。それはプロキシ自身の `auth.injection.clientId` が拒否されたことを意味し、再ログインでは直らない設定障害なので、ログインを促すのではなく `502 provider_config_error` を返す。

どちらのインジェクション経路でも、成功したトークン応答とみなすのは `200` だけである（RFC 6749 §5.1）。それ以外の `2xx` は — トークンを含んでいても — `502 provider_unavailable`（「unexpected provider response」、メッセージにステータス付き）になる。

どちらのインジェクション経路でも、トークンエンドポイントからのリダイレクトは追従しない。メッセージにステータスを付けた `502 provider_config_error` になる。エンドポイントは設定値であり、追従したリダイレクトは正直に報告できない。同一オリジンへの `307` / `308` は POST 全体 — セッションクッキーとフォームボディ — を、何も設定していないパスへ再送し、そこでトークンが発行される。同じステータスでもクロスオリジンならクッキーが外されるので、プロバイダーは `401` を返し、呼び出し元はエンドポイントが設定を誤っているだけなのに再認証を求められる。`301` / `302` / `303` はグラントをボディの無い `GET` に変え、トークンエンドポイントはそれに `405` を返す。

#### CSRF の責務境界

プロキシは透過的な付加レイヤー。Bearer を注入するが、CSRF は強制しない。`SameSite=Lax` クッキー、同一オリジンデプロイ、アップストリームサービス側の CSRF 保護と組み合わせて使用する。「透過的」であることは逆方向にも効く — [受信 Authorization ヘッダー](#受信-authorization-ヘッダー)を参照。

#### 受信 Authorization ヘッダー

プロキシが受信 `Authorization` ヘッダーを上書きするのは、セッションクッキーから実際にトークンを取得できたリクエストだけ（`injection.authorization_override` としてログされる。値が空の受信 `Authorization:` も含む）。トークンを発行しなかった 2 経路 — セッションクッキーが無い場合と、クッキーが文法チェックで拒否された場合 — では、リクエストは**受信 `Authorization` ヘッダーを含めてそのまま**転送される。

**アップストリームサービスは渡されたトークンを自分で検証しなければならない。** 「プロキシからの接続に Bearer ヘッダーが載っていた」を「プロキシが発行したものだ」と読んではいけない。セッションクッキーを送らず自前の `Authorization` を送るだけのクライアントは、そのヘッダーを保ったままアップストリームに到達する。プロキシを経由しないリクエストと同じように、プロバイダーの鍵で署名・`iss`・`aud`・`exp` を検証するか、イントロスペクションすること。ヘッダーの出所は認証シグナルではない。

`auth.injection.stripInboundAuthorization`（`INJECTION_STRIP_INBOUND_AUTHORIZATION`）はこの曖昧さをプロキシ側で解消する。`true` にすると、プロキシがトークンを発行しなかったリクエストの受信 `Authorization` は転送前に削除され、`injection.inbound_authorization_stripped` として **warn** でログされる（リクエスト id と、`no_cookie` / `cookie_rejected` の `reason` 付き）。ヘッダーの値はログに出ない。これにより、アップストリームが Bearer ヘッダーを見るのはプロキシが載せたときだけになる。

デフォルトは `false` — このフラグ以前の全デプロイが動いていた素通し動作 — である。非ブラウザクライアント（サービスアカウント、モバイルアプリ）が同じプロキシ経由で意図的に自前のトークンを提示する構成では、その素通しが機能要件そのものだからである。プロキシがブラウザセッションだけを扱う場合、とりわけアップストリームの認可がヘッダーの出所に少しでも依存している場合に有効化する。これは多層防御であって、上の段落の代わりにはならない — クライアントが別経路でアップストリームに到達することは防げない。

`auth.injection.exchange.enabled` を有効にすると素通しそのものが無くなる。受信 `Authorization` ヘッダーはファーストパーティトークンに交換されるか、リクエストが拒否されるかのどちらかなので、`stripInboundAuthorization` が削除する対象は残らない — [外部クレデンシャル交換](#外部クレデンシャル交換authinjectionexchange)を参照。

#### クッキー転送

セッションのグラント呼び出しでプロバイダーに転送されるのは `auth.injection.sessionCookieName` で指定されたクッキーのみ。その他のクッキー（アナリティクス、CSRF トークン、サードパーティ）はプロバイダーに到達しない。

転送する値は RFC 6265 4.1.1 節の `cookie-value` 文法に従わなければならない: `cookie-octet`（空白・DQUOTE・カンマ・セミコロン・バックスラッシュを除く印字可能 US-ASCII）の並びで、全体をちょうど 1 組の DQUOTE で囲んでもよい。囲みの DQUOTE 1 組は受け付け、引用符ごとそのまま転送する（プロバイダー自身のクッキーパーサーに読み方を委ねる）。それ以外は拒否する — 値のどこかにある `,`・空白・`\`・制御文字・非 ASCII バイト、囲みの 1 組以外の位置にある DQUOTE（内部や対応の取れないもの）、または空の値。拒否したリクエストは、プロキシが発行した `Authorization` を付けずに転送し、プロバイダーは呼ばない。外部クレデンシャル交換が無効なら、クライアント自身の `Authorization` ヘッダーは `stripInboundAuthorization` が有効でない限りそのまま upstream に届く。交換が有効なら、受信した `Authorization` はクッキーより先に交換へ渡されるので、素通しされずに交換されるか拒否される（[受信 Authorization ヘッダー](#受信-authorization-ヘッダー)を参照）。`=` の直後の空白は値の一部とみなして拒否する。`;` 区切りの隣やヘッダー両端の SP / HTAB は区切りの余白として無視する。`;` はクッキーペアの区切りであり、値の一部にはならない。デフォルトのセッションストア（express-session の `connect.sid`、hex / base64url / JWT のセッション id）は常に文法に従う。

拒否されたクッキーは黙って捨てられない。クッキーをまったく含まないヘッダーは通常の匿名リクエストで、debug で `injection.no_cookie` をログする。クッキーを拒否される形で含むヘッダーは、**warn** で `injection.cookie_rejected` をログする（リクエスト id と、有限個の `reason` — `empty`（`sid=` / `sid=""`）、`quoting`（囲みの 1 組以外の位置にある DQUOTE）、`grammar`（`cookie-octet` 以外の文字） — 付き）。クッキーのバイト列はログに出ない。このイベントが継続的に出るなら、クライアントの誤動作か、文法外のセッションクッキーを発行しているプロバイダーを疑うこと。

ヘッダーに同じ名前が複数回現れる場合（RFC 6265 5.4 節により、ユーザーエージェントは同名のペアを 2 つ、パス順・作成時刻順に送ることがある）、最初の正しい形のペアを使う。その前にある不正なペアはスキップし、`action: "fallback"` 付きの `injection.cookie_rejected` としてログする。同名ペアがすべて不正な場合に限り、リクエストはプロキシが発行した `Authorization` なしで転送され、`action: "forward"` でログされる — `stripInboundAuthorization` が有効で削除すべき受信ヘッダーがあった場合は `action: "forward_stripped"`。`action` はこの行でも `injection.no_cookie` でも結果そのものの名前なので、`"forward"` だけをキーにしたクエリには削除されたリクエストは現れない。`sid=bad,val; sid=good` と `sid=good; sid=bad,val` はどちらも `good` を交換する。

クッキー名自体は起動時に検査する: `auth.injection.sessionCookieName` は RFC 6265 の `cookie-name`（RFC 9110 の `token`: `` !#$%&'*+-.^_`|~ ``、数字、英字の 1 文字以上）でなければならない。空白・`=`・その他のセパレータを含む名前は、そのキーを名指しする設定エラーになる。名前は同じ送出 `Cookie` ヘッダーに埋め込まれるからである。

#### 外部クレデンシャル交換（`auth.injection.exchange`）

オプトイン。`auth.injection.exchange.enabled = true` にすると、セッションクッキーの代わりに `Authorization: Bearer <JWT>` を提示したリクエストは、プロバイダーでファーストパーティのアクセストークンに交換され、そのトークンだけがアップストリームに届く。これにより、セッションベースのクライアントと、サポート対象の外部クレデンシャルを持つクライアントが、同じバックエンドのトークン検証・認可を受ける。無効（デフォルト）のときはこの節の内容は一切適用されず、インジェクションモードは上記のとおりに動作する。

**責務境界。** プロキシは**トークンエンドポイントのクライアント**である。クレデンシャルを取り出し、設定されたプロバイダーに提出し、成功結果をその有効範囲内でキャッシュし、受信 `Authorization` ヘッダーを発行されたトークンで置き換える。トークン検証、発行者（issuer）の信頼、アイデンティティのマッピング、交換の認可、トークン発行は [auth.provider](https://github.com/o3co/auth.provider) の責務である。どの外部発行者をどの条件で信頼するか — 発行者ごとの鍵、アルゴリズム、`allowedSubjects` / `allowedScopes` / `allowedAudiences` / `allowedClients` — の唯一の情報源は、プロバイダーの `AssertionIssuerRegistry` である。テナントの IdP を追加するのはプロバイダー側の登録作業であり、プロキシはその信頼設定を複製せず、単一発行者の制約も課さない。未検証の `iss` がトークンエンドポイント・鍵 URL・クライアントを選ぶことはない。プロキシは常に設定済みの `providerOrigin` を呼ぶ。

**グラント: RFC 7523 であって RFC 8693 ではない。** 交換は [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) の JWT-bearer 認可グラントである:

```http
POST /oauth/token
Authorization: Basic <client_secret_basic の資格情報>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>[&scope=…][&audience=…][&resource=…]
```

これは [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) のトークン交換（`subject_token` / `subject_token_type` を伴う `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`）ではなく、両者は互換ではない。プロバイダーが受け付けるのは、登録された発行者のプロファイルを満たすアサーション — プロバイダー自身を指す audience を含む — だけである。外部 IdP が無関係な API 向けに発行した JWT アクセストークンは、発行者が登録済みだというだけでは有効なアサーションにならない。一般の外部アクセストークンを交換するには、別途定義されたプロバイダーの検証・交換契約（RFC 8693）が必要であり、この経路が行うことではない。委任（delegation）も対象外である。jwt-bearer グラントは `act` クレームを発行せず、転送ヘッダーがその代わりになることもない。

**サポートするプロファイル。** アサーションの発行者についてプロバイダーのレジストリが認めるもの — 通常の RFC 7523 アサーションと、Identity Assertion JWT Authorization Grant（ID-JAG）プロファイル。プロキシは `assertion` をそのまま提出し、どのプロファイルが適用されるかはレジストリのエントリが決める。ID-JAG については、プロバイダーが次の 2 つの規則を強制し、プロキシの動作はそれを前提に組まれている:

- **クライアント束縛。** ID-JAG の `client_id` クレームは、トークンエンドポイントで認証したクライアント — プロキシの `auth.injection.exchange.clientId` — と一致しなければならない。IdP はそのクライアント向けに ID-JAG を発行する必要があり、他のクライアント向けに発行されたものは拒否される（`401 credential_rejected`）。
- **一回限りの使用。** 各 `jti` は一度しか受け付けられない。プロキシが自らアサーションを再提出することはない。リトライせず、失敗をキャッシュせず、同一の並行リクエストは 1 回の提出を共有する。成功結果はキャッシュエントリが失効するまで再利用される。その後 — あるいはキャッシュを別に持つ別のプロキシインスタンスで — 同じ ID-JAG を提示すると、プロバイダーがリプレイとして拒否し（`401 credential_rejected`）、クライアントは新しいアサーションを取得する必要がある。
- **キャッシュ期間中はリプレイ検査されない。** プロバイダーの一回限りの検査はアサーションの提出時に行われ、キャッシュヒットは何も提出しない。キャッシュ寿命の間は、同じアサーションを提示した者 — クライアント自身でも、それを入手した第三者でも — にキャッシュ済みトークンが渡る。その期間、アサーションはベアラークレデンシャルとして扱うこと。期間の上限は `tokenCache.ttlSeconds` である。

**クライアント認証。** 交換を有効にした場合、`clientId` と `clientSecret` は両方必須で、どちらかが欠けると起動に失敗する — `client_id` だけではクライアント認証にならない。プロキシは `client_secret_basic` で認証し、エンコードは[イントロスペクションのクライアント識別](#イントロスペクションのクライアント識別)で説明した RFC 6749 §2.3.1 のものを使う。プロバイダーには、`allowedGrantTypes` に `urn:ietf:params:oauth:grant-type:jwt-bearer` を含むコンフィデンシャルクライアントとして登録し、`allowedClients` を持つ発行者エントリにはすべてそのクライアントを列挙すること。要求する `scope`・`audience`・`resource` はデプロイ設定で固定され、設定したときだけ送られる。それらに何が許されるかはプロバイダーが強制し、どれを読むかもプロバイダーが決める（auth.provider の jwt-bearer グラントが読むのは `scope` と、`oauth.resourceIndicator.enabled` のときの `resource`）。

**リクエストの形。** 交換を有効にした場合:

| セッションクッキー | `Authorization` | 結果 |
| --- | --- | --- |
| なし | なし | 交換なしのときと同じく、`Authorization` なしで転送。 |
| あり | なし | 交換なしのときと同じく、セッショングラント。 |
| なし | `Bearer <JWT>` | 交換し、発行されたトークンでヘッダーを置き換える。 |
| なし | それ以外 — 別のスキーム、不透明トークン、不正な JWT、空の値 | `401 credential_unsupported`。プロバイダー呼び出しなし、転送なし。 |
| あり | 任意 | `400 credential_ambiguous`。プロバイダー呼び出しなし、転送なし。 |

「あり」とは、`Cookie` ヘッダーに `auth.injection.sessionCookieName` が含まれていることを指し、その値が[クッキーの文法チェック](#クッキー転送)を通るかどうかは問わない。他のクッキーは数えない。プロキシは 2 つのクレデンシャルのどちらかを選ぶことも、一方が失敗した後にもう一方へ切り替えることもしない。`Bearer` スキームは大文字小文字を区別せずに照合し、トークンはヘッダーとペイロードが JSON オブジェクトにデコードされる JWS コンパクト形式の JWT でなければならない。

**エラー。** セッション経路と同じ形 — `{ "error", "error_description" }`、`WWW-Authenticate` なし。いずれの場合も、元のクレデンシャルを転送することも、セッションにフォールバックすることもない。

| ステータス | `error` | 条件 |
| --- | --- | --- |
| 400 | `credential_ambiguous` | 同一リクエストにセッションクッキーと `Authorization` の両方がある。 |
| 401 | `credential_unsupported` | `Authorization` が `Bearer <JWT>` ではない。 |
| 401 | `credential_rejected` | `iss` が `allowedIssuers` に無い（プロバイダー呼び出しなし）、またはプロバイダーが `invalid_grant` を返した: 署名不正、期限切れ、audience 不一致、未登録の発行者、発行者が認めないクライアント、リプレイされた ID-JAG、解決できない subject。 |
| 403 | `exchange_not_permitted` | プロバイダーが `invalid_scope`・`invalid_target`・`unauthorized_client` を返した。 |
| 502 | `provider_config_error` | プロバイダーが `401`（プロキシ自身のクライアント認証）、その他の `400`、またはリダイレクトを返した（リダイレクトは追従しない）。 |
| 502 | `provider_unavailable` | プロバイダーの `5xx` または `429`、ネットワークエラー、タイムアウト、想定外のステータス。プロバイダーの `Retry-After` はそのまま透過する。 |
| 502 | `provider_invalid_response` | ボディが JSON オブジェクトでない（空、JSON でない、配列）か 64 KiB の上限を超える `200`、`access_token` の無い `200`、または `token_type` が `Bearer` 以外（例: `DPoP`）の `200`。 |

各結果は `injection.exchange_*` イベントとしてログされる（`exchange_fetch`、`exchange_success`、`exchange_cache_hit`、warn の `exchange_credential_ambiguous`、`reason` が `scheme` / `format` の `exchange_credential_unsupported`、`exchange_issuer_refused`、`exchange_rejected`、warn の `exchange_not_permitted`、error の `exchange_provider_config_error` / `exchange_provider_unavailable` / `exchange_provider_invalid_response`。プロバイダーの `error` コードがあれば付く）。アサーション、発行されたトークン、クライアントシークレット、未検証の `iss` はログに出ない。プロバイダーの `error` は RFC 6749 のエラーコードの形 — 空白なし、64 文字以内、JWT の形でない、アサーションやシークレットを含まない — のときだけそのままログされ、それ以外は `invalid_error_code` としてログされる。`error_description` はログに出ない。

**発行者プレフィルター。** `allowedIssuers`（デフォルトは空 = 無効）は、未検証の `iss` が一覧に無いアサーションを、プロバイダーを呼ぶ前に拒否する — デプロイが想定しない発行者からのトラフィックを落とすための手段である。交換の安全性に必須ではなく、プロバイダーの検証を置き換えることもない。一覧にある発行者もプロバイダーが完全に検証し、一覧に無いものはプロバイダーの拒否と同じ `credential_rejected` を受け取る。環境変数では `INJECTION_SCOPE` と同様に空白区切りで指定する。

**キャッシュ。** 成功した交換は、インスタンス単位のインメモリキャッシュに保持される。セッションキャッシュとは別だが、サイズと時間は同じ `auth.injection.tokenCache` の設定に従う。キーは、グラント種別・トークンエンドポイント・クライアント・`scope`・`audience`・`resource`・アサーションの SHA-256 なので、結果が別のアサーションや別の交換コンテキストに再利用されることはない。エントリの失効時刻は

`min(送信時刻 + tokenCache.ttlSeconds, 送信時刻 + プロバイダーの expires_in, アサーションの exp) − tokenCache.safetyMarginSeconds`

であり、送信時刻はトークンリクエストを送った瞬間である。`ttlSeconds` と `expires_in` はレスポンス到着時ではなくリクエスト時から数えるので、プロバイダーの応答が遅くてもエントリが発行トークンの有効期限を越えることはない。`exp` の無いアサーション、またはレスポンス到着時点ですでに失効しているはずのエントリはキャッシュしない。アサーションの `exp` は未検証のまま読むが、寿命を短くする方向にしか働かないので安全である。[auth.provider#588](https://github.com/o3co/auth.provider/pull/588) を含むプロバイダーは、jwt-bearer トークンの寿命もアサーションの残り有効期間で上限付けする。プロキシのキャッシュの上限はそれとは独立に成り立つ。

**失効の遅延。** 有効期限の上限は失効を伝播しない。外部クレデンシャル、その発行者の登録、あるいはプロキシのクライアントを失効させても、発行済みのトークン — オフライン検証側では自身の `exp` まで有効（[アクセストークンの寿命と失効](#アクセストークンの寿命と失効)を参照）— にも、キャッシュ済みの結果 — このプロキシが上記のキャッシュ寿命まで、プロバイダーに再確認せず注入し続ける — にも届かない。即時の失効が必要なデプロイには、明示的な仕組み — 発行トークンの短い寿命と、アップストリームでのイントロスペクションによる検証 — が必要である。

**バックエンドと CSRF。** アップストリームは渡されたトークンを引き続きすべて検証し — プロバイダーの鍵で署名・`iss`・`aud`・`exp` を検証するか、イントロスペクションする — 認可を実施すること。このプロキシから届いたヘッダーであること自体は何も証明しない。発行されたトークンがどの内部発行者・audience を持つかはプロバイダーの設定の帰結であり、プロキシが決めるものではない。セッション経路には引き続き [CSRF の責務境界](#csrf-の責務境界)で述べた CSRF 保護が必要である。交換のキャッシュミスは、セッショングラントと同じインスタンス単位の `/oauth/token` レート制限バケットを消費する（[プロバイダーのレート制限](#プロバイダーのレート制限)を参照）。

#### 脅威モデル — プロセスメモリ

アクティブなアクセストークンはプロセスメモリに保持される。プロキシプロセスのメモリに読み取りアクセスできる攻撃者は、キャッシュしたトークンをすべて抽出できる。標準的なホストセキュリティプラクティスを適用すること（コンテナ分離、最小イメージ、不要な `ptrace` ケーパビリティの排除）。

グレースフルシャットダウンはキャッシュを消去しない。ドレインはリスナーを閉じて処理中のリクエストの完了を `drainTimeoutMs` まで待つ（超過すると残りの接続を強制的に閉じる）だけで、キャッシュしたトークンはプロセスが終了するまでメモリに残る（#95 F21）。

### プロバイダーのレート制限

プロバイダーは OAuth エンドポイントのレート制限を**呼び出し元の IP アドレス**でキーイングする（バケットキーは `<endpoint>:ip:<ip>`）。このプロキシが行う呼び出しは、インスタンスごとに 1 つのバケットを共有する — インジェクションモードの `POST /oauth/token`（セッショングラントも交換も）も、バリデーションモードの `POST /oauth/introspect` も。ユーザー単位でもセッション単位でもトークン単位でもない。

プロバイダーのデフォルト予算は 60 リクエスト／60 秒なので、背後に何人の利用者がいようと、1 プロキシインスタンスは**キャッシュミスするリクエスト毎分およそ 60 件**で頭打ちになる。キャッシュヒットは無料、ミスは共有バケットを消費する。1 つのクレデンシャルに対する並行ミスは 1 回分しか消費しない。どちらのモードもそれらを 1 回のプロバイダー呼び出しに集約するので、同じトークンやクッキーを載せた並列リクエストのバーストのコストは 1 回である。

溢れ方はグレースフルではない。プロバイダーは `429` を返し、プロキシはそれを 5xx に変換する:

- インジェクションモード — 想定外のプロバイダー 4xx は `502 provider_unavailable` になる（プロバイダーの `Retry-After` はそのまま透過する）。
- バリデーションモード — プロバイダーの `429` は `502 Bad Gateway` になる。`401`（トークンについての `401 Invalid Token`、またはプロキシ自身のクライアントについての `502 Provider Configuration Error`）とリダイレクト（`502 Provider Configuration Error`）を除く、そこでのすべてのプロバイダー障害と同じである。

つまり症状は「負荷時にプロキシの 5xx が急増する」であり、そこにレート制限と読み取れる情報は無い。プロバイダー障害と決めつける前に、プロバイダー側のレート制限イベントを確認すること。

回避策をプロキシ側で組むのではなく、プロバイダー側で予算を引き上げる:

- 単一プロセスの memory アダプターなら `memoryRateLimiter.limits { token { limit, windowSeconds } }` および `{ introspect { … } }`。
- `rateLimiter.adapter = "redis"` なら `redisRateLimiter.limits { … }`（および `redisRateLimiter.defaultLimit`）。memory アダプターのカウンターはレプリカごとに分裂するので、マルチレプリカ構成ではいずれにせよ redis が必要になる。

事態を悪化させる 2 点:

- **`tokenCache.ttlSeconds` / `INTROSPECT_CACHE_TTL_SEC` を下げるとミスが増える。** TTL が短いほど、同じトラフィックが同じ 60/60 秒バケットを多く消費する。失効への効果はインジェクションとバリデーションで異なる — [アクセストークンの寿命と失効](#アクセストークンの寿命と失効)を参照。
- **スケールアウトすると、各インスタンスが自前のバケットと自前のコールドキャッシュを持つ。** そのためロールアウトは `インスタンス数 × アクティブセッション数` のプロバイダー呼び出しを、まさにバケットが最速で消費される瞬間に発生させる。複数インスタンスが 1 つの NAT やイグレスゲートウェイの背後にある場合は、逆に同一送信元 IP として 1 バケットを共有することになる。

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
| `LOG_LEVEL` | pino のログレベル — `trace`・`debug`・`info`・`warn`・`error`・`fatal`・`silent`（デフォルト: `info`）。HOCON 設定を経由せず、ロガー生成時に環境変数から直接読む。出力は stdout への NDJSON。どちらのモードでも、リクエストに関する行 — `incoming request` と各判定 — はリクエスト ID を `requestId` に、`injection.*` または `validation.*` という名前の `event` を持つ。 |

バリデーションモード:

| 環境変数 | 説明 |
| --- | --- |
| `CLIENT_ID` | イントロスペクション認証のクライアント ID（任意。`CLIENT_SECRET` とペアで設定する）。 |
| `CLIENT_SECRET` | イントロスペクション認証のクライアントシークレット（任意。`CLIENT_ID` とペアで設定する）。 |
| `INTROSPECT_URL` | イントロスペクションエンドポイント URL。userinfo を含まない絶対 `http(s)` URL であること。それ以外はキー名を示して起動時に失敗する — プロキシは URL ではなく `CLIENT_ID` / `CLIENT_SECRET` で認証する。 |
| `VALIDATION_REALM` | `WWW-Authenticate` の RFC 6750 `realm`（任意。印字可能 ASCII で 256 文字以内、`"`・`\`・前後の空白を含まない）。未設定なら、別の認証方式を使ったリクエストにはチャレンジを返さない。 |
| `INTROSPECT_CACHE_TTL_SEC` | キャッシュ TTL（秒、デフォルト: 30）。 |
| `INTROSPECT_CACHE_MAX_ENTRIES` | キャッシュ最大エントリ数（デフォルト: 10000）。 |
| `INTROSPECT_TIMEOUT_MS` | イントロスペクション HTTP タイムアウト（デフォルト: 5000）。 |

インジェクションモード:

| 環境変数 | 説明 |
| --- | --- |
| `INJECTION_PROVIDER_ORIGIN` | プロバイダーオリジン — `scheme://host[:port]`、パス／クエリ／フラグメント／userinfo 不可、http または https のみ（デフォルト: `http://localhost:3000`）。 |
| `INJECTION_CLIENT_ID` | **必須。** OAuth `client_id`。 |
| `INJECTION_SCOPE` | **必須。** OAuth `scope` 文字列（スペース区切り）。 |
| `INJECTION_SESSION_COOKIE_NAME` | セッションクッキー名（デフォルト: `connect.sid`）。RFC 6265 `cookie-name`（RFC 9110 token）であること — 空白・`=`・その他のセパレータは起動時に失敗する。 |
| `INJECTION_STRIP_INBOUND_AUTHORIZATION` | `"true"` / `"false"`（デフォルト: `false`）。プロキシがトークンを発行しなかったリクエストの受信 `Authorization` ヘッダーを削除する。それ以外の値は起動時に失敗する。[受信 Authorization ヘッダー](#受信-authorization-ヘッダー)を参照。 |
| `INJECTION_TOKEN_CACHE_TTL_SEC` | トークンキャッシュ TTL（秒、デフォルト: 60）。セッションキャッシュと交換キャッシュの両方に適用。 |
| `INJECTION_TOKEN_CACHE_MAX_ENTRIES` | トークンキャッシュ最大エントリ数（デフォルト: 10000）。セッションキャッシュと交換キャッシュそれぞれに適用。 |
| `INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC` | クロックドリフト安全マージン（秒、デフォルト: 5）。両方のキャッシュに適用。 |
| `INJECTION_TIMEOUT_MS` | プロバイダー HTTP タイムアウト（デフォルト: 5000）。セッショングラントと交換の両方に適用。 |
| `INJECTION_EXCHANGE_ENABLED` | `"true"` / `"false"`（デフォルト: `false`）。受信 `Authorization: Bearer <JWT>` をプロバイダーで交換する（RFC 7523 jwt-bearer）。それ以外の値は起動時に失敗する。[外部クレデンシャル交換](#外部クレデンシャル交換authinjectionexchange)を参照。 |
| `INJECTION_EXCHANGE_CLIENT_ID` | 交換でプロキシが名乗る `client_id`。交換を有効にした場合は**必須**。 |
| `INJECTION_EXCHANGE_CLIENT_SECRET` | そのクライアントシークレット（`client_secret_basic`）。交換を有効にした場合は**必須**。 |
| `INJECTION_EXCHANGE_SCOPE` | 交換で送る `scope`（スペース区切り、任意）。 |
| `INJECTION_EXCHANGE_AUDIENCE` | 交換で送る `audience`（任意）。 |
| `INJECTION_EXCHANGE_RESOURCE` | 交換で送る RFC 8707 `resource`（任意）。 |
| `INJECTION_EXCHANGE_ALLOWED_ISSUERS` | 未検証の `iss` に対する任意のプレフィルター。空白区切りのリスト（デフォルト: 空 = 無効）。 |

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 トークン発行。
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器。
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト。
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf option ベースの認可 interceptor。

## ライセンス

Apache License 2.0
