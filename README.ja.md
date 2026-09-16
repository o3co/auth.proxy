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

- 失効したトークンを検出できる（イントロスペクションキャッシュ TTL の範囲内）。失効を観測できる検証方式はこれだけ（「アクセストークンの寿命と失効」を参照）。
- イントロスペクション結果をキャッシュ（デフォルト 30 秒 TTL）し、プロバイダーの負荷を軽減。
- ダウンストリームサービスは認証ロジックを実装せずに検証済みリクエストを受け取れる。

#### イントロスペクションのクライアント識別

`CLIENT_ID` / `CLIENT_SECRET` は任意項目だが、設定するかしないかで「プロバイダーがどのトークンを `active` と答えるか」が変わる。

**クライアント認証あり（両方設定）。** プロキシは HTTP Basic で `POST /oauth/introspect` に認証する。このときプロバイダーは、イントロスペクション対象トークンの audience を**呼び出し元クライアント自身の識別子に固定する**。`aud` がこのクライアントを指していないトークンは `active: false` で返る。エラーも診断情報も出ない — ワイヤー上では audience 不一致と偽造・期限切れトークンが区別できないため、実際には完全に有効なトークンに対してプロキシが `401` を返す。

したがって、プロキシが名乗るクライアントは、検証対象トークンの audience と紐付いている必要がある。方法は 2 つ:

- そのクライアントの `allowedAudiences` に該当 audience を登録する、または
- リソース URI 自体をそのクライアントの `client_id` にする。

`https://api.example.com/orders` の前段に置いたプロキシが無関係な `client_id` で認証している場合、RFC 8707 `resource` audience 付きで発行されたトークンにはすべて `401` を返す — resource indicator を使っている環境では、それは受け取る全リクエストを意味する。

> `auth.provider` 側の対応変更で、この固定は他のグラントがすでに使っている上限、すなわち `allowedAudiences ∪ {clientId}` に拡張される。それが入るまでは、クライアント認証ありの場合に active となるのは `aud` が呼び出し元の `client_id` と完全一致するトークンだけ。

**クライアント認証なし（両方未設定）。** プロキシは受信トークン自体をイントロスペクションの資格情報として提示する。`buildAuthHeader` が `Authorization: Bearer <token>` を出し、ボディにも同じトークンを載せる（プロバイダーは両者の一致を要求する）。この経路では呼び出し元クライアントが特定されないため、**audience の固定は適用されず**、どの audience 向けのトークンでもトークン自体の妥当性だけで判定される。

引き換えに失うもの:

- **プロバイダーが `aud` を検査しなくなる。** プロバイダーはその欠落を記録した上でクレームを返す。プロキシ側も `aud` を見ていないので、*別の*リソースサーバー向けに発行されたトークンがここを通ってしまう。アップストリームサービスが自分で `aud` を検査しないなら、これは実際の confused deputy の穴になる — `CLIENT_ID` / `CLIENT_SECRET` を設定して audience を登録するか、アップストリームで `aud` を検査すること。
- **プロバイダーの監査ログにクライアント識別が残らない。**
- 署名・issuer・トークン種別・有効期限・失効 denylist は引き続き検査されるので、失効済み／偽造トークンは変わらず `active: false` になる。

レート制限はこの選択に影響されない — どちらでもプロキシの IP でキーイングされる（「プロバイダーのレート制限」を参照）。

**予約文字を含む資格情報。** RFC 6749 §2.3.1 は、`client_id` とシークレットを `:` で連結して base64 する*前に*、それぞれを `application/x-www-form-urlencoded` でエンコードすることを要求する。そうしないと、どちらかに含まれる `:` が資格情報を誤った位置で再分割し、プロバイダーは設定したのとは別のペアを読むことになる。`buildAuthHeader` はこれを行っており（`clientSecretBasic`、`src/oauth/client-secret-basic.mts`）、プロバイダー側も対応する form-urlencoded デコーダで復号するため、予約文字を含む資格情報もバイト単位でラウンドトリップする。環境変数には生の値を設定すること（自分で事前エンコードしない）。

### インジェクションモード（`auth.mode = "injection"`）

受信したセッションクッキーを `Authorization: Bearer` トークンに変換してアップストリームへ送出する。OWASP OAuth 2.0 BCP Token Handler Pattern を実現 — ブラウザはアクセストークンを保持しない。

フロー:

1. `auth.injection.sessionCookieName` で指定されたセッションクッキーを抽出。
2. クッキーがない場合はリクエストをそのまま転送（認証が必要かどうかはサービス層が判断）。
3. キャッシュヒット時は、キャッシュした Bearer を注入して転送。
4. キャッシュミス時は、`grant_type=session` でプロバイダーの `POST /oauth/token` を呼び出してアクセストークンを取得。同一クッキーの並行ミスは 1 回のプロバイダー呼び出しに集約（single-flight）。
5. `Authorization: Bearer <token>` を注入してアップストリームに転送。

オプトインで、`Authorization: Bearer <JWT>` として提示された外部クレデンシャルをファーストパーティトークンに交換することもできる — 「外部クレデンシャル交換」を参照。

#### キャッシュ動作

- インメモリ、インスタンス単位。再起動やスケールアウト時はキャッシュがコールドになる。ロールアウト時のピーク負荷 ≈ `インスタンス数 × アクティブセッション数`。
- TTL: `min(auth.injection.tokenCache.ttlSeconds, provider.expires_in) - safetyMarginSeconds`。レスポンス到着時ではなくグラントリクエストを送った時点から数えるので、プロバイダーの応答が遅くてもエントリがトークンの有効期限を越えることはない。デフォルト 60 秒 − 5 秒の安全マージン。その時点より後にレスポンスが届いたグラントはキャッシュしない。
- キャッシュミスは、インスタンス全体で共有するレート制限バケットを消費する。TTL を下げる前に「プロバイダーのレート制限」を読むこと。

#### アクセストークンの寿命と失効

プロバイダー側でログアウトした後の露出を決めるのは、プロキシのキャッシュ TTL ではなく**アクセストークン自身の寿命**である。

`session` グラントが発行するのは素のアクセストークンで、プロバイダーは `sid` もリフレッシュトークンの `family_id` も刻まない。そして `POST /session/logout` はブラウザセッションを破棄するだけである。したがって、ログアウト前にプロキシが注入したトークンは、`exp` — プロバイダーの `oauth.accessToken.defaultExpiresIn`（旧 `expiresIn`、非推奨エイリアスとして引き続き受け付ける）、デフォルト `3600` 秒 — までダウンストリームのリソースサーバーすべてで有効なままになる。プロキシのキャッシュは関係しない。アップストリームサービスがすでに保持しているコピーはログアウト前に渡ったものであり、回収できない。そこから先に転送されたコピーも同じである。

`tokenCache.ttlSeconds` が縛るのはもっと狭い範囲、すなわち「プロキシがすでに保持しているトークンを、プロバイダーに再確認せずに何秒間再注入し続けるか」である。値を下げれば、ログアウト済みセッションでの*新しい*リクエストがプロバイダーに到達し、グラントから `401` を受け取るのが早くなる。しかし、すでに流通しているトークンを短くも無効にも回収もしないうえ、このプロキシが `/oauth/token` を叩く回数を増やす（「プロバイダーのレート制限」を参照）。

運用上の指針:

- **BFF 構成ではプロバイダーのアクセストークン寿命を短く保つ。** 実際の失効ウィンドウは `oauth.accessToken.defaultExpiresIn`（旧 `expiresIn`）である。クッキー → トークン交換はプロキシが担うので、寿命を短くしても増えるのはグラント呼び出しだけで、利用者に再ログインを強いることにはならない。
- **JWT をオフライン検証するダウンストリームサービスは、ログアウトを知る手段が一切ない。** オフライン検証が見るのは署名・`iss`・`aud`・`exp` だけで、そのどれもセッション終了で変化しない。そうしたサービスにとって失効ウィンドウ＝トークン寿命であり、短縮する手立てはない。
- **失効を観測できるのはイントロスペクションによる検証だけ。** リソースサーバー（あるいはその前段の `auth.mode = "validation"` プロキシ）が `POST /oauth/introspect` を呼べば、キャッシュミスのたびにプロバイダーへ問い合わせるので、プロバイダーが保証をやめたトークンはそのイントロスペクションキャッシュ TTL 以内に `active: false` となる。

`auth.provider` 側の対応変更で、session グラントのトークンに `sid` が刻まれ、プロバイダー自身のイントロスペクション／userinfo エンドポイントが、セッション破棄済みトークンを拒否するようになる。これにより上記の後ろ 2 項目の差がはっきりする — 変更後はイントロスペクションする検証側はログアウトを認識でき、オフライン JWT 検証側は依然として認識できない。1 項目目は変わらない。オフライン検証側の露出を縛るのは、どちらにせよアクセストークンの寿命である。

#### スコープ境界

1 インスタンスは 1 つの OAuth スコープドメインを担当する。`auth.injection.clientId` と `auth.injection.scope` はデプロイ時に固定する。交換の `clientId`・`scope`・`audience`・`resource` も同様。複数のスコープドメインを扱う場合は、インスタンスを複数用意する。

#### CSRF の責務境界

プロキシは透過的な付加レイヤー。Bearer を注入するが、CSRF は強制しない。`SameSite=Lax` クッキー、同一オリジンデプロイ、アップストリームサービス側の CSRF 保護と組み合わせて使用する。「透過的」であることは逆方向にも効く — 「受信 Authorization ヘッダー」を参照。

#### 受信 Authorization ヘッダー

プロキシが受信 `Authorization` ヘッダーを上書きするのは、セッションクッキーから実際にトークンを取得できたリクエストだけ（`injection.authorization_override` としてログされる）。トークンを発行しなかった 2 経路 — セッションクッキーが無い場合と、クッキーが文法チェックで拒否された場合 — では、リクエストは**受信 `Authorization` ヘッダーを含めてそのまま**転送される。

**アップストリームサービスは渡されたトークンを自分で検証しなければならない。** 「プロキシからの接続に Bearer ヘッダーが載っていた」を「プロキシが発行したものだ」と読んではいけない。セッションクッキーを送らず自前の `Authorization` を送るだけのクライアントは、そのヘッダーを保ったままアップストリームに到達する。プロキシを経由しないリクエストと同じように、プロバイダーの鍵で署名・`iss`・`aud`・`exp` を検証するか、イントロスペクションすること。ヘッダーの出所は認証シグナルではない。

`auth.injection.stripInboundAuthorization`（`INJECTION_STRIP_INBOUND_AUTHORIZATION`）はこの曖昧さをプロキシ側で解消する。`true` にすると、プロキシがトークンを発行しなかったリクエストの受信 `Authorization` は転送前に削除され、`injection.inbound_authorization_stripped` として **warn** でログされる（リクエスト id と、`no_cookie` / `cookie_rejected` の `reason` 付き）。ヘッダーの値はログに出ない。これにより、アップストリームが Bearer ヘッダーを見るのはプロキシが載せたときだけになる。

デフォルトは `false` — このフラグ以前の全デプロイが動いていた素通し動作 — である。非ブラウザクライアント（サービスアカウント、モバイルアプリ）が同じプロキシ経由で意図的に自前のトークンを提示する構成では、その素通しが機能要件そのものだからである。プロキシがブラウザセッションだけを扱う場合、とりわけアップストリームの認可がヘッダーの出所に少しでも依存している場合に有効化する。これは多層防御であって、上の段落の代わりにはならない — クライアントが別経路でアップストリームに到達することは防げない。

`auth.injection.exchange.enabled` を有効にすると素通しそのものが無くなる。受信 `Authorization` ヘッダーはファーストパーティトークンに交換されるか、リクエストが拒否されるかのどちらかなので、`stripInboundAuthorization` が削除する対象は残らない — 「外部クレデンシャル交換」を参照。

#### クッキー転送

セッションのグラント呼び出しでプロバイダーに転送されるのは `auth.injection.sessionCookieName` で指定されたクッキーのみ。その他のクッキー（アナリティクス、CSRF トークン、サードパーティ）はプロバイダーに到達しない。

#### 外部クレデンシャル交換（`auth.injection.exchange`）

オプトイン。`auth.injection.exchange.enabled = true` にすると、セッションクッキーの代わりに `Authorization: Bearer <JWT>` を提示したリクエストは、プロバイダーでファーストパーティのアクセストークンに交換され、そのトークンだけがアップストリームに届く。これにより、セッションベースのクライアントと、サポート対象の外部クレデンシャルを持つクライアントが、同じバックエンドのトークン検証・認可モデルを使える。無効（デフォルト）のときはこの節の内容は一切適用されず、インジェクションモードは上記のとおりに動作する。

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

**クライアント認証。** 交換を有効にした場合、`clientId` と `clientSecret` は両方必須で、どちらかが欠けると起動に失敗する — `client_id` だけではクライアント認証にならない。プロキシは `client_secret_basic` で認証し、エンコードは「イントロスペクションのクライアント識別」で説明した RFC 6749 §2.3.1 のものを使う。プロバイダーには、`allowedGrantTypes` に `urn:ietf:params:oauth:grant-type:jwt-bearer` を含むコンフィデンシャルクライアントとして登録し、`allowedClients` を持つ発行者エントリにはすべてそのクライアントを列挙すること。要求する `scope`・`audience`・`resource` はデプロイ設定で固定され、設定したときだけ送られる。それらに何が許されるかはプロバイダーが強制し、どれを読むかもプロバイダーが決める（auth.provider の jwt-bearer グラントが読むのは `scope` と、`oauth.resourceIndicator.enabled` のときの `resource`）。

**リクエストの形。** 交換を有効にした場合:

| セッションクッキー | `Authorization` | 結果 |
| --- | --- | --- |
| なし | なし | 交換なしのときと同じく、`Authorization` なしで転送。 |
| あり | なし | 交換なしのときと同じく、セッショングラント。 |
| なし | `Bearer <JWT>` | 交換し、発行されたトークンでヘッダーを置き換える。 |
| なし | それ以外 — 別のスキーム、不透明トークン、不正な JWT、空の値 | `401 credential_unsupported`。プロバイダー呼び出しなし、転送なし。 |
| あり | 任意 | `400 credential_ambiguous`。プロバイダー呼び出しなし、転送なし。 |

「あり」とは、`Cookie` ヘッダーに `auth.injection.sessionCookieName` が含まれていることを指し、その値が「クッキー転送」の文法チェックを通るかどうかは問わない。他のクッキーは数えない。プロキシは 2 つのクレデンシャルのどちらかを選ぶことも、一方が失敗した後にもう一方へ切り替えることもしない。`Bearer` スキームは大文字小文字を区別せずに照合し、トークンはヘッダーとペイロードが JSON オブジェクトにデコードされる JWS コンパクト形式の JWT でなければならない。

**エラー。** セッション経路と同じ形 — `{ "error", "error_description" }`、`WWW-Authenticate` なし。いずれの場合も、元のクレデンシャルを転送することも、セッションにフォールバックすることもない。

| ステータス | `error` | 条件 |
| --- | --- | --- |
| 400 | `credential_ambiguous` | 同一リクエストにセッションクッキーと `Authorization` の両方がある。 |
| 401 | `credential_unsupported` | `Authorization` が `Bearer <JWT>` ではない。 |
| 401 | `credential_rejected` | `iss` が `allowedIssuers` に無い（プロバイダー呼び出しなし）、またはプロバイダーが `invalid_grant` を返した: 署名不正、期限切れ、audience 不一致、未登録の発行者、発行者が認めないクライアント、リプレイされた ID-JAG、解決できない subject。 |
| 403 | `exchange_not_permitted` | プロバイダーが `invalid_scope`・`invalid_target`・`unauthorized_client` を返した。 |
| 502 | `provider_config_error` | プロバイダーが `401`（プロキシ自身のクライアント認証）、その他の `400`、またはリダイレクトを返した（リダイレクトは追従しない）。 |
| 502 | `provider_unavailable` | プロバイダーの `5xx` または `429`、ネットワークエラー、タイムアウト、想定外のステータス。プロバイダーの `Retry-After` はそのまま透過する。 |
| 502 | `provider_invalid_response` | `access_token` の無い `200`、または `token_type` が `Bearer` 以外（例: `DPoP`）の `200`。 |

各結果は `injection.exchange_*` イベントとしてログされる（`exchange_fetch`、`exchange_success`、`exchange_cache_hit`、warn の `exchange_credential_ambiguous`、`reason` が `scheme` / `format` の `exchange_credential_unsupported`、`exchange_issuer_refused`、`exchange_rejected`、warn の `exchange_not_permitted`、error の `exchange_provider_config_error` / `exchange_provider_unavailable` / `exchange_provider_invalid_response`。プロバイダーの `error` コードがあれば付く）。アサーション、発行されたトークン、クライアントシークレット、未検証の `iss` はログに出ない。プロバイダーの `error` は RFC 6749 のエラーコードの形 — 空白なし、64 文字以内、JWT の形でない、アサーションやシークレットを含まない — のときだけそのままログされ、それ以外は `invalid_error_code` としてログされる。`error_description` はログに出ない。

**発行者プレフィルター。** `allowedIssuers`（デフォルトは空 = 無効）は、未検証の `iss` が一覧に無いアサーションを、プロバイダーを呼ぶ前に拒否する — デプロイが想定しない発行者からのトラフィックを落とすための手段である。交換の安全性に必須ではなく、プロバイダーの検証を置き換えることもない。一覧にある発行者もプロバイダーが完全に検証し、一覧に無いものはプロバイダーの拒否と同じ `credential_rejected` を受け取る。環境変数では `INJECTION_SCOPE` と同様に空白区切りで指定する。

**キャッシュ。** 成功した交換は、インスタンス単位のインメモリキャッシュに保持される。セッションキャッシュとは別だが、サイズと時間は同じ `auth.injection.tokenCache` の設定に従う。キーは、グラント種別・トークンエンドポイント・クライアント・`scope`・`audience`・`resource`・アサーションの SHA-256 なので、結果が別のアサーションや別の交換コンテキストに再利用されることはない。エントリの失効時刻は

`min(送信時刻 + tokenCache.ttlSeconds, 送信時刻 + プロバイダーの expires_in, アサーションの exp) − tokenCache.safetyMarginSeconds`

であり、送信時刻はトークンリクエストを送った瞬間である。`ttlSeconds` と `expires_in` はレスポンス到着時ではなくリクエスト時から数えるので、プロバイダーの応答が遅くてもエントリが発行トークンの有効期限を越えることはない。`exp` の無いアサーション、またはレスポンス到着時点ですでに失効しているはずのエントリはキャッシュしない。アサーションの `exp` は未検証のまま読むが、寿命を短くする方向にしか働かないので安全である。プロバイダーも jwt-bearer トークンの寿命をアサーションの残り有効期間で上限付けするが、プロキシのキャッシュの上限はそれとは独立に成り立つ。

**失効の遅延。** 有効期限の上限は失効を伝播しない。外部クレデンシャル、その発行者の登録、あるいはプロキシのクライアントを失効させても、発行済みのトークン — オフライン検証側では自身の `exp` まで有効（「アクセストークンの寿命と失効」を参照）— にも、キャッシュ済みの結果 — このプロキシが上記のキャッシュ寿命まで、プロバイダーに再確認せず注入し続ける — にも届かない。即時の失効が必要なデプロイには、明示的な仕組み — 発行トークンの短い寿命と、アップストリームでのイントロスペクションによる検証 — が必要である。

**バックエンドと CSRF。** アップストリームは渡されたトークンを引き続きすべて検証し — プロバイダーの鍵で署名・`iss`・`aud`・`exp` を検証するか、イントロスペクションする — 認可を実施すること。このプロキシから届いたヘッダーであること自体は何も証明しない。発行されたトークンがどの内部発行者・audience を持つかはプロバイダーの設定の帰結であり、プロキシの不変条件ではない。セッション経路には引き続き「CSRF の責務境界」で述べた CSRF 保護が必要である。交換のキャッシュミスは、セッショングラントと同じインスタンス単位の `/oauth/token` レート制限バケットを消費する（「プロバイダーのレート制限」を参照）。

#### 脅威モデル — プロセスメモリ

アクティブなアクセストークンはプロセスメモリに保持される。プロキシプロセスのメモリに読み取りアクセスできる攻撃者は、キャッシュしたトークンをすべて抽出できる。標準的なホストセキュリティプラクティスを適用すること（コンテナ分離、最小イメージ、不要な `ptrace` ケーパビリティの排除）。

### プロバイダーのレート制限

プロバイダーは OAuth エンドポイントのレート制限を**呼び出し元の IP アドレス**でキーイングする（バケットキーは `<endpoint>:ip:<ip>`）。このプロキシが行う呼び出しは、インスタンスごとに 1 つのバケットを共有する — インジェクションモードの `POST /oauth/token`（セッショングラントも交換も）も、バリデーションモードの `POST /oauth/introspect` も。ユーザー単位でもセッション単位でもトークン単位でもない。

プロバイダーのデフォルト予算は 60 リクエスト／60 秒なので、背後に何人の利用者がいようと、1 プロキシインスタンスは**キャッシュミスするリクエスト毎分およそ 60 件**で頭打ちになる。キャッシュヒットは無料、ミスは共有バケットを消費する。

溢れ方はグレースフルではない。プロバイダーは `429` を返し、プロキシはそれを 5xx に変換する:

- インジェクションモード — 想定外のプロバイダー 4xx は `502 provider_unavailable` になる（プロバイダーの `Retry-After` はそのまま透過する）。
- バリデーションモード — 401 以外のイントロスペクション失敗は `500 Internal Server Error` になる。

つまり症状は「負荷時にプロキシの 5xx が急増する」であり、そこにレート制限と読み取れる情報は無い。プロバイダー障害と決めつける前に、プロバイダー側のレート制限イベントを確認すること。

回避策をプロキシ側で組むのではなく、プロバイダー側で予算を引き上げる:

- 単一プロセスの memory アダプターなら `memoryRateLimiter.limits { token { limit, windowSeconds } }` および `{ introspect { … } }`。
- `rateLimiter.adapter = "redis"` なら `redisRateLimiter.limits { … }`（および `redisRateLimiter.defaultLimit`）。memory アダプターのカウンターはレプリカごとに分裂するので、マルチレプリカ構成ではいずれにせよ redis が必要になる。

事態を悪化させる 2 点:

- **`tokenCache.ttlSeconds` / `INTROSPECT_CACHE_TTL_SEC` を下げるとミスが増える。** TTL が短いほど、同じトラフィックが同じ 60/60 秒バケットを多く消費する。しかも失効を縛るのは TTL ではない — 「アクセストークンの寿命と失効」を参照。
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
| `INJECTION_SESSION_COOKIE_NAME` | セッションクッキー名（デフォルト: `connect.sid`）。RFC 6265 `cookie-name`（RFC 9110 token）であること — 空白・`=`・その他のセパレータは起動時に失敗する。 |
| `INJECTION_STRIP_INBOUND_AUTHORIZATION` | `"true"` / `"false"`（デフォルト: `false`）。プロキシがトークンを発行しなかったリクエストの受信 `Authorization` ヘッダーを削除する。それ以外の値は起動時に失敗する。「受信 Authorization ヘッダー」を参照。 |
| `INJECTION_TOKEN_CACHE_TTL_SEC` | トークンキャッシュ TTL（秒、デフォルト: 60）。セッションキャッシュと交換キャッシュの両方に適用。 |
| `INJECTION_TOKEN_CACHE_MAX_ENTRIES` | トークンキャッシュ最大エントリ数（デフォルト: 10000）。セッションキャッシュと交換キャッシュそれぞれに適用。 |
| `INJECTION_TOKEN_CACHE_SAFETY_MARGIN_SEC` | クロックドリフト安全マージン（秒、デフォルト: 5）。両方のキャッシュに適用。 |
| `INJECTION_TIMEOUT_MS` | プロバイダー HTTP タイムアウト（デフォルト: 5000）。セッショングラントと交換の両方に適用。 |
| `INJECTION_EXCHANGE_ENABLED` | `"true"` / `"false"`（デフォルト: `false`）。受信 `Authorization: Bearer <JWT>` をプロバイダーで交換する（RFC 7523 jwt-bearer）。それ以外の値は起動時に失敗する。「外部クレデンシャル交換」を参照。 |
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
