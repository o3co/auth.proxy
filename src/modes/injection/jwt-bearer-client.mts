/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { clientSecretBasic } from "../../oauth/client-secret-basic.mjs";
import { readBoundedJsonObject, sanitizeErrorCode } from "./provider-error.mjs";
import { buildTokenUrl, parseJsonBody } from "./token-endpoint.mjs";

/** RFC 7523 section 2.1. */
export const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/**
 * How a failed exchange is answered. Each code is also the `error` of the
 * proxy's response body.
 *
 *   - `credential_rejected` (401)       the provider refused the assertion
 *                                       (`invalid_grant`)
 *   - `exchange_not_permitted` (403)    the assertion may be fine, but not for
 *                                       this client / scope / target
 *                                       (`invalid_scope`, `invalid_target`,
 *                                       `unauthorized_client`)
 *   - `provider_config_error` (502)     the provider refused the proxy itself:
 *                                       a 401 (`invalid_client`), any other 400,
 *                                       or a redirect
 *   - `provider_unavailable` (502)      5xx, 429, network error, timeout, or an
 *                                       unexpected status
 *   - `provider_invalid_response` (502) a 200 that is not a Bearer token response
 */
export type JwtBearerErrorCode =
	| "credential_rejected"
	| "exchange_not_permitted"
	| "provider_config_error"
	| "provider_unavailable"
	| "provider_invalid_response";

export class JwtBearerError extends Error {
	constructor(
		public readonly code: JwtBearerErrorCode,
		public readonly status: number,
		message: string,
		public readonly retryAfter: string | null = null,
		/**
		 * The provider's RFC 6749 section 5.2 `error`, for logs — validated by
		 * `sanitizeErrorCode`, so never a credential the provider echoed back.
		 */
		public readonly providerError: string | null = null,
	) {
		super(message);
		this.name = "JwtBearerError";
	}
}

export interface JwtBearerResult {
	accessToken: string;
	expiresIn: number | null;
}

export interface JwtBearerClientConfig {
	providerOrigin: string;
	timeoutMs: number;
	clientId: string;
	clientSecret: string;
	scope: string | null;
	audience: string | null;
	resource: string | null;
}

export interface JwtBearerClient {
	exchange(args: { assertion: string; requestId: string }): Promise<JwtBearerResult>;
}

const NOT_PERMITTED: ReadonlySet<string> = new Set([
	"invalid_scope",
	"invalid_target",
	"unauthorized_client",
]);

/**
 * The token-endpoint client for the external credential exchange (#90).
 *
 * It submits an assertion exactly once per call: there is no retry, because
 * an ID-JAG assertion is accepted once and a second submission would be
 * refused as a replay. Deciding whether the assertion is trustworthy, for which
 * client, scope and audience, is the provider's; this client only maps the
 * answer.
 *
 * Same origin, URL construction and timeout as the session grant client. It
 * authenticates with `client_secret_basic`, so the body carries no `client_id`.
 * Redirects are not followed: the body carries a bearer credential and the
 * header the proxy's own secret, and a token endpoint that redirects is a
 * misconfigured one.
 */
export const createJwtBearerClient = (cfg: JwtBearerClientConfig): JwtBearerClient => {
	const url = buildTokenUrl(cfg.providerOrigin);
	const authorization = clientSecretBasic(cfg);

	return {
		async exchange({ assertion, requestId }) {
			const params = new URLSearchParams({ grant_type: JWT_BEARER_GRANT_TYPE, assertion });
			if (cfg.scope !== null) params.set("scope", cfg.scope);
			if (cfg.audience !== null) params.set("audience", cfg.audience);
			if (cfg.resource !== null) params.set("resource", cfg.resource);

			let resp: Response;
			try {
				resp = await fetch(url, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: authorization,
						"X-Request-Id": requestId,
						Accept: "application/json",
					},
					body: params.toString(),
					redirect: "manual",
					signal: AbortSignal.timeout(cfg.timeoutMs),
				});
			} catch (err) {
				// Network error, timeout (TimeoutError), DNS failure.
				throw new JwtBearerError(
					"provider_unavailable",
					502,
					`provider call failed: ${err instanceof Error ? err.message : String(err)}`,
				);
			}

			const retryAfter = resp.headers.get("retry-after");

			if (resp.status === 200) {
				const data = await parseJsonBody(resp);
				if (data === null) {
					throw new JwtBearerError(
						"provider_invalid_response",
						502,
						"provider returned 200 with a body that is not a JSON object, or is over the size bound",
					);
				}
				if (typeof data.access_token !== "string" || data.access_token.length === 0) {
					throw new JwtBearerError(
						"provider_invalid_response",
						502,
						"provider returned 200 without an access_token",
					);
				}
				// RFC 6749 section 5.1: token_type is REQUIRED. Only a Bearer token
				// can be injected — a DPoP-bound token is useless without the
				// proof key, which the proxy does not hold.
				if (typeof data.token_type !== "string" || data.token_type.toLowerCase() !== "bearer") {
					throw new JwtBearerError(
						"provider_invalid_response",
						502,
						"provider returned 200 without a Bearer token_type",
					);
				}
				const expiresIn =
					typeof data.expires_in === "number" && Number.isFinite(data.expires_in)
						? data.expires_in
						: null;
				return { accessToken: data.access_token, expiresIn };
			}

			if (resp.status >= 300 && resp.status < 400) {
				throw new JwtBearerError(
					"provider_config_error",
					502,
					`provider token endpoint redirected (${resp.status})`,
					retryAfter,
				);
			}

			if (resp.status === 400 || resp.status === 401) {
				const data = await readBoundedJsonObject(resp);
				const rawError = data?.error;
				const providerError = sanitizeErrorCode(rawError, [assertion, cfg.clientSecret]);
				if (resp.status === 400 && rawError === "invalid_grant") {
					throw new JwtBearerError(
						"credential_rejected",
						401,
						"the provider rejected the credential",
						retryAfter,
						providerError,
					);
				}
				if (resp.status === 400 && typeof rawError === "string" && NOT_PERMITTED.has(rawError)) {
					throw new JwtBearerError(
						"exchange_not_permitted",
						403,
						"the provider does not permit this exchange",
						retryAfter,
						providerError,
					);
				}
				throw new JwtBearerError(
					"provider_config_error",
					502,
					resp.status === 401
						? "provider rejected the proxy's client authentication"
						: "provider rejected the exchange request",
					retryAfter,
					providerError,
				);
			}

			// The answer does not depend on the body; its validated `error` code
			// is kept only so the log line can say what the provider reported.
			const data = await readBoundedJsonObject(resp);
			throw new JwtBearerError(
				"provider_unavailable",
				502,
				resp.status === 429 || resp.status >= 500
					? `provider call failed: returned ${resp.status}`
					: `unexpected provider response: ${resp.status}`,
				retryAfter,
				sanitizeErrorCode(data?.error, [assertion, cfg.clientSecret]),
			);
		},
	};
};
