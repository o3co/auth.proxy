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

import { readBoundedJsonObject, sanitizeErrorDescription } from "./provider-error.mjs";
import { buildTokenUrl, parseJsonBody } from "./token-endpoint.mjs";

/** The provider-specific grant this client submits, as the request says it. */
export const SESSION_GRANT_TYPE = "session";

export type SessionGrantErrorCode =
	| "session_unauthorized"
	| "provider_config_error"
	| "provider_unavailable"
	| "provider_invalid_response";

export class SessionGrantError extends Error {
	constructor(
		public readonly code: SessionGrantErrorCode,
		public readonly status: number,
		message: string,
		public readonly retryAfter: string | null = null,
	) {
		super(message);
		this.name = "SessionGrantError";
	}
}

export interface SessionGrantResult {
	accessToken: string;
	expiresIn: number | null;
}

export interface SessionGrantClientConfig {
	providerOrigin: string;
	clientId: string;
	scope: string;
	sessionCookieName: string;
	timeoutMs: number;
}

export interface SessionGrantClient {
	/**
	 * No signal parameter, deliberately (#95 F10): the only cancellation is
	 * `AbortSignal.timeout(cfg.timeoutMs)`, and a caller's disconnect must not
	 * abort a grant other waiters are coalesced onto.
	 */
	exchange(args: {
		sessionCookieValue: string;
		requestId: string;
	}): Promise<SessionGrantResult>;
}

export const createSessionGrantClient = (
	cfg: SessionGrantClientConfig,
): SessionGrantClient => {
	const url = buildTokenUrl(cfg.providerOrigin);

	return {
		async exchange({ sessionCookieValue, requestId }) {
			const body = new URLSearchParams({
				grant_type: SESSION_GRANT_TYPE,
				client_id: cfg.clientId,
				scope: cfg.scope,
			}).toString();

			let resp: Response;
			try {
				resp = await fetch(url, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						// Both halves are grammar-checked before they get here: the name by
						// the Zod schema at boot (#75), the value by extractCookie (#23).
						Cookie: `${cfg.sessionCookieName}=${sessionCookieValue}`,
						"X-Request-Id": requestId,
						Accept: "application/json",
					},
					body,
					// The token endpoint is configuration, not somewhere a provider
					// moves at runtime, and neither way a redirect goes is one this
					// call can report honestly (#95 F8). Same-origin, `fetch` keeps
					// the Cookie and re-sends it to a path nothing configured, with
					// the method changed to GET on a 301/302/303. Cross-origin it
					// strips the Cookie, so the provider sees an unauthenticated
					// request, answers 401, and the caller is told to authenticate
					// again over a misconfigured endpoint. The jwt-bearer client has
					// always refused a redirect; this one inherited `fetch`'s default
					// of following up to twenty.
					redirect: "manual",
					signal: AbortSignal.timeout(cfg.timeoutMs),
				});
			} catch (err) {
				// Network error, timeout (AbortError), DNS failure, etc.
				throw new SessionGrantError(
					"provider_unavailable",
					502,
					`provider call failed: ${err instanceof Error ? err.message : String(err)}`,
				);
			}

			const retryAfter = resp.headers.get("retry-after");

			if (resp.ok) {
				const data = await parseJsonBody(resp);
				if (data === null) {
					throw new SessionGrantError(
						"provider_invalid_response",
						502,
						"provider returned 200 with a body that is not a JSON object, or is over the size bound",
					);
				}
				const accessToken =
					typeof data.access_token === "string" && data.access_token.length > 0
						? data.access_token
						: null;
				if (accessToken === null) {
					throw new SessionGrantError(
						"provider_invalid_response",
						502,
						"provider returned 200 without an access_token",
					);
				}
				const expiresIn =
					typeof data.expires_in === "number" ? data.expires_in : null;
				return { accessToken, expiresIn };
			}

			if (resp.status >= 300 && resp.status < 400) {
				throw new SessionGrantError(
					"provider_config_error",
					502,
					`provider token endpoint redirected (${resp.status})`,
					retryAfter,
				);
			}

			if (resp.status === 401) {
				throw new SessionGrantError(
					"session_unauthorized",
					401,
					"provider reported the session is invalid or expired",
					retryAfter,
				);
			}
			if (resp.status === 400) {
				const data = await readBoundedJsonObject(resp);
				// A revoked/expired session is a rejected grant, not a proxy
				// configuration error. Preserve the existing session_required
				// response so the caller can recover by authenticating again.
				if (data?.error === "invalid_grant") {
					throw new SessionGrantError(
						"session_unauthorized", 401, "provider rejected the session grant", retryAfter,
					);
				}
				// The description becomes the error message, which the router logs
				// and returns to the client: only a validated one is relayed, so a
				// provider echoing the session cookie cannot put it in either.
				const provided = sanitizeErrorDescription(data?.error_description, [
					sessionCookieValue,
				]);
				throw new SessionGrantError(
					"provider_config_error",
					502,
					provided !== null
						? provided
						: "provider rejected proxy configuration (client_id or scope)",
					retryAfter,
				);
			}
			if (resp.status >= 500) {
				throw new SessionGrantError(
					"provider_unavailable",
					502,
					`provider call failed: returned ${resp.status}`,
					retryAfter,
				);
			}
			// Unexpected 4xx.
			throw new SessionGrantError(
				"provider_unavailable",
				502,
				`unexpected provider response: ${resp.status}`,
				retryAfter,
			);
		},
	};
};
