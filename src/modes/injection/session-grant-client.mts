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
	exchange(args: {
		sessionCookieValue: string;
		requestId: string;
	}): Promise<SessionGrantResult>;
}

const buildTokenUrl = (providerOrigin: string): string => {
	// providerOrigin is validated as origin-only by the Zod schema.
	return new URL("/oauth/token", providerOrigin).toString();
};

const parseJsonBody = async (resp: Response): Promise<Record<string, unknown> | null> => {
	try {
		const text = await resp.text();
		if (text.length === 0) return null;
		const parsed = JSON.parse(text);
		return typeof parsed === "object" && parsed !== null
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
};

export const createSessionGrantClient = (
	cfg: SessionGrantClientConfig,
): SessionGrantClient => {
	const url = buildTokenUrl(cfg.providerOrigin);

	return {
		async exchange({ sessionCookieValue, requestId }) {
			const body = new URLSearchParams({
				grant_type: "session",
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
						"provider returned 200 with a non-JSON or non-object JSON body",
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

			if (resp.status === 401) {
				throw new SessionGrantError(
					"session_unauthorized",
					401,
					"provider reported the session is invalid or expired",
					retryAfter,
				);
			}
			if (resp.status === 400) {
				const data = await parseJsonBody(resp);
				const provided =
					data !== null && typeof data.error_description === "string"
						? data.error_description
						: null;
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
