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
import axios from "axios";

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

const extractRetryAfter = (headers: unknown): string | null => {
	if (headers === null || typeof headers !== "object") return null;
	const h = headers as Record<string, unknown>;
	const v = h["retry-after"] ?? h["Retry-After"];
	return typeof v === "string" ? v : null;
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

			try {
				const resp = await axios.post<Record<string, unknown>>(url, body, {
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Cookie: `${cfg.sessionCookieName}=${sessionCookieValue}`,
						"X-Request-Id": requestId,
						Accept: "application/json",
					},
					timeout: cfg.timeoutMs,
					// Let axios throw on non-2xx so we can branch in catch.
				});

				const data = resp.data;
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
			} catch (err) {
				if (err instanceof SessionGrantError) throw err;
				if (axios.isAxiosError(err)) {
					const status = err.response?.status;
					const retryAfter = extractRetryAfter(err.response?.headers);
					if (status === 401) {
						throw new SessionGrantError(
							"session_unauthorized",
							401,
							"provider reported the session is invalid or expired",
							retryAfter,
						);
					}
					if (status === 400) {
						const provided =
							typeof (err.response?.data as Record<string, unknown> | undefined)?.error_description === "string"
								? ((err.response?.data as Record<string, unknown>).error_description as string)
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
					if (typeof status === "number" && status >= 500) {
						throw new SessionGrantError(
							"provider_unavailable",
							502,
							`provider call failed: returned ${status}`,
							retryAfter,
						);
					}
					// Network error / timeout / unexpected 4xx.
					throw new SessionGrantError(
						"provider_unavailable",
						502,
						typeof status === "number"
							? `unexpected provider response: ${status}`
							: `provider call failed: ${err.code ?? err.message}`,
						retryAfter,
					);
				}
				throw new SessionGrantError(
					"provider_unavailable",
					502,
					`provider call failed: ${String(err)}`,
				);
			}
		},
	};
};
