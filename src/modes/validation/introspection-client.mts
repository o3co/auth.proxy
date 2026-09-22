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
import { type ClientCredentials, clientSecretBasic } from "../../oauth/client-secret-basic.mjs";

export type { ClientCredentials };

/**
 * An RFC 7662 introspection response, validated only as far as the RFC
 * requires: `active` is a boolean. Every other claim is the provider's and is
 * `unknown` until something narrows it.
 */
export interface IntrospectionResult {
	active: boolean;
	[key: string]: unknown;
}

export class IntrospectHttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
	) {
		super(message);
		this.name = "IntrospectHttpError";
	}
}

/**
 * Which credential the introspection request itself carries. With client
 * credentials configured the proxy authenticates as itself
 * (`client_secret_basic`); without them the inbound token is both the subject
 * of the call and the credential for it — see "Introspection client identity"
 * in the root README for what that costs.
 */
export const buildAuthHeader = (credentials: ClientCredentials | null, token: string): string =>
	credentials !== null ? clientSecretBasic(credentials) : `Bearer ${token}`;

/**
 * The provider's introspection endpoint, as the one call this proxy makes to
 * it (#95 F5). Replaceable: the decision reaches it through
 * `Introspector`, and `createRouter` builds the bundled implementation or
 * takes another.
 *
 * @throws {IntrospectHttpError} the provider's status for a non-2xx, `502`
 * for a 200 whose body is not a valid RFC 7662 response. A `fetch` rejection
 * — timeout or network — propagates unwrapped. The same class carries one
 * more `502` raised outside this module: a malformed `exp` on an otherwise
 * valid response, which `createIntrospector` refuses once it has decided the
 * response is one it would read at all.
 */
export interface IntrospectionClient {
	introspect(token: string, requestId: string): Promise<IntrospectionResult>;
}

export interface IntrospectionClientConfig {
	/** `auth.validation.introspect.url`. */
	url: string;
	/** `auth.validation.introspect.timeoutMs`, as `AbortSignal.timeout`. */
	timeoutMs: number;
	/** `auth.validation.client`, resolved: both halves set, or none. */
	credentials: ClientCredentials | null;
}

export const createIntrospectionClient = ({
	url,
	timeoutMs,
	credentials,
}: IntrospectionClientConfig): IntrospectionClient => {
	// The Basic header depends on configuration alone, so it is built once;
	// the Bearer form is the request's own token and is built per call.
	const configuredHeader = credentials !== null ? buildAuthHeader(credentials, "") : null;

	return {
		async introspect(token, requestId) {
			const resp = await fetch(url, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: configuredHeader ?? buildAuthHeader(null, token),
					"x-request-id": requestId,
				},
				body: new URLSearchParams({ token }).toString(),
				signal: AbortSignal.timeout(timeoutMs),
			});

			if (!resp.ok) {
				throw new IntrospectHttpError(resp.status, `introspect returned ${resp.status}`);
			}

			let parsed: unknown;
			try {
				parsed = await resp.json();
			} catch {
				// Provider returned 200 with a non-JSON body — treat as provider bug, not auth decision.
				throw new IntrospectHttpError(502, "introspect returned 200 with a non-JSON body");
			}

			// RFC 7662 §2.2: `active` MUST be a boolean. Reject anything else so a provider
			// returning {"active":"false"} or a non-object cannot bypass auth via truthy coercion.
			if (
				parsed === null ||
				typeof parsed !== "object" ||
				Array.isArray(parsed) ||
				typeof (parsed as { active?: unknown }).active !== "boolean"
			) {
				throw new IntrospectHttpError(
					502,
					"introspect returned 200 but the body is not a valid introspection response (RFC 7662)",
				);
			}
			return parsed as IntrospectionResult;
		},
	};
};
