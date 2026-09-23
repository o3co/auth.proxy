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
import { discardBody, readBoundedJsonObject } from "../../response-body.mjs";

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

/**
 * Which credential the provider refused, on a 401 and nowhere else (#95 F7).
 *
 * RFC 7662 §2.3 requires the introspection request to be authenticated, so a
 * 401 answers whichever credential this module presented — and only this
 * module knows which that was. `token` means the inbound token was the
 * credential and the provider refused it, which is a statement about the
 * caller. `client` means the proxy authenticated as itself and was refused,
 * which is a statement about the deployment: the caller's token was never
 * examined.
 */
export type RefusedCredential = "client" | "token";

/**
 * How much of a 200 introspection response is read before giving up on it
 * (#95 F39).
 *
 * The same allowance the injection path gives a token response
 * (`MAX_TOKEN_BODY_BYTES`, F35), for the same reason: an introspection
 * response is the answer itself, and a claim set can be generous. Nothing a
 * provider legitimately sends comes near it, so it is reached only by a body
 * that is not an introspection response at all. It is a memory bound, not a
 * validity check — until F39 this path buffered whatever arrived, once per
 * request in flight.
 */
export const MAX_INTROSPECTION_BODY_BYTES = 64 * 1024;

export class IntrospectHttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
		/** Set on a 401 by the bundled client; `null` on every other status. */
		public readonly refusedCredential: RefusedCredential | null = null,
		/** What was thrown instead of an answer, when there was no answer. */
		cause?: unknown,
	) {
		super(message, cause === undefined ? undefined : { cause });
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
 * @throws {IntrospectHttpError} the provider's status for a non-2xx — carrying
 * {@link RefusedCredential} on a 401, which says whether the provider refused
 * the inbound token or the proxy's own client authentication — and `502`
 * for a 200 whose body is not a JSON object, is over the
 * {@link MAX_INTROSPECTION_BODY_BYTES} bound, or is not a valid RFC 7662
 * response, and `502` for a call that never answered — a timeout or a
 * network error, kept as the `cause` (#95 F42). The same class carries one
 * more `502` raised outside this module: a malformed `exp` on an otherwise
 * valid response, which `createIntrospector` refuses once it has decided the
 * response is one it would read at all.
 */
export interface IntrospectionClient {
	/**
	 * No signal parameter, deliberately (#95 F10): the only cancellation is
	 * `AbortSignal.timeout(timeoutMs)`, and a caller's disconnect must not
	 * abort a call other waiters are coalesced onto.
	 */
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
			let resp: Response;
			try {
				resp = await fetch(url, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: configuredHeader ?? buildAuthHeader(null, token),
					"x-request-id": requestId,
				},
				body: new URLSearchParams({ token }).toString(),
				// The endpoint is configuration, and a followed redirect cannot be
				// reported honestly (#95 F43, the counterpart of F8 on the token
				// clients): a same-origin 307/308 re-sends this request's credential
				// — the inbound token, or the proxy's Basic header — to a path
				// nothing configured; cross-origin it strips it, and the provider's
				// 401 would read as the caller's token being bad. A 3xx comes back
				// as the non-2xx it is, and the decision reports it.
				redirect: "manual",
				signal: AbortSignal.timeout(timeoutMs),
			});
			} catch (err) {
				// The provider did not answer: a timeout, a refused connection, a
				// DNS failure. That is the provider failing, as its 5xx is, so it is
				// reported in the same class and answered 502 (#95 F42) — until then
				// it propagated raw and the decision answered 500, the status it
				// keeps for what the proxy itself did not expect.
				throw new IntrospectHttpError(
					502,
					`introspect call failed: ${err instanceof Error ? err.message : String(err)}`,
					null,
					err,
				);
			}

			if (!resp.ok) {
				// Nothing reads an error body on this path (#95 F28).
				await discardBody(resp);
				throw new IntrospectHttpError(
					resp.status,
					`introspect returned ${resp.status}`,
					// Only a 401 answers a credential, and which one depends on
					// what this request carried (#95 F7). Every other status is
					// about the request or the provider, not a credential.
					resp.status === 401 ? (credentials !== null ? "client" : "token") : null,
				);
			}

			// Read at most MAX_INTROSPECTION_BODY_BYTES of it (#95 F39). A body
			// that is not a JSON object, or that does not stop, is the provider
			// answering badly rather than an auth decision.
			const parsed = await readBoundedJsonObject(resp, MAX_INTROSPECTION_BODY_BYTES);
			if (parsed === null) {
				throw new IntrospectHttpError(
					502,
					"introspect returned 200 with a body that is not a JSON object, or is over the size bound",
				);
			}

			// RFC 7662 §2.2: `active` MUST be a boolean. Reject anything else so a provider
			// returning {"active":"false"} cannot bypass auth via truthy coercion.
			if (typeof parsed.active !== "boolean") {
				throw new IntrospectHttpError(
					502,
					"introspect returned 200 but the body is not a valid introspection response (RFC 7662)",
				);
			}
			return parsed as IntrospectionResult;
		},
	};
};
