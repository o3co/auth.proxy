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

import { extractBearerToken } from "../../express/bearer.mjs";
import type { Logger } from "../../logger.mjs";
import { IntrospectHttpError, type IntrospectionResult } from "./introspection-client.mjs";

/** The two header values the decision reads — plain strings, no request object. */
export interface ValidationInputs {
	/** As normalised by `express/requestId`; `""` when that middleware is not mounted first. */
	requestId: string;
	authorization: string | undefined;
}

/**
 * What the decision asks of the provider: the introspection result for one
 * token, from the cache or the endpoint. `createRouter` binds the concrete
 * `introspect` with its URL, bounds and credential choice; a caller may supply
 * its own — and then owns what the bundled one guarantees and the decision
 * does not: the RFC 7662 section 2.2 check that `active` is a boolean (the decision
 * forwards only on `true`, so a non-boolean is a refusal, never a bypass), the
 * refusals for a `cnf`, a non-Bearer `token_type` and expiry during the call,
 * and its own timeout, since the decision has none. What `createRouter`
 * builds behind this seam is `createIntrospector` over an
 * `IntrospectionClient` and an `IntrospectionCache` (#95 F5).
 *
 * No signal parameter, deliberately (#95 F10): the only cancellation is the
 * timeout the implementation behind this seam imposes on itself, and a
 * caller's disconnect must not abort a call other waiters are coalesced onto.
 */
export type Introspector = (token: string, requestId: string) => Promise<IntrospectionResult>;

/** What the validation decision needs (#95 F3). */
export interface ValidationDeps {
	introspect: Introspector;
	logger: Logger;
}

/**
 * The `WWW-Authenticate` challenge for a token this path will not accept
 * (#95 F29).
 *
 * RFC 6750 §3 makes the header a MUST when a protected-resource request
 * carries no credentials or carries a token that does not enable access, and
 * a SHOULD to name the `error` **when the request included an access token**.
 * Only this refusal meets that second condition: the caller presented a
 * Bearer token and it was not accepted, which §3.1 calls `invalid_token`.
 *
 * No `realm` — it is OPTIONAL, and nothing configures a name to put in it, so
 * the `error` is the one auth-param that §3's "MUST be followed by one or
 * more auth-param values" needs. No `error_description`: §3 makes it a MAY,
 * the body already carries the wording, and the same string in two places
 * invites them to drift.
 */
const INVALID_TOKEN_CHALLENGE = 'Bearer error="invalid_token"';

/**
 * The decision, as data. The middleware in `router.mts` applies it: `forward`
 * calls `next()` with `req.headers` untouched, `reject` writes the status, the
 * `{ code, message }` body and, when there is one, the challenge.
 */
export type ValidationOutcome =
	| { kind: "forward" }
	| {
			kind: "reject";
			status: number;
			body: { code: number; message: string };
			/**
			 * The `WWW-Authenticate` value, or `null` when the refusal is not
			 * about the caller's credential and a challenge would ask them to
			 * fix something that is not theirs.
			 */
			challenge: string | null;
	  };

const reject = (
	status: number,
	message: string,
	challenge: string | null,
): ValidationOutcome => ({
	kind: "reject",
	status,
	body: { code: status, message },
	challenge,
});

/**
 * The validation decision (#95 F3): the one place that reads `Authorization`,
 * consults the introspector and says what happens to the request. It never
 * sees Express; `router.mts` reads the headers and applies the outcome.
 *
 *   - no Authorization                        forward, the provider not consulted
 *   - not `Bearer <token>`                    400 Invalid Token Type
 *   - active: false                           401 Invalid Token
 *   - the provider answers 401                401 Invalid Token, unless it was
 *                                             the proxy's own client
 *                                             authentication that was refused:
 *                                             502 Provider Configuration Error
 *   - the endpoint redirects                  502 Provider Configuration Error
 *   - any other provider failure              502 Bad Gateway — a 5xx, a 429,
 *     (an IntrospectHttpError)                a 4xx that is not 401, a 200 that
 *                                             is not an introspection response,
 *                                             no answer at all (#95 F42)
 *   - anything else thrown                    500 Internal Server Error
 *   - active: true                            forward
 *
 * What is forwarded is decided by `req.headers`, which the middleware never
 * modifies on this path: the first SP-delimited word is introspected, the
 * inbound bytes go upstream (F14).
 */
export const decideValidation = async (
	{ requestId, authorization }: ValidationInputs,
	{ introspect, logger }: ValidationDeps,
): Promise<ValidationOutcome> => {
	if (!authorization) {
		return { kind: "forward" };
	}

	const token = extractBearerToken(authorization);
	// Truthiness rather than `=== null`, matching the `!authorization` check
	// above it: the empty string is the only other falsy value a `string | null`
	// can hold, it is not a credential, and refusing it here is the safe
	// direction if the parser ever stops ruling it out (#95 F36).
	if (!token) {
		// No challenge. RFC 6750 §3.1's last paragraph: a request that
		// "attempted using an unsupported authentication method" SHOULD NOT
		// carry an error code — and §3's SHOULD to name one is conditioned on
		// the request having included an access token, which a Basic header or
		// a `Bearer` with nothing after it did not. What the RFC does offer for
		// this case is `Bearer realm="…"`, and there is no configured name to
		// put in a realm. Tracked as F45 on #95, which also has to split the
		// three requests this one branch answers.
		return reject(400, "Invalid Token Type", null);
	}

	try {
		const result = await introspect(token, requestId);
		// `=== true`, not truthiness: the concrete `introspect` already refuses a
		// non-boolean `active`, but a supplied introspector may not, and
		// `{ active: "false" }` must not forward.
		if (result.active !== true) {
			return reject(401, "Invalid Token", INVALID_TOKEN_CHALLENGE);
		}
	} catch (e) {
		// The status is checked beside the mark: the class documents that only a
		// 401 carries one, but nothing stops a supplied introspector constructing
		// an out-of-contract error, and this branch answers a different status.
		// A 401 that refused the proxy's own client authentication is not a
		// statement about the caller's token — the provider never examined it
		// (#95 F7). It is the deployment's own configuration, so it is reported
		// as a provider-side failure and logged as the actionable thing it is,
		// the way the injection path already reports `provider_config_error`.
		if (
			e instanceof IntrospectHttpError &&
			e.status === 401 &&
			e.refusedCredential === "client"
		) {
			logger.error(
				{ "x-request-id": requestId, error: e },
				"introspect refused the proxy's client credentials",
			);
			return reject(502, "Provider Configuration Error", null);
		}
		// A redirecting introspection endpoint is the same kind of thing: the
		// deployment's configuration, reported as such (#95 F43). The client
		// asks fetch not to follow, so the 3xx arrives with its own status.
		if (e instanceof IntrospectHttpError && e.status >= 300 && e.status < 400) {
			logger.error({ "x-request-id": requestId, error: e }, "introspect endpoint redirected");
			return reject(502, "Provider Configuration Error", null);
		}
		logger.error({ "x-request-id": requestId, error: e }, "introspect failed");
		// Every other 401 is about the token: the bundled client marks it, and a
		// supplied introspector that marks nothing is read the way it always was.
		if (e instanceof IntrospectHttpError && e.status === 401) {
			return reject(401, "Invalid Token", INVALID_TOKEN_CHALLENGE);
		}
		// The rest of IntrospectHttpError is the provider failing, and a gateway
		// reports its upstream's failure as 502 (RFC 9110 §15.6.3) — the status
		// the injection path gives every one of these already (#95 F42). What
		// is left is something the proxy, or a supplied introspector, did not
		// expect, and that is the proxy's own 500.
		if (e instanceof IntrospectHttpError) {
			return reject(502, "Bad Gateway", null);
		}
		return reject(500, "Internal Server Error", null);
	}

	return { kind: "forward" };
};
