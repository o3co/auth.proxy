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

/**
 * The validation decision, `decideValidation`: whether a request's Bearer
 * token is forwarded or refused, and a refusal's status, body and
 * `WWW-Authenticate` challenge. Also declares the `Introspector` seam it
 * consults and the policy it reads.
 */

import { extractBearerToken, namesBearerScheme } from "../../express/bearer.mjs";
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

/** What the decision reads from configuration (#95 F45). */
export interface ValidationPolicy {
	/**
	 * `auth.validation.realm`: the RFC 6750 §3 `realm` for every challenge, or
	 * `null` for none. The schema admits only what a quoted-string carries
	 * without escaping.
	 */
	realm: string | null;
}

const NO_REALM: ValidationPolicy = { realm: null };

/**
 * The `WWW-Authenticate` value for a refusal about the caller's credential,
 * or `null` when there is nothing to send (#95 F29, F45).
 *
 * RFC 6750 §3 makes the header a MUST when a protected-resource request
 * carries no usable credentials or a token that does not enable access, and
 * says the `Bearer` scheme "MUST be followed by one or more auth-param
 * values". It is a SHOULD to name the `error` only **when the request
 * included an access token** — `invalid_token` (the 401) or, for a Bearer
 * credential too malformed to read, `invalid_request` (§3.1). A request using
 * another method gets no error code (§3.1's last paragraph); its challenge is
 * `realm` alone, as in §3.1's own example, and without a configured realm
 * there is no auth-param left to send, so no header at all.
 *
 * No `error_description`: §3 makes it a MAY, the body already carries the
 * wording, and the same string in two places invites them to drift.
 */
const challengeFor = (
	{ realm }: ValidationPolicy,
	error: "invalid_token" | "invalid_request" | null,
): string | null => {
	const params = [
		...(realm !== null ? [`realm="${realm}"`] : []),
		...(error !== null ? [`error="${error}"`] : []),
	];
	return params.length > 0 ? `Bearer ${params.join(", ")}` : null;
};

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
 *   - not `Bearer <token>`                    400 Invalid Token Type — with
 *                                             `error="invalid_request"` when it
 *                                             named Bearer, the realm alone when
 *                                             it used another method (#95 F45)
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
 *
 * Every challenge carries `policy.realm` when one is configured.
 *
 * Every provider failure is logged once, with `requestId`, a `validation.*`
 * `event` and the thrown value under `error` — the vocabulary the injection
 * path logs in (#134). The provider's 401 about the caller's token is info;
 * everything that is the proxy's or the provider's own failure is error.
 */
export const decideValidation = async (
	{ requestId, authorization }: ValidationInputs,
	{ introspect, logger }: ValidationDeps,
	policy: ValidationPolicy = NO_REALM,
): Promise<ValidationOutcome> => {
	const invalidToken = challengeFor(policy, "invalid_token");

	if (!authorization) {
		return { kind: "forward" };
	}

	const token = extractBearerToken(authorization);
	// Truthiness rather than `=== null`, matching the `!authorization` check
	// above it: the empty string is the only other falsy value a `string | null`
	// can hold, it is not a credential, and refusing it here is the safe
	// direction if the parser ever stops ruling it out (#95 F36).
	if (!token) {
		// One status, two challenges (#95 F45). A `Bearer` with no usable token
		// after it is §3.1's "otherwise malformed" request: `invalid_request`.
		// Another method — `Basic`, or a lowercase `bearer` this parser does not
		// admit — "SHOULD NOT" carry an error code (§3.1's last paragraph), so it
		// gets the realm alone, or nothing when none is configured.
		return reject(
			400,
			"Invalid Token Type",
			challengeFor(policy, namesBearerScheme(authorization) ? "invalid_request" : null),
		);
	}

	try {
		const result = await introspect(token, requestId);
		// `=== true`, not truthiness: the concrete `introspect` already refuses a
		// non-boolean `active`, but a supplied introspector may not, and
		// `{ active: "false" }` must not forward.
		if (result.active !== true) {
			return reject(401, "Invalid Token", invalidToken);
		}
	} catch (e) {
		// The status is checked beside the mark: the class documents that only a
		// 401 carries one, but nothing stops a supplied introspector constructing
		// an out-of-contract error, and this branch answers a different status.
		// A 401 that refused the proxy's own client authentication is not a
		// statement about the caller's token — the provider never examined it
		// (#95 F7). It is the deployment's own configuration, so it is reported
		// as a provider-side failure and logged as the actionable thing it is,
		// under the event the injection path gives it (#134).
		if (
			e instanceof IntrospectHttpError &&
			e.status === 401 &&
			e.refusedCredential === "client"
		) {
			logger.error(
				{ requestId, event: "validation.provider_config_error", error: e },
				"introspect refused the proxy's client credentials",
			);
			return reject(502, "Provider Configuration Error", null);
		}
		// A redirecting introspection endpoint is the same kind of thing: the
		// deployment's configuration, reported as such (#95 F43), under the
		// same event — the injection path files a redirect there too. The
		// client asks fetch not to follow, so the 3xx arrives with its own status.
		if (e instanceof IntrospectHttpError && e.status >= 300 && e.status < 400) {
			logger.error(
				{ requestId, event: "validation.provider_config_error", error: e },
				"introspect endpoint redirected",
			);
			return reject(502, "Provider Configuration Error", null);
		}
		// Every other 401 is about the token: the bundled client marks it, and a
		// supplied introspector that marks nothing is read the way it always was.
		// It is the caller's refusal, not the proxy failing, so it is logged at
		// info — the level `injection.session_unauthorized` has (#134).
		if (e instanceof IntrospectHttpError && e.status === 401) {
			logger.info(
				{ requestId, event: "validation.token_unauthorized", error: e },
				"introspect failed",
			);
			return reject(401, "Invalid Token", invalidToken);
		}
		// The rest of IntrospectHttpError is the provider failing, and a gateway
		// reports its upstream's failure as 502 (RFC 9110 §15.6.3) — the status
		// the injection path gives every one of these already (#95 F42). One
		// event for all of them: the class carries a status and no finer
		// classification, so an outage and a 200 that is not an introspection
		// response cannot be told apart here the way injection's
		// `provider_unavailable` and `provider_invalid_response` are.
		if (e instanceof IntrospectHttpError) {
			logger.error(
				{ requestId, event: "validation.provider_error", error: e },
				"introspect failed",
			);
			return reject(502, "Bad Gateway", null);
		}
		// What is left is something the proxy, or a supplied introspector, did
		// not expect, and that is the proxy's own 500.
		logger.error(
			{ requestId, event: "validation.unexpected_error", error: e },
			"introspect failed",
		);
		return reject(500, "Internal Server Error", null);
	}

	return { kind: "forward" };
};
