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
 */
export type Introspector = (token: string, requestId: string) => Promise<IntrospectionResult>;

/** What the validation decision needs (#95 F3). */
export interface ValidationDeps {
	introspect: Introspector;
	logger: Logger;
}

/**
 * The decision, as data. The middleware in `router.mts` applies it: `forward`
 * calls `next()` with `req.headers` untouched, `reject` writes the status and
 * the `{ code, message }` body.
 */
export type ValidationOutcome =
	| { kind: "forward" }
	| { kind: "reject"; status: number; body: { code: number; message: string } };

const reject = (status: number, message: string): ValidationOutcome => ({
	kind: "reject",
	status,
	body: { code: status, message },
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
 *   - any other failure                       500 Internal Server Error
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
		return reject(400, "Invalid Token Type");
	}

	try {
		const result = await introspect(token, requestId);
		// `=== true`, not truthiness: the concrete `introspect` already refuses a
		// non-boolean `active`, but a supplied introspector may not, and
		// `{ active: "false" }` must not forward.
		if (result.active !== true) {
			return reject(401, "Invalid Token");
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
			return reject(502, "Provider Configuration Error");
		}
		logger.error({ "x-request-id": requestId, error: e }, "introspect failed");
		// Every other 401 is about the token: the bundled client marks it, and a
		// supplied introspector that marks nothing is read the way it always was.
		if (e instanceof IntrospectHttpError && e.status === 401) {
			return reject(401, "Invalid Token");
		}
		return reject(500, "Internal Server Error");
	}

	return { kind: "forward" };
};
