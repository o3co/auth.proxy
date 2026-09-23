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
import crypto from "node:crypto";
import type { ExchangeConfig } from "../../../config/application.schema.mjs";
import type { Logger } from "../../logger.mjs";
import type { SingleFlight } from "../../single-flight.mjs";
import { parseBearerAssertion } from "./bearer-assertion.mjs";
import { computeCacheExpiresAt } from "./cache-expiry.mjs";
import type { ExchangeArgs, InjectionOutcome } from "./decision.mjs";
import {
	JWT_BEARER_GRANT_TYPE,
	type JwtBearerClient,
	JwtBearerError,
	type JwtBearerErrorCode,
} from "./jwt-bearer-client.mjs";
import type { TokenCache } from "./token-cache.mjs";
import { buildTokenUrl } from "./token-endpoint.mjs";

/** `auth.injection.exchange` with the exchange on. */
export type ExchangeSettings = Extract<ExchangeConfig, { enabled: true }>;

/** Everything besides the assertion that changes what the provider issues. */
export interface ExchangeContext {
	tokenEndpoint: string;
	clientId: string;
	scope: string | null;
	audience: string | null;
	resource: string | null;
}

/**
 * The context from config. Pure, so the assembly derives it once per router;
 * the client secret is deliberately not part of it.
 */
export const exchangeContext = (
	providerOrigin: string,
	exchange: Pick<ExchangeSettings, "clientId" | "scope" | "audience" | "resource">,
): ExchangeContext => ({
	tokenEndpoint: buildTokenUrl(providerOrigin),
	clientId: exchange.clientId,
	scope: exchange.scope,
	audience: exchange.audience,
	resource: exchange.resource,
});

/**
 * The cache and single-flight key: SHA-256 over a JSON array, so no field's
 * text can shift into its neighbour's (`scope "a b"` + `audience "c"` is not
 * `scope "a"` + `audience "b c"`), and an unset parameter (`null`) is distinct
 * from any string. The grant type is part of it so the namespace can never
 * collide with another grant's entries, and the assertion never appears in the
 * key itself.
 */
export const exchangeCacheKey = (context: ExchangeContext, assertion: string): string =>
	crypto
		.createHash("sha256")
		.update(
			JSON.stringify([
				JWT_BEARER_GRANT_TYPE,
				context.tokenEndpoint,
				context.clientId,
				context.scope,
				context.audience,
				context.resource,
				assertion,
			]),
		)
		.digest("hex");

/**
 * When a cached exchange result stops being injected, or `null` for "do not
 * cache": `computeCacheExpiresAt` with the assertion's unverified `exp` as the
 * absolute bound —
 *
 *   min(requestedAt + ttl, requestedAt + expires_in, exp) - safety margin
 *
 * The unverified `exp` is safe to use here because it can only shorten the
 * lifetime. An assertion without one is not cached at all — there is no
 * validity to bound the result by.
 */
export const computeExchangeExpiresAt = ({
	assertionExpiresAt,
	...rest
}: {
	requestedAt: number;
	now: number;
	ttlSeconds: number;
	safetyMarginSeconds: number;
	expiresIn: number | null;
	assertionExpiresAt: number | null;
}): number | null =>
	assertionExpiresAt === null
		? null
		: computeCacheExpiresAt({ ...rest, notAfter: assertionExpiresAt * 1000 });

/** What the exchange decision reads and calls (#95 F2, F4). */
export interface ExchangeDeps {
	/** The cache key's context, derived once by `exchangeContext`. */
	context: ExchangeContext;
	/** `auth.injection.exchange.allowedIssuers` as a set: a prefilter when non-empty, no filter when empty. */
	allowedIssuers: ReadonlySet<string>;
	/** `auth.injection.tokenCache`'s bounds on a cached result; `maxEntries` is the cache's own. */
	cachePolicy: { ttlSeconds: number; safetyMarginSeconds: number };
	client: JwtBearerClient;
	/**
	 * The exchange path's own instances — the session path's never see an
	 * exchange entry, and vice versa, which the grant type leading each key
	 * says even when a caller hands both paths one instance. `exchangeCacheKey`
	 * carries the context (endpoint, client id, scope, audience, resource), so
	 * routers differing in any of those may share one. Three things it cannot
	 * carry, and which the caller must therefore match: `clientSecret`, which
	 * is not part of the context; the supplied `client`, which cannot be
	 * hashed; and the cache policy, which decides how long an entry lives
	 * rather than which token comes back (#95 F33).
	 */
	tokenCache: TokenCache;
	/** Same key space, same sharing contract as `tokenCache`. */
	singleFlight: SingleFlight<string>;
	logger: Logger;
}

/**
 * The exchange answers in the session decision's vocabulary: inject the
 * issued token, or respond. `router.mts` applies it the same way.
 */
export type ExchangeOutcome = Extract<InjectionOutcome, { kind: "inject" | "respond" }>;

const respond = (
	status: number,
	error: string,
	description: string,
	retryAfter: string | null = null,
): ExchangeOutcome => ({
	kind: "respond",
	status,
	// No WWW-Authenticate, as on the session path: the body is the contract.
	body: { error, error_description: description },
	retryAfter,
});

/** How a failed exchange is reported: which level, under which event, with which message. */
interface ExchangeFailureLine {
	level: "info" | "warn" | "error";
	event: string;
	message: string;
}

/**
 * The line each JwtBearerErrorCode is logged as (#95 F41), the exchange
 * path's counterpart of the session path's SESSION_FAILURE_LINES (F32).
 *
 * `satisfies` on the literal keeps it exhaustive: a code added to the union
 * fails the build here. The lookup is a Map keyed by string because a
 * supplied client (F2) is not bound by the union at runtime — and a plain
 * object would answer `constructor` or `__proto__` with an inherited value,
 * which #109 found on the session path.
 */
const EXCHANGE_FAILURE_LINES = new Map<string, ExchangeFailureLine>(
	Object.entries({
		credential_rejected: {
			level: "info",
			event: "injection.exchange_rejected",
			message: "exchange rejected",
		},
		exchange_not_permitted: {
			level: "warn",
			event: "injection.exchange_not_permitted",
			message: "exchange not permitted",
		},
		provider_config_error: {
			level: "error",
			event: "injection.exchange_provider_config_error",
			message: "exchange failed",
		},
		provider_invalid_response: {
			level: "error",
			event: "injection.exchange_provider_invalid_response",
			message: "exchange failed",
		},
		provider_unavailable: {
			level: "error",
			event: "injection.exchange_provider_unavailable",
			message: "exchange failed",
		},
	} satisfies Record<JwtBearerErrorCode, ExchangeFailureLine>),
);

/**
 * A code no version of this proxy declared, from a supplied client. It used
 * to fall out of a switch with no default, so the refusal was answered with
 * no log line at all; a refusal that leaves no trace is worse than one logged
 * under a general name.
 */
const UNKNOWN_EXCHANGE_FAILURE: ExchangeFailureLine = {
	level: "error",
	event: "injection.exchange_provider_unavailable",
	message: "exchange failed",
};

const logFailure = (logger: Logger, requestId: string, err: JwtBearerError): void => {
	const { level, event, message } =
		EXCHANGE_FAILURE_LINES.get(err.code) ?? UNKNOWN_EXCHANGE_FAILURE;
	logger[level](
		{ requestId, providerError: err.providerError, error: err.message, event },
		message,
	);
};

/**
 * The external credential exchange (#90) — the injection-mode decision for a
 * request that carries an `Authorization` header while
 * `auth.injection.exchange.enabled` is on. The session decision hands off to it
 * with `ExchangeArgs`; it never sees Express (#95 F2).
 *
 * The proxy is a token-endpoint client here and nothing more: it submits the
 * inbound JWT as an RFC 7523 assertion to its configured provider, and on
 * success the issued token REPLACES the inbound header. Which issuers are
 * trusted, on what terms, for which client, scope and audience — and the
 * ID-JAG profile's client binding and one-time `jti` — are decided by the
 * provider's assertion issuer registry. On every other outcome the request is
 * refused: the original credential is never forwarded, and no session grant
 * is attempted in its place.
 *
 *   - session cookie AND Authorization     400 credential_ambiguous
 *   - Authorization not a Bearer JWT       401 credential_unsupported
 *   - iss outside allowedIssuers (if set)  401 credential_rejected, no provider call
 *   - provider answers                     see JwtBearerErrorCode
 *
 * A successful result is cached under `exchangeCacheKey` and bounded by
 * `computeExchangeExpiresAt`; concurrent identical requests share one
 * submission. Failures are neither cached nor retried, so a one-time assertion
 * is submitted once per client presentation and never silently again.
 */
export const decideExchange = async (
	{ requestId, authorization, sessionCookie }: ExchangeArgs,
	deps: ExchangeDeps,
): Promise<ExchangeOutcome> => {
	const { logger } = deps;
	if (sessionCookie !== "absent") {
		// Two credentials for one request. Picking either would let a
		// failure on one quietly become a success on the other.
		logger.warn(
			{
				requestId,
				event: "injection.exchange_credential_ambiguous",
				sessionCookie,
				metric: "auth_proxy_injection_exchange_credential_ambiguous",
			},
			"request carries both a session cookie and an Authorization header",
		);
		return respond(
			400,
			"credential_ambiguous",
			"send either the session cookie or an Authorization header, not both",
		);
	}

	const parsed = parseBearerAssertion(authorization);
	if (parsed.kind === "unsupported") {
		logger.info(
			{ requestId, event: "injection.exchange_credential_unsupported", reason: parsed.reason },
			"Authorization is not a Bearer JWT assertion",
		);
		return respond(401, "credential_unsupported", "Authorization must be a Bearer JWT assertion");
	}

	// A prefilter only: it can refuse, never admit, and `iss` selects
	// nothing. The unverified value is not logged.
	if (
		deps.allowedIssuers.size > 0 &&
		(parsed.issuer === null || !deps.allowedIssuers.has(parsed.issuer))
	) {
		logger.info(
			{ requestId, event: "injection.exchange_issuer_refused" },
			"assertion issuer is not in allowedIssuers",
		);
		return respond(401, "credential_rejected", "the credential was rejected");
	}

	const cacheKey = exchangeCacheKey(deps.context, parsed.assertion);

	// No await between this lookup and `singleFlight.run`: a request that
	// misses here joins a flight still in progress rather than starting a
	// second submission of the same assertion.
	const cached = deps.tokenCache.get(cacheKey);
	if (cached !== null) {
		logger.debug({ requestId, event: "injection.exchange_cache_hit" }, "cache hit");
		return { kind: "inject", token: cached };
	}

	try {
		const { value: token, wasWaiter } = await deps.singleFlight.run(cacheKey, async () => {
			logger.info({ requestId, event: "injection.exchange_fetch" }, "exchanging assertion");
			// Captured before the request goes out: expires_in is measured
			// from here, not from however late the response arrives.
			const requestedAt = Date.now();
			const result = await deps.client.exchange({ assertion: parsed.assertion, requestId });
			const expiresAt = computeExchangeExpiresAt({
				requestedAt,
				now: Date.now(),
				ttlSeconds: deps.cachePolicy.ttlSeconds,
				safetyMarginSeconds: deps.cachePolicy.safetyMarginSeconds,
				expiresIn: result.expiresIn,
				assertionExpiresAt: parsed.expiresAt,
			});
			if (expiresAt !== null) {
				deps.tokenCache.set(cacheKey, result.accessToken, expiresAt);
			}
			logger.info(
				{
					requestId,
					event: "injection.exchange_success",
					expiresIn: result.expiresIn,
					cached: expiresAt !== null,
				},
				"exchange success",
			);
			return result.accessToken;
		});
		if (wasWaiter) {
			logger.debug({ requestId, event: "injection.exchange_single_flight_wait" }, "coalesced");
		}
		return { kind: "inject", token };
	} catch (err) {
		if (err instanceof JwtBearerError) {
			logFailure(logger, requestId, err);
			return respond(err.status, err.code, err.message, err.retryAfter);
		}
		logger.error(
			{ requestId, event: "injection.exchange_unexpected_error", error: String(err) },
			"exchange failed (unknown)",
		);
		return respond(502, "provider_unavailable", "provider call failed");
	}
};
