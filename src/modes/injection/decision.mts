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
import type { AppConfig } from "../../../config/application.schema.mjs";
import type { Logger } from "../../logger.mjs";
import type { SingleFlight } from "../../single-flight.mjs";
import { computeCacheExpiresAt } from "./cache-expiry.mjs";
import {
	type CookieExtraction,
	type CookieRejectReason,
	extractCookie,
} from "./cookie-extractor.mjs";
import {
	SESSION_GRANT_TYPE,
	type SessionGrantClient,
	type SessionGrantClientConfig,
	SessionGrantError,
	type SessionGrantErrorCode,
} from "./session-grant-client.mjs";
import type { TokenCache } from "./token-cache.mjs";
import { buildTokenUrl } from "./token-endpoint.mjs";

type InjectionConfig = Extract<AppConfig["auth"], { mode: "injection" }>;

/**
 * What the session grant asks the provider, as the key for the answer it gets
 * back (#95 F33).
 *
 * The cache and the flight table are supplied-able (#95 F4), so one instance
 * can serve two routers. The key was SHA-256 of the cookie value alone, which
 * made "this cookie's token" mean whatever the first router to ask had asked —
 * a different provider, client, scope or cookie name is a different question,
 * and the second router was served the first one's answer.
 *
 * Hashed as a JSON array rather than joined, so no field's text can shift into
 * its neighbour's, and the cookie value never leaves the digest. The cache
 * policy is not in it: `ttlSeconds` bounds how long an entry lives, not which
 * token comes back. Neither is the grant client, which cannot be hashed. Those
 * two are what a caller sharing one cache between routers must still match;
 * the rest is now the key's job.
 *
 * The parameter is the client's own config minus `timeoutMs`, and the rest
 * element below is what makes that a guarantee rather than a convention: a
 * field added to what the client sends lands in it and fails the build until
 * it is keyed or dropped on purpose.
 */
export const sessionCacheKey = (
	cfg: Omit<SessionGrantClientConfig, "timeoutMs">,
	sessionCookieValue: string,
): string => {
	const { providerOrigin, clientId, scope, sessionCookieName, ..._unkeyed } = cfg;
	// Empty by construction today; a new field makes it non-empty and this
	// assignment stops compiling.
	const _everythingIsKeyed: Record<string, never> = _unkeyed;

	return crypto
		.createHash("sha256")
		.update(
			JSON.stringify([
				SESSION_GRANT_TYPE,
				buildTokenUrl(providerOrigin),
				clientId,
				scope,
				sessionCookieName,
				sessionCookieValue,
			]),
		)
		.digest("hex");
};

/**
 * What the session decision needs. `createRouter` builds every default and
 * accepts overrides for the cache, the flight table, the grant client and the
 * logger (#95 F4). The exchange's deps are not here: the decision only needs
 * to know whether the exchange is on, and hands off with `ExchangeArgs`.
 */
export interface InjectionDeps {
	cfg: InjectionConfig["injection"];
	/**
	 * Both keyed by {@link sessionCacheKey}, which carries the grant context —
	 * provider, client, scope, cookie name — beside the cookie value (#95 F33).
	 * An instance supplied through `createRouter({ deps })` may therefore be
	 * shared between routers that differ in any of those. What is still not in
	 * the key, and so still the caller's to match: the `grantClient`, which
	 * cannot be hashed, and the cache policy, which decides how long an entry
	 * lives rather than which token comes back.
	 */
	tokenCache: TokenCache;
	singleFlight: SingleFlight<string>;
	grantClient: SessionGrantClient;
	/** `auth.injection.exchange.enabled`: an inbound `Authorization` is handed off, never forwarded as received. */
	exchangeEnabled: boolean;
	logger: Logger;
}

/** The three header values the decision reads — plain strings, no request object. */
export interface InjectionInputs {
	/** As normalised by `express/requestId`; `""` when that middleware is not mounted first. */
	requestId: string;
	cookieHeader: string | undefined;
	authorization: string | undefined;
}

/** Why a request goes upstream without the proxy having minted anything. */
export type ForwardWithoutInjectionReason = "no_cookie" | "cookie_rejected";

/** What `decideExchange` (F2) receives when the decision hands off to it. */
export interface ExchangeArgs {
	requestId: string;
	authorization: string;
	/** The session cookie's classification, so the handler can refuse two credentials at once. */
	sessionCookie: CookieExtraction["kind"];
}

/**
 * The decision, as data. The middleware in `router.mts` applies it: `forward`
 * and `forward_stripped` call `next()` (the latter after deleting the inbound
 * `Authorization` from `req.headers`), `inject` sets `Authorization: Bearer
 * <token>` on `req.headers` and calls `next()`, `respond` writes the status,
 * the body and the provider's `Retry-After`, `exchange` calls the exchange
 * handler with `args`.
 */
export type InjectionOutcome =
	| { kind: "forward" }
	| { kind: "forward_stripped"; reason: ForwardWithoutInjectionReason }
	| { kind: "inject"; token: string }
	| {
			kind: "respond";
			status: number;
			body: { error: string; error_description: string };
			retryAfter: string | null;
	  }
	| { kind: "exchange"; args: ExchangeArgs };

/**
 * What a forward without injection does to the inbound `Authorization`, as the
 * lines reporting it name it. Derived from {@link InjectionOutcome} rather
 * than spelled again, so renaming an outcome cannot leave a log field behind
 * (#95 F31).
 */
type ForwardAction = Extract<InjectionOutcome["kind"], "forward" | "forward_stripped">;

/**
 * A session cookie pair the proxy refuses to forward (#23). Unlike the absent
 * case this deserves an operator's attention, so it is a distinct event at warn
 * (#73). Only the bounded reason class is logged, never the value bytes.
 * `action` names what became of the request, in the outcome's own vocabulary:
 * `forward` — every same-name pair was refused and the request goes upstream
 * with whatever `Authorization` it arrived with, which is none unless the
 * client presented its own; `forward_stripped` — the same, with that header
 * removed because `stripInboundAuthorization` is on; `fallback` — a malformed
 * pair was skipped and a later well-formed same-name pair is used (#74), so
 * the request goes on to attempt the mint rather than forwarding here.
 */
const logCookieRejected = (
	logger: Logger,
	requestId: string,
	reason: CookieRejectReason,
	action: ForwardAction | "fallback",
): void => {
	logger.warn(
		{
			requestId,
			event: "injection.cookie_rejected",
			reason,
			action,
			metric: "auth_proxy_injection_cookie_rejected",
		},
		action === "fallback"
			? "malformed session cookie pair skipped, using the next well-formed pair"
			: "session cookie rejected, forwarding without a minted Authorization",
	);
};

/** How a failed session grant is reported: which level, under which event. */
interface SessionFailureLine {
	level: "info" | "error";
	event: string;
}

/**
 * One discriminator for the whole failure branch (#95 F32): the code says what
 * went wrong, and it decides the body's `error`, the level and the event
 * together. `status` decides only the status, which is the client's to choose
 * — the bundled one remaps a 400 `invalid_grant` to 401 deliberately — and it
 * used to decide the level as well, so an error whose code and status were not
 * paired was reported as one thing and answered as another.
 *
 * `satisfies` on the literal is what keeps this exhaustive: a new
 * `SessionGrantErrorCode` fails the build here rather than falling into the
 * unknown case and being reported as a provider outage it is not.
 *
 * A `Map` rather than the object itself, because a supplied grant client (F4)
 * is not bound by the union at runtime and the key is whatever it throws: a
 * plain object answers `Object.prototype` members — `constructor`,
 * `toString`, `__proto__` — with an inherited value that is truthy, so the
 * fallback below would not fire and the line would be logged with `undefined`
 * fields, throwing inside the `catch` that exists to answer a refusal.
 */
const SESSION_FAILURE_LINES = new Map<string, SessionFailureLine>(
	Object.entries({
		session_unauthorized: { level: "info", event: "injection.session_unauthorized" },
		provider_config_error: { level: "error", event: "injection.provider_config_error" },
		provider_invalid_response: { level: "error", event: "injection.provider_invalid_response" },
		provider_unavailable: { level: "error", event: "injection.provider_unavailable" },
	} satisfies Record<SessionGrantErrorCode, SessionFailureLine>),
);

/** A code no version of this proxy declared, from a supplied grant client. */
const UNKNOWN_SESSION_FAILURE: SessionFailureLine = {
	level: "error",
	event: "injection.provider_unavailable",
};

/**
 * The session decision (#95 F1): the one place that reads the cookie, consults
 * the cache, the flight table and the grant client, and says what happens to
 * the request. It never sees Express; `router.mts` reads the headers and
 * applies the outcome.
 */
export const decideInjection = async (
	{ requestId, cookieHeader, authorization }: InjectionInputs,
	deps: InjectionDeps,
): Promise<InjectionOutcome> => {
	const { tokenCache, singleFlight, grantClient, cfg, exchangeEnabled, logger } = deps;
	const extraction = extractCookie(cookieHeader, cfg.sessionCookieName);

	/**
	 * With the exchange enabled, an inbound `Authorization` header — any
	 * scheme, even empty — is never forwarded as received: it is exchanged
	 * for a first-party token or the request is refused (#90). That also
	 * leaves `stripInboundAuthorization` nothing to strip. A request without
	 * the header takes the paths below exactly as it would with the exchange
	 * disabled. The exchange itself is decided by `decideExchange` (F2); this only
	 * hands off.
	 */
	if (exchangeEnabled && authorization !== undefined) {
		return {
			kind: "exchange",
			args: { requestId, authorization, sessionCookie: extraction.kind },
		};
	}

	/**
	 * Whether a forward without injection takes the inbound `Authorization`
	 * with it. One predicate, read by the outcome and by the lines that report
	 * it, so the two cannot disagree — they did, and the line was written
	 * first, so it said `forward` and the request was stripped (#95 F31).
	 */
	const willStripInbound = cfg.stripInboundAuthorization && Boolean(authorization);
	const forwardAction: ForwardAction = willStripInbound ? "forward_stripped" : "forward";

	/**
	 * The two paths that forward without the proxy having minted anything.
	 * `inject` overwrites an inbound `Authorization` on every path that DID
	 * mint, so these are the only ones where a client's own header survives
	 * to the upstream — the reason an upstream service must never read "a
	 * Bearer header arrived from the proxy" as "the proxy minted this".
	 * `stripInboundAuthorization` removes the ambiguity for deployments that
	 * want it; it is opt-in because the pass-through is load-bearing for
	 * topologies where a service account presents its own token through the
	 * same proxy. The strip itself is applied on `req.headers` by the
	 * middleware, before the upstream stage — see the comment there.
	 */
	const forwardWithoutInjection = (reason: ForwardWithoutInjectionReason): InjectionOutcome => {
		if (willStripInbound) {
			logger.warn(
				{
					requestId,
					event: "injection.inbound_authorization_stripped",
					reason,
					metric: "auth_proxy_injection_inbound_authorization_stripped",
				},
				"stripping inbound Authorization header the proxy did not mint",
			);
			return { kind: "forward_stripped", reason };
		}
		return { kind: "forward" };
	};

	if (extraction.kind === "absent") {
		logger.debug(
			{ requestId, event: "injection.no_cookie", action: forwardAction },
			"no session cookie",
		);
		return forwardWithoutInjection("no_cookie");
	}

	if (extraction.kind === "rejected") {
		logCookieRejected(logger, requestId, extraction.reason, forwardAction);
		return forwardWithoutInjection("cookie_rejected");
	}

	if (extraction.skipped !== null) {
		logCookieRejected(logger, requestId, extraction.skipped, "fallback");
	}

	const sessionCookieValue = extraction.value;
	const cacheKey = sessionCacheKey(cfg, sessionCookieValue);
	const cached = tokenCache.get(cacheKey);

	const inject = (token: string): InjectionOutcome => {
		if (authorization) {
			logger.warn(
				{
					requestId,
					event: "injection.authorization_override",
					metric: "auth_proxy_injection_authorization_override",
				},
				"overriding inbound Authorization header",
			);
		}
		return { kind: "inject", token };
	};

	if (cached !== null) {
		logger.debug({ requestId, event: "injection.cache_hit" }, "cache hit");
		return inject(cached);
	}

	try {
		const { value: token, wasWaiter } = await singleFlight.run(cacheKey, async () => {
			logger.info({ requestId, event: "injection.grant_fetch" }, "fetching grant");
			// Captured before the request goes out: expires_in is measured
			// from here, not from however late the response arrives.
			const requestedAt = Date.now();
			const result = await grantClient.exchange({
				sessionCookieValue,
				requestId,
			});
			const expiresAt = computeCacheExpiresAt({
				requestedAt,
				now: Date.now(),
				ttlSeconds: cfg.tokenCache.ttlSeconds,
				safetyMarginSeconds: cfg.tokenCache.safetyMarginSeconds,
				expiresIn: result.expiresIn,
			});
			if (expiresAt !== null) {
				tokenCache.set(cacheKey, result.accessToken, expiresAt);
			}
			logger.info(
				{ requestId, event: "injection.grant_success", expiresIn: result.expiresIn },
				"grant success",
			);
			return result.accessToken;
		});
		if (wasWaiter) {
			logger.debug({ requestId, event: "injection.single_flight_wait" }, "coalesced");
		}
		return inject(token);
	} catch (err) {
		if (err instanceof SessionGrantError) {
			const body = {
				error:
					err.code === "session_unauthorized" ? "session_required" : err.code,
				error_description: err.message,
			};
			const { level, event } = SESSION_FAILURE_LINES.get(err.code) ?? UNKNOWN_SESSION_FAILURE;
			logger[level]({ requestId, event, error: err.message }, "grant failed");
			return { kind: "respond", status: err.status, body, retryAfter: err.retryAfter };
		}
		logger.error(
			{ requestId, event: "injection.unexpected_error", error: String(err) },
			"grant failed (unknown)",
		);
		return {
			kind: "respond",
			status: 502,
			body: { error: "provider_unavailable", error_description: "provider call failed" },
			retryAfter: null,
		};
	}
};
