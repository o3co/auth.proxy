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
import { computeCacheExpiresAt } from "./cache-expiry.mjs";
import {
	type CookieExtraction,
	type CookieRejectReason,
	extractCookie,
} from "./cookie-extractor.mjs";
import { type SessionGrantClient, SessionGrantError } from "./session-grant-client.mjs";
import type { SingleFlight } from "./single-flight.mjs";
import type { TokenCache } from "./token-cache.mjs";

type InjectionConfig = Extract<AppConfig["auth"], { mode: "injection" }>;

const sha256Hex = (s: string): string =>
	crypto.createHash("sha256").update(s).digest("hex");

/**
 * What the session decision needs. `createRouter` builds every default and
 * accepts overrides for the cache, the flight table, the grant client and the
 * logger (#95 F4). The exchange handler itself is not here: the decision only
 * needs to know whether the exchange is on, and hands off with `ExchangeArgs`.
 */
export interface InjectionDeps {
	cfg: InjectionConfig["injection"];
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

/** What the exchange handler (F2) receives when the decision hands off to it. */
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
 * A session cookie pair the proxy refuses to forward (#23). Unlike the absent
 * case this deserves an operator's attention, so it is a distinct event at warn
 * (#73). Only the bounded reason class is logged, never the value bytes.
 * `action` tells the two outcomes apart: `forward` — every same-name pair was
 * refused and the request goes upstream anonymously; `fallback` — a malformed
 * pair was skipped and a later well-formed same-name pair is used (#74).
 */
const logCookieRejected = (
	logger: Logger,
	requestId: string,
	reason: CookieRejectReason,
	action: "forward" | "fallback",
): void => {
	logger.warn(
		{
			requestId,
			event: "injection.cookie_rejected",
			reason,
			action,
			metric: "auth_proxy_injection_cookie_rejected",
		},
		action === "forward"
			? "session cookie rejected, forwarding without Authorization"
			: "malformed session cookie pair skipped, using the next well-formed pair",
	);
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
	 * disabled. The exchange itself is decided by its handler (F2); this only
	 * hands off.
	 */
	if (exchangeEnabled && authorization !== undefined) {
		return {
			kind: "exchange",
			args: { requestId, authorization, sessionCookie: extraction.kind },
		};
	}

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
		if (cfg.stripInboundAuthorization && authorization) {
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
			{ requestId, event: "injection.no_cookie", action: "forward" },
			"no session cookie",
		);
		return forwardWithoutInjection("no_cookie");
	}

	if (extraction.kind === "rejected") {
		logCookieRejected(logger, requestId, extraction.reason, "forward");
		return forwardWithoutInjection("cookie_rejected");
	}

	if (extraction.skipped !== null) {
		logCookieRejected(logger, requestId, extraction.skipped, "fallback");
	}

	const sessionCookieValue = extraction.value;
	const cacheKey = sha256Hex(sessionCookieValue);
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
			if (err.status === 401) {
				logger.info(
					{ requestId, event: "injection.session_unauthorized", error: err.message },
					"grant failed",
				);
			} else if (err.code === "provider_config_error") {
				logger.error(
					{ requestId, event: "injection.provider_config_error", error: err.message },
					"grant failed",
				);
			} else if (err.code === "provider_invalid_response") {
				logger.error(
					{ requestId, event: "injection.provider_invalid_response", error: err.message },
					"grant failed",
				);
			} else {
				logger.error(
					{ requestId, event: "injection.provider_unavailable", error: err.message },
					"grant failed",
				);
			}
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
