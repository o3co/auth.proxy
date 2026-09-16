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
import type { NextFunction, Request, Response } from "express";
import type { ExchangeConfig } from "../../../config/application.schema.mjs";
import logger from "../../logger.mjs";
import { parseBearerAssertion } from "./bearer-assertion.mjs";
import {
	createJwtBearerClient,
	JWT_BEARER_GRANT_TYPE,
	JwtBearerError,
} from "./jwt-bearer-client.mjs";
import { buildTokenUrl } from "./session-grant-client.mjs";
import { createSingleFlight } from "./single-flight.mjs";
import { createTokenCache } from "./token-cache.mjs";

/** Everything besides the assertion that changes what the provider issues. */
export interface ExchangeContext {
	tokenEndpoint: string;
	clientId: string;
	scope: string | null;
	audience: string | null;
	resource: string | null;
}

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
 * cache": the smallest of the configured TTL, the provider's `expires_in` and
 * the assertion's remaining validity (its unverified `exp`), minus the safety
 * margin.
 *
 * The unverified `exp` is safe to use here because it can only shorten the
 * lifetime. An assertion without one is not cached at all — there is no
 * validity to bound the result by.
 */
export const computeExchangeExpiresAt = ({
	now,
	ttlSeconds,
	safetyMarginSeconds,
	expiresIn,
	assertionExpiresAt,
}: {
	now: number;
	ttlSeconds: number;
	safetyMarginSeconds: number;
	expiresIn: number | null;
	assertionExpiresAt: number | null;
}): number | null => {
	if (assertionExpiresAt === null) {
		return null;
	}
	const lifetimeMs =
		Math.min(
			ttlSeconds * 1000,
			expiresIn === null ? Number.POSITIVE_INFINITY : expiresIn * 1000,
			assertionExpiresAt * 1000 - now,
		) -
		safetyMarginSeconds * 1000;
	return lifetimeMs > 0 ? now + lifetimeMs : null;
};

export interface ExchangeHandlerConfig {
	providerOrigin: string;
	timeoutMs: number;
	tokenCache: { ttlSeconds: number; maxEntries: number; safetyMarginSeconds: number };
	exchange: Extract<ExchangeConfig, { enabled: true }>;
}

export type ExchangeHandler = (
	req: Request,
	res: Response,
	next: NextFunction,
	args: { requestId: string; authorization: string; sessionCookie: "absent" | "found" | "rejected" },
) => Promise<void>;

const respond = (
	res: Response,
	status: number,
	error: string,
	description: string,
	retryAfter: string | null = null,
): void => {
	if (retryAfter !== null) {
		res.setHeader("Retry-After", retryAfter);
	}
	// No WWW-Authenticate, as on the session path: the body is the contract.
	res.status(status).json({ error, error_description: description });
};

const logFailure = (requestId: string, err: JwtBearerError): void => {
	const fields = { requestId, providerError: err.providerError, error: err.message };
	switch (err.code) {
		case "credential_rejected":
			logger.info({ ...fields, event: "injection.exchange_rejected" }, "exchange rejected");
			return;
		case "exchange_not_permitted":
			logger.warn(
				{ ...fields, event: "injection.exchange_not_permitted" },
				"exchange not permitted",
			);
			return;
		case "provider_config_error":
			logger.error(
				{ ...fields, event: "injection.exchange_provider_config_error" },
				"exchange failed",
			);
			return;
		case "provider_invalid_response":
			logger.error(
				{ ...fields, event: "injection.exchange_provider_invalid_response" },
				"exchange failed",
			);
			return;
		case "provider_unavailable":
			logger.error(
				{ ...fields, event: "injection.exchange_provider_unavailable" },
				"exchange failed",
			);
			return;
	}
};

/**
 * The external credential exchange (#90) — the injection-mode path for a
 * request that carries an `Authorization` header while
 * `auth.injection.exchange.enabled` is on.
 *
 * The proxy is a token-endpoint client here and nothing more: it submits the
 * inbound JWT as an RFC 7523 assertion to its configured provider, and on
 * success REPLACES the inbound header with the issued token. Which issuers are
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
export const createExchangeHandler = (cfg: ExchangeHandlerConfig): ExchangeHandler => {
	const { exchange } = cfg;
	const client = createJwtBearerClient({
		providerOrigin: cfg.providerOrigin,
		timeoutMs: cfg.timeoutMs,
		clientId: exchange.clientId,
		clientSecret: exchange.clientSecret,
		scope: exchange.scope,
		audience: exchange.audience,
		resource: exchange.resource,
	});
	// Its own instances: the session cache and its single-flight never see an
	// exchange entry, and vice versa. Sized by the same tokenCache.maxEntries.
	const cache = createTokenCache({ maxEntries: cfg.tokenCache.maxEntries });
	const singleFlight = createSingleFlight<string>();
	const context: ExchangeContext = {
		tokenEndpoint: buildTokenUrl(cfg.providerOrigin),
		clientId: exchange.clientId,
		scope: exchange.scope,
		audience: exchange.audience,
		resource: exchange.resource,
	};
	const allowedIssuers =
		exchange.allowedIssuers.length > 0 ? new Set(exchange.allowedIssuers) : null;

	return async (req, res, next, { requestId, authorization, sessionCookie }) => {
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
			respond(
				res,
				400,
				"credential_ambiguous",
				"send either the session cookie or an Authorization header, not both",
			);
			return;
		}

		const parsed = parseBearerAssertion(authorization);
		if (parsed.kind === "unsupported") {
			logger.info(
				{ requestId, event: "injection.exchange_credential_unsupported", reason: parsed.reason },
				"Authorization is not a Bearer JWT assertion",
			);
			respond(
				res,
				401,
				"credential_unsupported",
				"Authorization must be a Bearer JWT assertion",
			);
			return;
		}

		// A prefilter only: it can refuse, never admit, and `iss` selects
		// nothing. The unverified value is not logged.
		if (allowedIssuers !== null && (parsed.issuer === null || !allowedIssuers.has(parsed.issuer))) {
			logger.info(
				{ requestId, event: "injection.exchange_issuer_refused" },
				"assertion issuer is not in allowedIssuers",
			);
			respond(res, 401, "credential_rejected", "the credential was rejected");
			return;
		}

		const cacheKey = exchangeCacheKey(context, parsed.assertion);
		const replace = (token: string): void => {
			req.headers.authorization = `Bearer ${token}`;
			next();
		};

		// No await between this lookup and `singleFlight.run`: a request that
		// misses here joins a flight still in progress rather than starting a
		// second submission of the same assertion.
		const cached = cache.get(cacheKey);
		if (cached !== null) {
			logger.debug({ requestId, event: "injection.exchange_cache_hit" }, "cache hit");
			replace(cached);
			return;
		}

		try {
			const { value: token, wasWaiter } = await singleFlight.run(cacheKey, async () => {
				logger.info({ requestId, event: "injection.exchange_fetch" }, "exchanging assertion");
				const result = await client.exchange({ assertion: parsed.assertion, requestId });
				const expiresAt = computeExchangeExpiresAt({
					now: Date.now(),
					ttlSeconds: cfg.tokenCache.ttlSeconds,
					safetyMarginSeconds: cfg.tokenCache.safetyMarginSeconds,
					expiresIn: result.expiresIn,
					assertionExpiresAt: parsed.expiresAt,
				});
				if (expiresAt !== null) {
					cache.set(cacheKey, result.accessToken, expiresAt);
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
			replace(token);
		} catch (err) {
			if (err instanceof JwtBearerError) {
				logFailure(requestId, err);
				respond(res, err.status, err.code, err.message, err.retryAfter);
				return;
			}
			logger.error(
				{ requestId, event: "injection.exchange_unexpected_error", error: String(err) },
				"exchange failed (unknown)",
			);
			respond(res, 502, "provider_unavailable", "provider call failed");
		}
	};
};
