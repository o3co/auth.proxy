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
import { createRequestIdMiddleware } from "@o3co/auth.utils/express";
import type { NextFunction, Request, Response } from "express";
import express from "express";
import proxy from "express-http-proxy";
import type { AppConfig } from "../../../config/application.schema.mjs";
import logger from "../../logger.mjs";
import { extractCookie } from "./cookie-extractor.mjs";
import {
	createSessionGrantClient,
	type SessionGrantClient,
	SessionGrantError,
} from "./session-grant-client.mjs";
import { createSingleFlight, type SingleFlight } from "./single-flight.mjs";
import { createTokenCache, type TokenCache } from "./token-cache.mjs";

type InjectionConfig = Extract<AppConfig["auth"], { mode: "injection" }>;

const sha256Hex = (s: string): string =>
	crypto.createHash("sha256").update(s).digest("hex");

interface Deps {
	tokenCache: TokenCache;
	singleFlight: SingleFlight<string>;
	grantClient: SessionGrantClient;
	cfg: InjectionConfig["injection"];
}

const computeExpiresAt = (
	providerExpiresIn: number | null,
	cfg: InjectionConfig["injection"],
): number => {
	const ttlMs =
		Math.min(
			cfg.tokenCache.ttlSeconds * 1000,
			(providerExpiresIn ?? cfg.tokenCache.ttlSeconds) * 1000,
		) -
		cfg.tokenCache.safetyMarginSeconds * 1000;
	return Date.now() + ttlMs;
};

const injectionMiddleware =
	(deps: Deps) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const { tokenCache, singleFlight, grantClient, cfg } = deps;
		const requestId = (req.headers["x-request-id"] as string | undefined) ?? "";
		const cookieHeader = req.headers.cookie;
		const sessionCookieValue = extractCookie(cookieHeader, cfg.sessionCookieName);

		if (sessionCookieValue === null) {
			logger.debug(
				{ requestId, event: "injection.no_cookie", action: "forward" },
				"no session cookie",
			);
			next();
			return;
		}

		const cacheKey = sha256Hex(sessionCookieValue);
		const cached = tokenCache.get(cacheKey);

		const applyAuthorization = (token: string): void => {
			if (req.headers.authorization) {
				logger.warn(
					{
						requestId,
						event: "injection.authorization_override",
						metric: "auth_proxy_injection_authorization_override",
					},
					"overriding inbound Authorization header",
				);
			}
			req.headers.authorization = `Bearer ${token}`;
		};

		if (cached !== null) {
			logger.debug({ requestId, event: "injection.cache_hit" }, "cache hit");
			applyAuthorization(cached);
			next();
			return;
		}

		try {
			const { value: token, wasWaiter } = await singleFlight.run(cacheKey, async () => {
				logger.info({ requestId, event: "injection.grant_fetch" }, "fetching grant");
				const result = await grantClient.exchange({
					sessionCookieValue,
					requestId,
				});
				const expiresAt = computeExpiresAt(result.expiresIn, cfg);
				if (expiresAt > Date.now()) {
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
			applyAuthorization(token);
			next();
		} catch (err) {
			if (err instanceof SessionGrantError) {
				const body = {
					error:
						err.code === "session_unauthorized" ? "session_required" : err.code,
					error_description: err.message,
				};
				if (err.retryAfter !== null) {
					res.setHeader("Retry-After", err.retryAfter);
				}
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
				res.status(err.status).json(body);
				return;
			}
			logger.error(
				{ requestId, event: "injection.unexpected_error", error: String(err) },
				"grant failed (unknown)",
			);
			res.status(502).json({
				error: "provider_unavailable",
				error_description: "provider call failed",
			});
		}
	};

export const createRouter = ({
	config,
}: {
	config: AppConfig;
}): express.Router => {
	if (config.auth.mode !== "injection") {
		throw new Error(
			`injection router requires auth.mode = "injection" (got "${config.auth.mode}")`,
		);
	}
	const cfg: InjectionConfig["injection"] = config.auth.injection;

	const router = express.Router();
	const tokenCache = createTokenCache({ maxEntries: cfg.tokenCache.maxEntries });
	const singleFlight = createSingleFlight<string>();
	const grantClient = createSessionGrantClient(cfg);

	router
		.use(createRequestIdMiddleware())
		.use((req: Request, _res: Response, next: NextFunction) => {
			logger.info(
				{
					"x-request-id": req.headers["x-request-id"],
					method: req.method,
					path: req.path,
				},
				"incoming request",
			);
			next();
		})
		.use(injectionMiddleware({ tokenCache, singleFlight, grantClient, cfg }))
		.use(
			proxy(config.upstream.baseURL, {
				limit: config.http.bodyLimitSize,
				proxyReqOptDecorator: async (proxyReqOpts, srcReq) => {
					if (srcReq?.headers?.authorization) {
						proxyReqOpts.headers.Authorization = srcReq.headers.authorization;
					}
					if (srcReq?.headers?.["x-request-id"]) {
						proxyReqOpts.headers["x-request-id"] = srcReq.headers["x-request-id"];
					}
					return proxyReqOpts;
				},
			}),
		);

	return router;
};
