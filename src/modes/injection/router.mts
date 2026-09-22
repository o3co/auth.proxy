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
import type { NextFunction, Request, Response } from "express";
import express from "express";
import type { AppConfig } from "../../../config/application.schema.mjs";
import { createRequestIdMiddleware } from "../../express/requestId.mjs";
import type { Logger } from "../../logger.mjs";
import defaultLogger from "../../logger.mjs";
import { createUpstreamProxy } from "../../router/upstream.mjs";
import { decideInjection, type InjectionDeps } from "./decision.mjs";
import {
	decideExchange,
	type ExchangeDeps,
	type ExchangeSettings,
	exchangeContext,
} from "./exchange.mjs";
import { createJwtBearerClient } from "./jwt-bearer-client.mjs";
import { createSessionGrantClient } from "./session-grant-client.mjs";
import { createSingleFlight } from "./single-flight.mjs";
import { createTokenCache } from "./token-cache.mjs";

type InjectionConfig = Extract<AppConfig["auth"], { mode: "injection" }>;

/**
 * The exchange path's client, cache and flight table a caller may supply
 * (#95 F2, F4). See `ExchangeDeps` for what each is and for the sharing
 * contract on the cache and the flight table (#95 F33).
 */
export type ExchangeDepsOverrides = Partial<Pick<ExchangeDeps, "client" | "tokenCache" | "singleFlight">>;

/** What `createRouter` builds by default and a caller may supply instead (#95 F4). */
export type InjectionDepsOverrides = Partial<
	Pick<InjectionDeps, "tokenCache" | "singleFlight" | "grantClient" | "logger">
> & {
	/**
	 * Accepted only while `auth.injection.exchange.enabled` is on — any value,
	 * even `{}`, is refused at construction otherwise, since an injected client
	 * silently dropped would leave the inbound `Authorization` on the forward
	 * path. The logger is the shared `deps.logger`.
	 */
	exchange?: ExchangeDepsOverrides;
};

/**
 * `createRouter` sets `deps.exchangeEnabled` from these very deps, so the
 * session decision hands off only when there are some; a null here is a
 * wiring bug, thrown rather than left as an unanswered request.
 */
const requireExchange = (exchange: ExchangeDeps | null): ExchangeDeps => {
	if (exchange === null) {
		throw new Error("injection outcome `exchange` while the exchange is disabled");
	}
	return exchange;
};

/**
 * Reads the three headers, lets `decideInjection` decide — and, on its
 * `exchange` hand-off, `decideExchange` — then applies the outcome.
 *
 * `inject` and `forward_stripped` act on `req.headers`, before the upstream
 * stage, rather than in the proxy's `proxyReqOptDecorator`: express-http-proxy
 * copies `req.headers` wholesale into the outbound request, so the decorator
 * alone would leave the original copy in place. An outcome kind this switch
 * does not know throws rather than leaving the request unanswered and the
 * socket held.
 */
const injectionMiddleware =
	(deps: InjectionDeps, exchange: ExchangeDeps | null) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const decided = await decideInjection(
			{
				requestId: (req.headers["x-request-id"] as string | undefined) ?? "",
				cookieHeader: req.headers.cookie,
				authorization: req.headers.authorization,
			},
			deps,
		);
		const outcome =
			decided.kind === "exchange"
				? await decideExchange(decided.args, requireExchange(exchange))
				: decided;
		switch (outcome.kind) {
			case "forward":
				return next();
			case "forward_stripped":
				// `delete`, not `= undefined`: express-http-proxy copies own
				// enumerable properties, and Node's `setHeader` throws
				// ERR_HTTP_INVALID_HEADER_VALUE on an undefined value.
				delete req.headers.authorization;
				return next();
			case "inject":
				req.headers.authorization = `Bearer ${outcome.token}`;
				return next();
			case "respond":
				if (outcome.retryAfter !== null) {
					res.setHeader("Retry-After", outcome.retryAfter);
				}
				res.status(outcome.status).json(outcome.body);
				return;
			default: {
				const _exhaustive: never = outcome;
				throw new Error(
					`unhandled injection outcome: ${(_exhaustive as { kind: string }).kind}`,
				);
			}
		}
	};

/** The exchange path's deps: what `createRouter` builds, or what the caller supplied. */
const buildExchangeDeps = (
	cfg: InjectionConfig["injection"],
	exchange: ExchangeSettings,
	overrides: ExchangeDepsOverrides,
	logger: Logger,
): ExchangeDeps => ({
	context: exchangeContext(cfg.providerOrigin, exchange),
	// Built once: the prefilter runs on every exchange request.
	allowedIssuers: new Set(exchange.allowedIssuers),
	cachePolicy: { ttlSeconds: cfg.tokenCache.ttlSeconds, safetyMarginSeconds: cfg.tokenCache.safetyMarginSeconds },
	client:
		overrides.client ??
		createJwtBearerClient({
			providerOrigin: cfg.providerOrigin,
			timeoutMs: cfg.timeoutMs,
			clientId: exchange.clientId,
			clientSecret: exchange.clientSecret,
			scope: exchange.scope,
			audience: exchange.audience,
			resource: exchange.resource,
		}),
	// Its own instances, sized by the same tokenCache.maxEntries: the session
	// cache and its single-flight never see an exchange entry, and vice versa.
	tokenCache: overrides.tokenCache ?? createTokenCache({ maxEntries: cfg.tokenCache.maxEntries }),
	singleFlight: overrides.singleFlight ?? createSingleFlight<string>(),
	logger,
});

export const createRouter = ({
	config,
	deps: overrides = {},
}: {
	config: AppConfig;
	deps?: InjectionDepsOverrides;
}): express.Router => {
	if (config.auth.mode !== "injection") {
		throw new Error(
			`injection router requires auth.mode = "injection" (got "${config.auth.mode}")`,
		);
	}
	const cfg: InjectionConfig["injection"] = config.auth.injection;
	if (!cfg.exchange.enabled && overrides.exchange !== undefined) {
		throw new Error("deps.exchange supplied while auth.injection.exchange.enabled is false");
	}

	const router = express.Router();
	const logger = overrides.logger ?? defaultLogger;
	const exchange = cfg.exchange.enabled
		? buildExchangeDeps(cfg, cfg.exchange, overrides.exchange ?? {}, logger)
		: null;
	const deps: InjectionDeps = {
		cfg,
		tokenCache:
			overrides.tokenCache ?? createTokenCache({ maxEntries: cfg.tokenCache.maxEntries }),
		singleFlight: overrides.singleFlight ?? createSingleFlight<string>(),
		grantClient: overrides.grantClient ?? createSessionGrantClient(cfg),
		exchangeEnabled: exchange !== null,
		logger,
	};

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
		.use(injectionMiddleware(deps, exchange))
		.use(createUpstreamProxy(config));

	return router;
};
