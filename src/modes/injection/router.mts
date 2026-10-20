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
 * The injection-mode router: request id, the `incoming request` line, the
 * shared body limit, the injection middleware, the shared upstream stage,
 * then the shared error handler.
 *
 * `createRouter` builds the session path's cache, flight table and grant
 * client and — with the exchange on — the exchange's context, client, cache
 * and flight table, or takes them from `deps`; the exchange context is always
 * derived from config, never supplied, and so are the request source the
 * session grant and the exchange report a request's address and scheme from
 * (`auth.injection.trustedProxies`) and the same-origin gate in front of the
 * session cache (`auth.injection.publicOrigin`).
 */

import type { NextFunction, Request, Response } from "express";
import express from "express";
import type { AppConfig } from "../../../config/application.schema.mjs";
import { createRequestIdMiddleware } from "../../express/requestId.mjs";
import type { Logger } from "../../logger.mjs";
import defaultLogger from "../../logger.mjs";
import type { ClientAuthentication } from "../../oauth/client-authentication.mjs";
import { bodyLimitBytes, createBodyLimitGuard } from "../../router/body-limit.mjs";
import { createErrorHandler } from "../../router/error-handler.mjs";
import { createUpstreamProxy } from "../../router/upstream.mjs";
import { createSingleFlight } from "../../single-flight.mjs";
import { decideInjection, type InjectionDeps } from "./decision.mjs";
import {
	decideExchange,
	type ExchangeDeps,
	type ExchangeSettings,
	exchangeContext,
} from "./exchange.mjs";
import { createJwtBearerClient } from "./jwt-bearer-client.mjs";
import { createSameOriginGate } from "./origin-gate.mjs";
import { createRequestSource, type RequestSource, trustAllEntries } from "./request-source.mjs";
import { type CallerContext, createSessionGrantClient } from "./session-grant-client.mjs";
import { stageRefusals } from "./stage-refusals.mjs";
import { createTokenCache } from "./token-cache.mjs";

type InjectionConfig = Extract<AppConfig["auth"], { mode: "injection" }>;

/**
 * The exchange path's client, cache and flight table a caller may supply. See
 * `ExchangeDeps` for what each is and for the sharing contract on the cache
 * and the flight table.
 */
export type ExchangeDepsOverrides = Partial<Pick<ExchangeDeps, "client" | "tokenCache" | "singleFlight">>;

/** What `createRouter` builds by default and a caller may supply instead. */
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

/** A header the browser sent, as received; `null` when it sent none. */
const received = (value: string | string[] | undefined): string | null =>
	typeof value === "string" ? value : null;

/**
 * The browser request as the session grant tells the provider about it: its
 * own `Origin`, `Sec-Fetch-Site` and `Referer`, untouched, and the address and
 * scheme this proxy vouches for, which the exchange tells it too. The client's
 * own `X-Forwarded-*` count only through `requestSource`, which believes them
 * from a trusted proxy alone.
 */
const callerOf = (req: Request, requestSource: (req: Request) => RequestSource): CallerContext => ({
	origin: received(req.headers.origin),
	secFetchSite: received(req.headers["sec-fetch-site"]),
	referer: received(req.headers.referer),
	...requestSource(req),
});

/**
 * Reads the request, lets `decideInjection` decide — and, on its
 * `exchange` hand-off, `decideExchange` — then applies the outcome.
 *
 * `inject` and `forward_stripped` act on `req.headers` before the upstream
 * stage, not in the proxy's `proxyReqOptDecorator`: express-http-proxy copies
 * `req.headers` wholesale into the outbound request, so the decorator alone
 * would leave the original copy in place. An outcome kind this switch does not
 * know throws rather than leaving the request unanswered and the socket held.
 */
const injectionMiddleware =
	(
		deps: InjectionDeps,
		exchange: ExchangeDeps | null,
		requestSource: (req: Request) => RequestSource,
	) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const decided = await decideInjection(
			{
				requestId: (req.headers["x-request-id"] as string | undefined) ?? "",
				cookieHeader: req.headers.cookie,
				authorization: req.headers.authorization,
				caller: callerOf(req, requestSource),
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

/**
 * How the proxy authenticates as the exchange's client: its secret, or its key
 * with the provider's issuer as the assertion's audience. The schema admits
 * exactly one of the two, and a key only with an issuer.
 */
const exchangeCredentials = (
	cfg: InjectionConfig["injection"],
	exchange: ExchangeSettings,
): ClientAuthentication => {
	if (exchange.clientSecret !== null) {
		return { clientId: exchange.clientId, clientSecret: exchange.clientSecret };
	}
	if (exchange.clientKey !== null && cfg.providerIssuer !== null) {
		return { clientId: exchange.clientId, clientKey: exchange.clientKey, audience: cfg.providerIssuer };
	}
	throw new Error(
		"auth.injection.exchange needs clientSecret, or clientKey with auth.injection.providerIssuer",
	);
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
			credentials: exchangeCredentials(cfg, exchange),
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

	const limitBytes = bodyLimitBytes(config);
	const router = express.Router();
	const logger = overrides.logger ?? defaultLogger;
	const refusals = stageRefusals(logger);
	const requestSource = createRequestSource(cfg.trustedProxies);
	const trustAll = trustAllEntries(cfg.trustedProxies);
	if (trustAll.length > 0) {
		// Allowed, since a deployment may know its only peers are proxies, but
		// said once at boot: every client's X-Forwarded-* now reach the provider.
		// Only an entry that covers a family on its own is caught.
		logger.warn(
			{ event: "injection.trusted_proxies_trust_all", entries: trustAll },
			"auth.injection.trustedProxies trusts every address: any client can set the X-Forwarded-For and X-Forwarded-Proto the session grant and the exchange send",
		);
	}
	if (cfg.publicOrigin === null) {
		// Allowed, but said once at boot: browsers send a same-origin Referer
		// by default, which names an origin the gate has nothing to compare to,
		// so nearly every browser request misses the session cache.
		logger.warn(
			{ event: "injection.public_origin_unset" },
			"auth.injection.publicOrigin is unset: browser requests that send a Referer are not answered from the session cache, and each calls the provider",
		);
	}
	const exchange = cfg.exchange.enabled
		? buildExchangeDeps(cfg, cfg.exchange, overrides.exchange ?? {}, logger)
		: null;
	const deps: InjectionDeps = {
		cfg,
		tokenCache:
			overrides.tokenCache ?? createTokenCache({ maxEntries: cfg.tokenCache.maxEntries }),
		singleFlight: overrides.singleFlight ?? createSingleFlight<string>(),
		grantClient: overrides.grantClient ?? createSessionGrantClient(cfg),
		sameOriginGate: createSameOriginGate(cfg.publicOrigin),
		exchangeEnabled: exchange !== null,
		logger,
	};

	router
		.use(createRequestIdMiddleware())
		.use((req: Request, _res: Response, next: NextFunction) => {
			logger.info(
				{
					requestId: req.headers["x-request-id"],
					event: "injection.incoming_request",
					method: req.method,
					path: req.path,
				},
				"incoming request",
			);
			next();
		})
		.use(createBodyLimitGuard({ limitBytes, refusals }))
		.use(injectionMiddleware(deps, exchange, requestSource))
		.use(createUpstreamProxy(config))
		.use(createErrorHandler({ limitBytes, refusals }));

	return router;
};
