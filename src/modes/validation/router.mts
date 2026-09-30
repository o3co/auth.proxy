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
 * The validation-mode router: request id, the `incoming request` line, the
 * shared body limit, the validation middleware, the shared upstream stage,
 * then the shared error handler.
 *
 * `createRouter` builds the introspector over a client, a cache and a flight
 * table of its own (`buildIntrospector`), or takes one from `deps.introspect`.
 */

import { STATUS_CODES } from "node:http";
import type { NextFunction, Request, Response } from "express";
import express from "express";
import type { AppConfig } from "../../../config/application.schema.mjs";
import { createRequestIdMiddleware } from "../../express/requestId.mjs";
import type { Logger } from "../../logger.mjs";
import defaultLogger from "../../logger.mjs";
import { bodyLimitBytes, createBodyLimitGuard } from "../../router/body-limit.mjs";
import { createErrorHandler } from "../../router/error-handler.mjs";
import type { ModeRefusals } from "../../router/refusal.mjs";
import { createUpstreamProxy } from "../../router/upstream.mjs";
import { createSingleFlight } from "../../single-flight.mjs";
import {
	decideValidation,
	type Introspector,
	type ValidationDeps,
	type ValidationPolicy,
} from "./decision.mjs";
import { createIntrospector } from "./introspect.mjs";
import { createIntrospectionCache } from "./introspection-cache.mjs";
import {
	type ClientAuthentication,
	createIntrospectionClient,
	type IntrospectionResult,
} from "./introspection-client.mjs";

type ValidationConfig = Extract<AppConfig["auth"], { mode: "validation" }>;

/** What `createRouter` builds by default and a caller may supply instead. */
export type ValidationDepsOverrides = Partial<ValidationDeps>;

/**
 * Reads the two headers, lets `decideValidation` decide, applies the outcome.
 * `forward` leaves `req.headers` untouched, so the upstream receives the
 * inbound `Authorization` bytes. An outcome kind this switch does not
 * know throws rather than leaving the request unanswered and the socket held.
 */
const validationMiddleware =
	(deps: ValidationDeps, policy: ValidationPolicy) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const outcome = await decideValidation(
			{
				requestId: (req.headers["x-request-id"] as string | undefined) ?? "",
				authorization: req.headers.authorization,
			},
			deps,
			policy,
		);
		switch (outcome.kind) {
			case "forward":
				return next();
			case "reject":
				// Before the body because headers must precede the send. Which
				// refusals carry one at all is the decision's, not this
				// switch's — see `challengeFor` in `decision.mts`.
				if (outcome.challenge !== null) {
					res.setHeader("WWW-Authenticate", outcome.challenge);
				}
				res.status(outcome.status).json(outcome.body);
				return;
			default: {
				const _exhaustive: never = outcome;
				throw new Error(
					`unhandled validation outcome: ${(_exhaustive as { kind: string }).kind}`,
				);
			}
		}
	};

/**
 * The shared stages' refusals in this mode's vocabulary: the
 * `{ "code", "message" }` body every validation refusal has, and
 * `validation.*` events with the `Error` itself under `error`. A body over
 * the limit is the caller's to fix, as is any other `4xx`, so both are logged
 * at info; anything else is the proxy or its upstream failing, at error.
 */
const stageRefusals = (logger: Logger): ModeRefusals => ({
	log: (requestId, refusal) => {
		if (refusal.reason === "body_too_large") {
			const { limitBytes, contentLength } = refusal;
			logger.info(
				{ requestId, event: "validation.body_too_large", limitBytes, contentLength },
				"request body over the limit",
			);
			return;
		}
		const line = { requestId, event: "validation.request_failed", error: refusal.error };
		if (refusal.status < 500) logger.info(line, "request failed");
		else logger.error(line, "request failed");
	},
	body: (refusal) => ({ code: refusal.status, message: STATUS_CODES[refusal.status] ?? "Error" }),
});

/**
 * How the proxy authenticates to introspection: its secret, its key with the
 * provider's issuer as the assertion's audience, or nothing, when the inbound
 * token is the credential. The schema admits exactly these shapes.
 */
const introspectionCredentials = (
	validation: ValidationConfig["validation"],
): ClientAuthentication | null => {
	const { clientId, clientSecret, clientKey } = validation.client;
	if (clientId === null) return null;
	if (clientSecret !== null) return { clientId, clientSecret };
	if (clientKey !== null && validation.providerIssuer !== null) {
		return { clientId, clientKey, audience: validation.providerIssuer };
	}
	throw new Error(
		"auth.validation.client needs clientSecret, or clientKey with auth.validation.providerIssuer",
	);
};

/**
 * The bundled introspector for this router: the provider's endpoint behind
 * `IntrospectionClient`, a cache this router owns, and the reading of the
 * response between them. Each router builds its own, so routers in one
 * process share no cache.
 */
const buildIntrospector = (validation: ValidationConfig["validation"]): Introspector => {
	const credentials = introspectionCredentials(validation);

	return createIntrospector({
		client: createIntrospectionClient({
			url: validation.introspect.url,
			timeoutMs: validation.introspect.timeoutMs,
			credentials,
		}),
		cache: createIntrospectionCache({ maxEntries: validation.introspect.cacheMaxEntries }),
		// The router's own, like the cache: not supplied through `deps`, because
		// a caller that supplies `deps.introspect` replaces everything below
		// this seam and owns its own coalescing.
		singleFlight: createSingleFlight<IntrospectionResult>(),
		cacheTtlSec: validation.introspect.cacheTtlSec,
	});
};

export const createRouter = ({
	config,
	deps: overrides = {},
}: {
	config: AppConfig;
	deps?: ValidationDepsOverrides;
}): express.Router => {
	if (config.auth.mode !== "validation") {
		throw new Error(
			`validation router requires auth.mode = "validation" (got "${config.auth.mode}")`,
		);
	}
	const validation: ValidationConfig["validation"] = config.auth.validation;

	const limitBytes = bodyLimitBytes(config);
	const router = express.Router();
	const logger = overrides.logger ?? defaultLogger;
	const refusals = stageRefusals(logger);
	const deps: ValidationDeps = {
		introspect: overrides.introspect ?? buildIntrospector(validation),
		logger,
	};

	router
		.use(createRequestIdMiddleware())
		.use((req: Request, _res: Response, next) => {
			logger.info(
				{
					requestId: req.headers["x-request-id"],
					event: "validation.incoming_request",
					method: req.method,
					path: req.path,
				},
				"incoming request",
			);
			return next();
		})
		.use(createBodyLimitGuard({ limitBytes, refusals }))
		.use(validationMiddleware(deps, { realm: validation.realm }))
		.use(createUpstreamProxy(config))
		.use(createErrorHandler({ limitBytes, refusals }));

	return router;
};
