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
import defaultLogger from "../../logger.mjs";
import { createUpstreamProxy } from "../../router/upstream.mjs";
import { decideValidation, type Introspector, type ValidationDeps } from "./decision.mjs";
import { buildAuthHeader, type ClientCredentials, introspect } from "./introspect.mjs";

type ValidationConfig = Extract<AppConfig["auth"], { mode: "validation" }>;

/** What `createRouter` builds by default and a caller may supply instead (#95 F3). */
export type ValidationDepsOverrides = Partial<ValidationDeps>;

/**
 * Reads the two headers, lets `decideValidation` decide, applies the outcome.
 * `forward` leaves `req.headers` untouched, so the upstream receives the
 * inbound `Authorization` bytes (F14). An outcome kind this switch does not
 * know throws rather than leaving the request unanswered and the socket held.
 */
const validationMiddleware =
	(deps: ValidationDeps) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const outcome = await decideValidation(
			{
				requestId: (req.headers["x-request-id"] as string | undefined) ?? "",
				authorization: req.headers.authorization,
			},
			deps,
		);
		switch (outcome.kind) {
			case "forward":
				return next();
			case "reject":
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
 * The concrete `introspect` bound to this router's config: URL, cache bounds,
 * timeout, and the credential choice per token (`buildAuthHeader`).
 */
const bindIntrospect = (validation: ValidationConfig["validation"]): Introspector => {
	const introspectUrl: string = validation.introspect.url;
	const cacheTtlSec: number = validation.introspect.cacheTtlSec;
	const cacheMaxEntries: number = validation.introspect.cacheMaxEntries;
	const introspectTimeoutMs: number = validation.introspect.timeoutMs;

	const { clientId, clientSecret } = validation.client;
	const credentials: ClientCredentials | null =
		clientId !== null && clientSecret !== null ? { clientId, clientSecret } : null;

	return (token, requestId) =>
		introspect(
			token,
			introspectUrl,
			cacheTtlSec,
			requestId,
			buildAuthHeader(credentials, token),
			cacheMaxEntries,
			introspectTimeoutMs,
		);
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

	const router = express.Router();
	const logger = overrides.logger ?? defaultLogger;
	const deps: ValidationDeps = {
		introspect: overrides.introspect ?? bindIntrospect(validation),
		logger,
	};

	router
		.use(createRequestIdMiddleware())
		.use((req: Request, _res: Response, next) => {
			logger.info(
				{
					"x-request-id": req.headers["x-request-id"],
					method: req.method,
					path: req.path,
				},
				"incoming request",
			);
			return next();
		})
		.use(validationMiddleware(deps))
		.use(createUpstreamProxy(config));

	return router;
};
