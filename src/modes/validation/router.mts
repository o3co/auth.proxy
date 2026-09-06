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

import type { Request, Response } from "express";
import express from "express";
import proxy from "express-http-proxy";
import type { AppConfig } from "../../../config/application.schema.mjs";
import { extractBearerToken } from "../../express/bearer.mjs";
import { createRequestIdMiddleware } from "../../express/requestId.mjs";
import logger from "../../logger.mjs";
import {
	buildAuthHeader,
	type ClientCredentials,
	IntrospectHttpError,
	introspect,
} from "./introspect.mjs";

type ValidationConfig = Extract<AppConfig["auth"], { mode: "validation" }>;

export const createRouter = ({ config }: { config: AppConfig }): express.Router => {
	if (config.auth.mode !== "validation") {
		throw new Error(
			`validation router requires auth.mode = "validation" (got "${config.auth.mode}")`,
		);
	}
	const validation: ValidationConfig["validation"] = config.auth.validation;

	const router = express.Router();
	const introspectUrl: string = validation.introspect.url;
	const cacheTtlSec: number = validation.introspect.cacheTtlSec;
	const cacheMaxEntries: number = validation.introspect.cacheMaxEntries;
	const introspectTimeoutMs: number = validation.introspect.timeoutMs;

	const { clientId, clientSecret } = validation.client;
	const credentials: ClientCredentials | null =
		clientId !== null && clientSecret !== null ? { clientId, clientSecret } : null;

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
		.use(async (req: Request, res: Response, next) => {
			if (!req?.headers?.authorization) {
				return next();
			}

			const requestId = req.headers["x-request-id"] as string;
			const bearer = extractBearerToken(req.headers.authorization);

			if (!bearer) {
				return res.status(400).json({ code: 400, message: "Invalid Token Type" });
			}

			const authHeader = buildAuthHeader(credentials, bearer.token);

			try {
				const result = await introspect(
					bearer.token,
					introspectUrl,
					cacheTtlSec,
					requestId,
					authHeader,
					cacheMaxEntries,
					introspectTimeoutMs,
				);
				if (!result.active) {
					return res.status(401).json({ code: 401, message: "Invalid Token" });
				}
			} catch (e) {
				logger.error({ "x-request-id": requestId, error: e }, "introspect failed");
				if (e instanceof IntrospectHttpError && e.status === 401) {
					return res.status(401).json({ code: 401, message: "Invalid Token" });
				}
				return res.status(500).json({ code: 500, message: "Internal Server Error" });
			}

			return next();
		})
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
