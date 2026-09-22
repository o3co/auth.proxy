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
import type { RequestHandler } from "express";
import proxy from "express-http-proxy";
import type { AppConfig } from "../../config/application.schema.mjs";

/**
 * The upstream proxy stage — the last middleware of either mode's router.
 *
 * It is assembly (built from `upstream.baseURL` and `http.bodyLimitSize`), not
 * a mode's decision, so both routers mount this one function instead of each
 * carrying its own copy (#95 F18). The decorator copies the inbound
 * `Authorization` and `x-request-id` onto the proxied request when present;
 * upstream receives the inbound bytes unchanged.
 */
export const createUpstreamProxy = (config: AppConfig): RequestHandler =>
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
	});
