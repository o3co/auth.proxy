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

/** The two config fields the stage reads. `AppConfig` satisfies it structurally. */
export interface UpstreamStageConfig {
	upstream: { baseURL: string };
	http: { bodyLimitSize: string };
}

/**
 * The upstream proxy stage — the last middleware of either mode's router.
 *
 * It is assembly (built from `upstream.baseURL` and `http.bodyLimitSize`), not
 * a mode's decision, so both routers mount this one function instead of each
 * carrying its own copy (#95 F18).
 *
 * What reaches upstream is decided before this stage, on `req.headers`.
 * express-http-proxy copies every inbound header except `connection` and
 * `host` onto the outbound request and sets `connection: close` before any
 * decorator runs (`reqHeaders` in `express-http-proxy/lib/requestOptions.js`).
 * So this decorator does not choose what is forwarded. It re-sets
 * `Authorization` in canonical casing beside the lowercase copy the library
 * already made — Node's `setHeader` dedups header names case-insensitively
 * and the last write wins, so only the casing on the wire changes — and it
 * re-sets `x-request-id` to the value already there, a wire no-op. That is
 * why `stripInboundAuthorization` deletes the header from `req.headers` in
 * `src/modes/injection/decision.mts` (see the comment above
 * `forwardWithoutInjection`) rather than acting here. Whether to drop this
 * decorator is tracked with F14 on #95.
 */
export const createUpstreamProxy = (config: UpstreamStageConfig): RequestHandler =>
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
