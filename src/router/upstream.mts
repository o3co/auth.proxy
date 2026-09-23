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
 * What the decorator does. When an `Authorization` header arrived — empty
 * included, as the injection paths read presence (#95 F40, #133) — it sets
 * `Authorization`, in canonical casing, to the inbound value, and it re-sets
 * `x-request-id` to the value it already has.
 *
 * What it does not do: choose what is forwarded. What reaches upstream is
 * decided before this stage, on `req.headers`. express-http-proxy copies every
 * inbound header except `connection` and `host` onto the outbound request and
 * sets `connection: close` before any decorator runs (`reqHeaders` in
 * `express-http-proxy/lib/requestOptions.js`). Node lower-cases every inbound
 * header name in `req.headers`, so that copy already carries `authorization`.
 * Node's `setHeader` dedups header names case-insensitively and the last
 * write wins, so the decorator's `Authorization` replaces the name, not the
 * value: `Authorization` is sent once, and the `x-request-id` write changes
 * nothing on the wire. That is why `stripInboundAuthorization` deletes the
 * header from `req.headers` in `src/modes/injection/decision.mts` (see the
 * comment above `forwardWithoutInjection`) rather than acting here.
 *
 * Why it is kept (#132): for header-name casing compatibility. HTTP header
 * names are case-insensitive (RFC 9110 §5.1), so a conforming upstream sees no
 * difference; without the decorator an upstream would receive `authorization`
 * in lower case, and one that matches the name case-sensitively would miss it.
 * The casing on the wire is pinned by `__tests__/upstream-wire.test.mts`.
 */
export const createUpstreamProxy = (config: UpstreamStageConfig): RequestHandler =>
	proxy(config.upstream.baseURL, {
		limit: config.http.bodyLimitSize,
		proxyReqOptDecorator: async (proxyReqOpts, srcReq) => {
			// Presence, as the injection paths read it (#95 F40, #133): an empty
			// `Authorization:` is re-set in canonical casing too.
			if (srcReq?.headers?.authorization !== undefined) {
				proxyReqOpts.headers.Authorization = srcReq.headers.authorization;
			}
			if (srcReq?.headers?.["x-request-id"]) {
				proxyReqOpts.headers["x-request-id"] = srcReq.headers["x-request-id"];
			}
			return proxyReqOpts;
		},
	});
