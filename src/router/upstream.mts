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
 * The upstream proxy stage both mode routers end with, `createUpstreamProxy`,
 * and the two config fields it reads. What its decorator does and does not
 * do, and why it is kept, is the doc comment on the function.
 */

import type { RequestHandler } from "express";
import proxy from "express-http-proxy";
import { bodyLimitBytes } from "./body-limit.mjs";

/** The two config fields the stage reads. `AppConfig` satisfies it structurally. */
export interface UpstreamStageConfig {
	upstream: { baseURL: string };
	http: { bodyLimitSize: string };
}

/**
 * The byte count in the form the library keeps. It resolves `limit || "1mb"`,
 * so zero goes as `"0"`, which its body reader reads as 0; every other count
 * goes as the number, since a large one's string is exponent notation, which
 * the reader would read as 1.
 */
const upstreamLimit = (bytes: number): number | string => (bytes === 0 ? "0" : bytes);

/**
 * The upstream proxy stage — the last stage of either mode's router before
 * its error handler. It is assembly (built from `upstream.baseURL` and
 * `http.bodyLimitSize`, in bytes), not a mode's decision, so both routers
 * mount this one function. It reads the request body against that limit; a
 * body over it that declared no length is refused here, as an error the
 * router's error handler answers.
 *
 * What the decorator does. When `req.headers.authorization` is present as this
 * stage runs — empty included, as the injection paths read presence — it sets
 * `Authorization`, in canonical casing, to that value: the minted token after
 * an `inject`, the inbound header otherwise. It also re-sets `x-request-id` to
 * the value it already has.
 *
 * It also reframes the body. The stage reads the whole body before sending it
 * on, and the library frames the outbound request by a `Content-Length` it
 * sets itself, so the decorator drops the inbound `Transfer-Encoding` and the
 * `Trailer` that announces fields of it: they described how the caller's
 * message was framed, not this one. RFC 9112 §6.2 forbids a sender to put a
 * `Content-Length` beside a `Transfer-Encoding`, and a strict upstream — Node's
 * parser, for one — refuses the pair. Only `chunked` is taken off: Node
 * removes the chunked framing and hands on whatever other coding is left
 * still applied, which the stage cannot undo or describe, so a request with
 * any other transfer coding is refused `501` (RFC 9112 §6.1) rather than
 * forwarded as if its coded bytes were the body.
 *
 * What it does not do: choose which fields are forwarded, beyond that
 * framing. Every other choice is made before this stage, on `req.headers`. express-http-proxy copies every
 * inbound header except `connection` and `host` onto the outbound request and
 * sets `connection: close` before any decorator runs (`reqHeaders` in
 * `express-http-proxy/lib/requestOptions.js`). Node lower-cases every inbound
 * header name in `req.headers`, so that copy already carries `authorization`.
 * Node's `setHeader` dedups header names case-insensitively and the last
 * write wins, so the decorator's `Authorization` replaces the name, not the
 * value: `Authorization` is sent once, and the `x-request-id` write changes
 * nothing on the wire. That is why `stripInboundAuthorization` takes effect
 * by deleting the header from `req.headers`, in the `forward_stripped` case of
 * `injectionMiddleware` (`src/modes/injection/router.mts`), rather than here.
 *
 * Why it is kept: the framing above, and header-name casing. HTTP header names are case-insensitive
 * (RFC 9110 §5.1), so a conforming upstream sees no difference; without the
 * decorator an upstream would receive `authorization` in lower case, and one
 * that matches the name case-sensitively would miss it. The casing on the
 * wire is pinned by `__tests__/upstream-wire.test.mts`.
 */
export const createUpstreamProxy = (config: UpstreamStageConfig): RequestHandler =>
	proxy(config.upstream.baseURL, {
		limit: upstreamLimit(bodyLimitBytes(config)),
		proxyReqOptDecorator: async (proxyReqOpts, srcReq) => {
			// Presence, as the injection paths read it: an empty
			// `Authorization:` is re-set in canonical casing too.
			if (srcReq?.headers?.authorization !== undefined) {
				proxyReqOpts.headers.Authorization = srcReq.headers.authorization;
			}
			if (srcReq?.headers?.["x-request-id"]) {
				proxyReqOpts.headers["x-request-id"] = srcReq.headers["x-request-id"];
			}
			// The body's inbound framing: see the doc comment. The library copied
			// the fields from `req.headers`, so the names are lower case.
			const coding = srcReq?.headers?.["transfer-encoding"];
			if (coding !== undefined && coding.trim().toLowerCase() !== "chunked") {
				throw Object.assign(new Error(`transfer coding not supported: ${coding}`), { status: 501 });
			}
			delete proxyReqOpts.headers["transfer-encoding"];
			delete proxyReqOpts.headers.trailer;
			return proxyReqOpts;
		},
	});
