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

/**
 * The upstream failing rather than the request, before its answer started: it
 * could not be reached, its TLS handshake failed, or it dropped the exchange
 * or answered something that is not HTTP (`502`), or it timed out (`504`,
 * RFC 9110 §15.6.5). `cause` is what the connection threw. The router's error
 * handler answers it as the `upstream_unavailable` refusal.
 */
export class UpstreamUnavailableError extends Error {
	constructor(
		readonly status: 502 | 504,
		cause: unknown,
	) {
		super(`upstream unavailable: ${cause instanceof Error ? cause.message : String(cause)}`, {
			cause,
		});
		this.name = "UpstreamUnavailableError";
	}
}

/** The connection failures `UpstreamUnavailableError` stands for, by the code Node gives them. */
const CONNECTION_FAILURES = new Set([
	"ECONNREFUSED",
	"ECONNRESET",
	"EPIPE",
	"ENOTFOUND",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"EHOSTDOWN",
	"ENETUNREACH",
	"ENETDOWN",
	"EPROTO",
]);
/**
 * An `https` upstream whose certificate or handshake Node refused: OpenSSL's
 * verify codes (`CERT_HAS_EXPIRED`, `DEPTH_ZERO_SELF_SIGNED_CERT`, …) and
 * Node's own TLS codes (`ERR_TLS_CERT_ALTNAME_INVALID`, …).
 */
const TLS_FAILURE =
	/^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_SELF_SIGNED_CERT$|SELF_SIGNED_CERT_IN_CHAIN$)/;
/**
 * The connection timing out, on connect or on an established connection. The
 * library's own `timeout` option, which this stage does not set, would fail as
 * a hang-up, not as one of these.
 */
const TIMEOUTS = new Set(["ETIMEDOUT"]);

/**
 * What the library rejects with, handed on to the router: a failure of the
 * connection to the upstream as an `UpstreamUnavailableError`, anything else
 * as it came. Everything the library does before the upstream's answer starts
 * fails through here — the body read, which carries its own status (a body
 * over the limit, one that ended early), and the decorator's refusal of a
 * transfer coding — so only an error with no status of its own and the code
 * of a connection failure is the upstream's.
 */
const toUpstreamFailure = (err: unknown): unknown => {
	if (typeof err !== "object" || err === null) return err;
	const { status, statusCode, code } = err as { status?: unknown; statusCode?: unknown; code?: unknown };
	if (status !== undefined || statusCode !== undefined || typeof code !== "string") return err;
	if (TIMEOUTS.has(code)) return new UpstreamUnavailableError(504, err);
	// `HPE_*`: Node's HTTP parser could not read what the upstream sent.
	if (CONNECTION_FAILURES.has(code) || TLS_FAILURE.test(code) || code.startsWith("HPE_")) {
		return new UpstreamUnavailableError(502, err);
	}
	return err;
};

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
 * Every failure the library meets before the upstream's answer starts goes to
 * the router's error handler, through `proxyErrorHandler`, which replaces the
 * library's default handler — that one would answer a reset itself, as a
 * bodyless `504` nothing logs. `toUpstreamFailure` names the upstream's
 * failures on the way. A caller that has already closed its connection is
 * handed nothing: the library aborts its own upstream request when the caller
 * leaves, which fails as a hang-up, and there is no one to answer and no
 * upstream failure to report. Once the upstream's answer starts it is streamed
 * to the caller as it arrives, and a failure after that point is not seen here.
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
 * It drops the inbound `Expect` too. The stage already holds the whole body,
 * so there is nothing to ask the upstream to wait for, and a forwarded
 * `100-continue` makes Node send the outbound headers at once, before the
 * library sets that `Content-Length`, which then fails.
 *
 * What it does not do: choose which fields are forwarded, beyond the body's
 * framing and the expectation. Every other choice is made before this stage,
 * on `req.headers`. express-http-proxy copies every inbound header except
 * `connection` and `host` onto the outbound request and sets
 * `connection: close` before any decorator runs (`reqHeaders` in
 * `express-http-proxy/lib/requestOptions.js`). Node lower-cases every inbound
 * header name in `req.headers`, so that copy already carries `authorization`.
 * Node's `setHeader` dedups header names case-insensitively and the last
 * write wins, so the decorator's `Authorization` replaces the name, not the
 * value: `Authorization` is sent once, and the `x-request-id` write changes
 * nothing on the wire. That is why `stripInboundAuthorization` takes effect
 * by deleting the header from `req.headers`, in the `forward_stripped` case of
 * `injectionMiddleware` (`src/modes/injection/router.mts`), rather than here.
 *
 * Why it is kept: the framing above, and header-name casing. HTTP header
 * names are case-insensitive (RFC 9110 §5.1), so a conforming upstream sees
 * no difference; without the
 * decorator an upstream would receive `authorization` in lower case, and one
 * that matches the name case-sensitively would miss it. The casing on the
 * wire is pinned by `__tests__/upstream-wire.test.mts`.
 */
export const createUpstreamProxy = (config: UpstreamStageConfig): RequestHandler =>
	proxy(config.upstream.baseURL, {
		limit: upstreamLimit(bodyLimitBytes(config)),
		proxyErrorHandler: (err, res, next) => {
			if (res.destroyed) return;
			next(toUpstreamFailure(err));
		},
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
			delete proxyReqOpts.headers.expect;
			return proxyReqOpts;
		},
	});
