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

import type { IncomingMessage, ServerResponse } from "node:http";
import type { NextFunction, RequestHandler } from "express";
import proxy from "express-http-proxy";
import { bodyLimitBytes } from "./body-limit.mjs";

/**
 * The upstream failing rather than the request. Before its answer started: it
 * could not be reached, its TLS handshake failed, or it dropped the exchange
 * or answered something that is not HTTP (`502`), or it timed out (`504`,
 * RFC 9110 §15.6.5) — the router's error handler answers it as the
 * `upstream_unavailable` refusal. Or after its answer started: it dropped the
 * connection partway through the body — the status is already sent, so the
 * error handler logs it as that refusal and closes the caller's connection.
 * `cause` is what the connection threw — for an answer cut off, an error that
 * says so, around it.
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

/** Whether `err` says its own status, as the body reader's and the decorator's refusals do. */
const hasOwnStatus = (err: unknown): boolean => {
	if (typeof err !== "object" || err === null) return false;
	const { status, statusCode } = err as { status?: unknown; statusCode?: unknown };
	return status !== undefined || statusCode !== undefined;
};

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
	if (typeof err !== "object" || err === null || hasOwnStatus(err)) return err;
	const { code } = err as { code?: unknown };
	if (typeof code !== "string") return err;
	if (TIMEOUTS.has(code)) return new UpstreamUnavailableError(504, err);
	// `HPE_*`: Node's HTTP parser could not read what the upstream sent.
	if (CONNECTION_FAILURES.has(code) || TLS_FAILURE.test(code) || code.startsWith("HPE_")) {
		return new UpstreamUnavailableError(502, err);
	}
	return err;
};

/**
 * Fields for the connection to this proxy, never sent on: the hop-by-hop
 * fields (RFC 9110 §7.6.1), and `Proxy-Authorization` (§11.7.2), a
 * credential for this hop the proxy does not use. The inbound `Connection`
 * the library already leaves out, and `Transfer-Encoding`, `Trailer` and
 * `Expect` go with the body's framing.
 */
const THIS_HOP_ONLY = ["keep-alive", "proxy-connection", "te", "upgrade", "proxy-authorization"];

/**
 * Fields the proxy decides what the upstream receives for. A caller naming
 * one in `Connection` does not remove it: that would let the caller take away
 * the token the proxy forwards or injected, the request id it correlates by,
 * or the library's `connection: close`, which keeps one upstream connection
 * per request. `Content-Length` and `Host` need no entry: the library and
 * Node set them again after the decorator.
 */
const PROXY_DECIDED = new Set(["authorization", "x-request-id", "connection"]);

/**
 * The upstream's fields for its connection to this proxy, never sent to the
 * caller (RFC 9110 §7.6.1), beside `Connection` itself: the other hop-by-hop
 * fields; `Trailer`, which announces fields the piped body does not carry on;
 * and `Proxy-Authenticate` (§11.7.1), a challenge for the upstream's own hop.
 */
const UPSTREAM_HOP_ONLY = new Set(["keep-alive", "proxy-connection", "te", "upgrade", "trailer", "proxy-authenticate"]);

/** The field names a `Connection` value lists, lower-cased. */
const connectionOptions = (connection: string | undefined): string[] =>
	(connection ?? "")
		.split(",")
		.map((name) => name.trim().toLowerCase())
		.filter((name) => name !== "");

/**
 * Keeps the upstream's connection fields off `res`. The library copies the
 * upstream's fields onto `res` one by one through `setHeader` and then pipes
 * the body, so the stage takes over `setHeader` for this response: the
 * upstream's `Connection` is held back rather than set, and so are
 * `UPSTREAM_HOP_ONLY`. As the head is written — Node writes it through
 * `writeHead`, on the first write too — the fields that `Connection` names are
 * removed where the upstream set them. A field the proxy had set before the
 * stage (the request id, `cors`'s) is the proxy's answer, not the upstream's
 * hop: named, it goes back to the proxy's value. A name the response does not
 * carry is left alone, since Node takes removing `Transfer-Encoding`,
 * `Content-Length`, `Connection` or `Date` as a decision about framing or the
 * announcement, though nothing was there. Its own response decorator would
 * read the whole body first, so the answer still streams.
 *
 * `Connection` never reaches the header map, so Node writes its own: it keeps
 * or closes the caller's connection and says which. A stage after this one
 * that has to close the connection sets `shouldKeepAlive`, not the field.
 *
 * Returns what puts the head back to the one the proxy had set before the
 * stage, for an answer of the proxy's own in place of the upstream's — every
 * field the upstream's head brought dropped, the proxy's at its values, and
 * nothing the upstream's `Connection` named held against it.
 */
const keepUpstreamHopFieldsOff = (res: ServerResponse): (() => void) => {
	const proxySet = res.getHeaders();
	let named: string[] = [];
	const setHeader = res.setHeader;
	res.setHeader = function (this: ServerResponse, name: string, value: number | string | readonly string[]) {
		const field = name.toLowerCase();
		if (field === "connection") {
			named = connectionOptions(Array.isArray(value) ? value.join(",") : String(value));
			return this;
		}
		if (UPSTREAM_HOP_ONLY.has(field)) return this;
		return setHeader.call(this, name, value);
	} as ServerResponse["setHeader"];
	const writeHead = res.writeHead;
	res.writeHead = function (this: ServerResponse, ...args: unknown[]) {
		// Removing `Date` turns Node's own off; the caller's answer is still dated.
		const sendDate = this.sendDate;
		for (const name of named) {
			const proxyValue = proxySet[name];
			if (proxyValue !== undefined) setHeader.call(this, name, proxyValue);
			else if (this.hasHeader(name)) this.removeHeader(name);
		}
		this.sendDate = sendDate;
		return (writeHead as (...rest: unknown[]) => ServerResponse).apply(this, args);
	} as ServerResponse["writeHead"];
	return () => {
		named = [];
		const sendDate = res.sendDate;
		for (const name of res.getHeaderNames()) {
			if (proxySet[name] === undefined) res.removeHeader(name);
		}
		for (const [name, value] of Object.entries(proxySet)) {
			if (value !== undefined) setHeader.call(res, name, value);
		}
		res.sendDate = sendDate;
	};
};

/**
 * Watches the upstream's answer as the library pipes it into `res` (a pipe
 * says so to its destination with `pipe`). An answer that ends before it is
 * complete — the upstream dropped the connection partway through the body —
 * is handed on as an `UpstreamUnavailableError`; nothing else would see it,
 * since the library pipes after its own promise chain has settled. A caller
 * that has already left is no one to answer, as in `proxyErrorHandler`. An
 * answer cut off before any of it was written — its head only — is answered
 * by the proxy, so its head goes back to the proxy's first (`restoreHead`).
 */
const watchAnswer = (res: ServerResponse, next: NextFunction, restoreHead: () => void): void => {
	res.once("pipe", (answer: IncomingMessage) => {
		let thrown: Error | undefined;
		answer.once("error", (err) => {
			thrown = err;
		});
		answer.once("close", () => {
			if (answer.complete || res.destroyed) return;
			if (!res.headersSent) restoreHead();
			// The log line says the answer had started, not only what the connection threw.
			const cause = new Error(
				`upstream answer cut off after it started: ${thrown?.message ?? "ended before it was complete"}`,
				thrown === undefined ? undefined : { cause: thrown },
			);
			next(new UpstreamUnavailableError(502, cause));
		});
	});
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
 * failures on the way. When the caller has already closed its connection, a
 * failure with no status of its own is handed nothing: the library aborts its
 * own upstream request when the caller leaves, which fails as a hang-up, and
 * there is no one to answer and no upstream failure to report. A refusal that
 * says its status — the body reader's, of a body the caller cut short — is
 * handed on, and logged, though no one is left to read the answer. Once the
 * upstream's answer starts it is streamed to the caller as it arrives; an
 * answer the upstream cuts off partway is handed on too (`watchAnswer`), and
 * the error handler, the status being spent, closes the caller's connection.
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
 * It also keeps the connection's own fields on this hop: the fields the
 * inbound `Connection` names and the hop-by-hop fields are not sent on, nor
 * is `Proxy-Authorization` (`THIS_HOP_ONLY`). A caller naming
 * `Authorization`, `x-request-id` or `Connection` in `Connection` does not
 * remove them (`PROXY_DECIDED`).
 *
 * What it does not do: choose which fields are forwarded, beyond the body's
 * framing, the expectation and the connection's own fields. Every other
 * choice is made before this stage, on `req.headers`. express-http-proxy
 * copies every inbound header except `connection` and `host` onto the
 * outbound request and sets `connection: close` before any decorator runs
 * (`reqHeaders` in `express-http-proxy/lib/requestOptions.js`). Node
 * lower-cases every inbound header name in `req.headers`, so that copy
 * already carries `authorization`. Node's `setHeader` dedups header names
 * case-insensitively and the last write wins, so the decorator's
 * `Authorization` replaces the name, not the value: `Authorization` is sent
 * once, and the `x-request-id` write changes nothing on the wire. That is why `stripInboundAuthorization` takes effect
 * by deleting the header from `req.headers`, in the `forward_stripped` case of
 * `injectionMiddleware` (`src/modes/injection/router.mts`), rather than here.
 *
 * On the way back, the upstream's connection fields stay on its hop: its
 * `Connection`, the fields that names — except those the proxy set before
 * forwarding, which keep the proxy's value — and the hop-by-hop fields do not
 * reach the caller (`keepUpstreamHopFieldsOff`). Node keeps or closes the caller's
 * connection and announces it, and the answer still streams.
 *
 * Why it is kept: the framing above, the connection's own fields, and
 * header-name casing. HTTP header names are case-insensitive (RFC 9110 §5.1),
 * so a conforming upstream sees no difference; without the decorator an
 * upstream would receive `authorization` in lower case, and one that matches
 * the name case-sensitively would miss it. The casing on the
 * wire is pinned by `__tests__/upstream-wire.test.mts`.
 */
export const createUpstreamProxy = (config: UpstreamStageConfig): RequestHandler => {
	const forward = proxyTo(config);
	return (req, res, next) => {
		watchAnswer(res, next, keepUpstreamHopFieldsOff(res));
		forward(req, res, next);
	};
};

/** The library's handler, configured as `createUpstreamProxy` describes. */
const proxyTo = (config: UpstreamStageConfig): RequestHandler =>
	proxy(config.upstream.baseURL, {
		limit: upstreamLimit(bodyLimitBytes(config)),
		proxyErrorHandler: (err, res, next) => {
			if (res.destroyed && !hasOwnStatus(err)) return;
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
			// The fields for the connection to this proxy.
			for (const name of connectionOptions(srcReq?.headers?.connection)) {
				if (!PROXY_DECIDED.has(name)) delete proxyReqOpts.headers[name];
			}
			for (const name of THIS_HOP_ONLY) delete proxyReqOpts.headers[name];
			return proxyReqOpts;
		},
	});
