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
 * and the config fields it reads. What its decorator does and does not
 * do, and why it is kept, is the doc comment on the function.
 */

import type { ClientRequest, IncomingMessage, RequestOptions, ServerResponse } from "node:http";
import type { NextFunction, RequestHandler } from "express";
import proxy from "express-http-proxy";
import { bodyLimitBytes } from "./body-limit.mjs";
import { type CorsConfig, proxyOwnedCorsFields } from "./cors.mjs";

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
 * or the library's `connection: close`, which tells the upstream the
 * connection carries this one request. `Content-Length` and `Host` need no
 * entry: the library and Node set them again after the decorator.
 */
const PROXY_DECIDED = new Set(["authorization", "x-request-id", "connection"]);

/**
 * The proxy's name in the `Via` member it adds: a pseudonym in place of its
 * host and port (RFC 9110 §7.6.3), which tell the upstream nothing it needs.
 */
const VIA_PSEUDONYM = "auth.proxy";

/**
 * `Via` with the proxy's member after those the request arrived with
 * (RFC 9110 §7.6.3): the version of HTTP the proxy received it by, and its
 * pseudonym. An empty inbound value counts as none.
 */
const appendVia = (received: number | string | readonly string[] | undefined, httpVersion: string): string => {
	const own = `${httpVersion} ${VIA_PSEUDONYM}`;
	const members = Array.isArray(received) ? received.join(", ") : String(received ?? "");
	return members.trim() === "" ? own : `${members}, ${own}`;
};

/**
 * The upstream's fields for its connection to this proxy, never sent to the
 * caller (RFC 9110 §7.6.1), beside `Connection` itself: the other hop-by-hop
 * fields; `Trailer`, which announces fields the piped body does not carry on;
 * and `Proxy-Authenticate` (§11.7.1), a challenge for the upstream's own hop.
 */
const UPSTREAM_HOP_ONLY = new Set(["keep-alive", "proxy-connection", "te", "upgrade", "trailer", "proxy-authenticate"]);

/** The members of a `Vary` value, in order. */
const varyMembers = (value: number | string | readonly string[]): string[] =>
	(Array.isArray(value) ? value.join(",") : String(value))
		.split(",")
		.map((member) => member.trim())
		.filter((member) => member !== "");

/**
 * The `Vary` of an answer both sides chose from (RFC 9110 §12.5.5): the
 * proxy's members, then the upstream's not already listed, compared
 * case-insensitively; `*` when either lists it.
 */
const mergeVary = (proxy: number | string | readonly string[], upstream: number | string | readonly string[]): string => {
	const merged: string[] = [];
	for (const member of [...varyMembers(proxy), ...varyMembers(upstream)]) {
		if (member === "*") return "*";
		if (!merged.some((listed) => listed.toLowerCase() === member.toLowerCase())) merged.push(member);
	}
	return merged.join(", ");
};

/** The field names a `Connection` value lists, lower-cased. */
const connectionOptions = (connection: string | undefined): string[] =>
	(connection ?? "")
		.split(",")
		.map((name) => name.trim().toLowerCase())
		.filter((name) => name !== "");

/**
 * Screens the upstream's fields on their way onto `res`. The library copies
 * the upstream's fields onto `res` one by one through `setHeader` and then
 * pipes the body, so the stage takes over `setHeader` for this response: the
 * upstream's `Connection` is held back rather than set, and so are
 * `UPSTREAM_HOP_ONLY` and `proxyOnly`, the fields only the proxy sets.
 *
 * A field the proxy had set before the stage — the request id, `cors`'s — is
 * the proxy's answer: the upstream's value for it is dropped, except for
 * `Vary`, whose members both sides add to (`mergeVary`). So a stage before
 * this one sets only fields the proxy decides whole, or `Vary`; a list field
 * such as `Set-Cookie` set there would drop the upstream's.
 *
 * As the head is written — Node writes it through `writeHead`, on the first
 * write too — the fields that `Connection` names are removed where the
 * upstream set them; one the proxy had set goes back to the proxy's value,
 * the upstream's `Vary` members with it. A name the response does not carry
 * is left alone, since Node takes removing `Transfer-Encoding`,
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
const screenUpstreamHead = (res: ServerResponse, proxyOnly: ReadonlySet<string>): (() => void) => {
	const proxySet = res.getHeaders();
	let named: string[] = [];
	const setHeader = res.setHeader;
	res.setHeader = function (this: ServerResponse, name: string, value: number | string | readonly string[]) {
		const field = name.toLowerCase();
		if (field === "connection") {
			named = connectionOptions(Array.isArray(value) ? value.join(",") : String(value));
			return this;
		}
		if (UPSTREAM_HOP_ONLY.has(field) || proxyOnly.has(field)) return this;
		const proxyValue = proxySet[field];
		if (proxyValue === undefined) return setHeader.call(this, name, value);
		if (field === "vary") return setHeader.call(this, name, mergeVary(proxyValue, value));
		return this;
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

/**
 * The part of the library's per-request state that `sendAsReceived` reads
 * and fills (`lib/scopeContainer.js` in express-http-proxy): the module and
 * options for the upstream request, the body read, and where the library
 * looks for the request it sent and the answer it pipes.
 */
interface LibraryExchange {
	user: { res: ServerResponse };
	proxy: {
		requestModule: { request(options: RequestOptions, onAnswer: (answer: IncomingMessage) => void): ClientRequest };
		reqBuilder: RequestOptions;
		bodyContent: Buffer | string;
		req?: ClientRequest;
		res?: IncomingMessage;
	};
}

/**
 * Sends the upstream request with the body as the bytes that arrived. It
 * takes the place of the library's own sender, which re-serialises an
 * `application/x-www-form-urlencoded` body that parses as JSON, unencoded
 * (`{"a":"1&b=2"}` goes as `a=1&b=2`, a bare `42` as nothing) — a different
 * body from the one a signature covers or a firewall in front of the upstream
 * read. Otherwise it does what that sender does with the stage's options,
 * and only with them: the library has read the whole body (`parseReqBody`, its
 * default) and set the `Content-Length` it is framed by; the upstream's answer
 * is handed on as soon as its head arrives, for the library to stream, which
 * it does only with no response decorator and no skip filter; there is no
 * `timeout` to apply; and a caller that leaves before its answer is complete
 * ends the upstream request. The fields it reads are the library's own, not
 * its documented API; `upstream-wire.test.mts` drives the real library
 * through them.
 */
const sendAsReceived = (exchange: LibraryExchange): Promise<LibraryExchange> =>
	new Promise((resolve, reject) => {
		const { res } = exchange.user;
		const sent = exchange.proxy.requestModule.request(exchange.proxy.reqBuilder, (answer) => {
			exchange.proxy.res = answer;
			resolve(exchange);
		});
		exchange.proxy.req = sent;
		sent.on("error", reject);
		res.on("close", () => {
			if (!res.writableFinished) sent.destroy();
		});
		sent.end(exchange.proxy.bodyContent);
	});

/** The config fields the stage reads. `AppConfig` satisfies it structurally. */
export interface UpstreamStageConfig {
	upstream: { baseURL: string };
	http: { bodyLimitSize: string } & CorsConfig["http"];
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
 * its error handler. It is assembly (built from `upstream.baseURL`,
 * `http.bodyLimitSize` in bytes, and whether the proxy answers CORS), not a
 * mode's decision, so both routers mount this one function. It reads the
 * request body against that limit; a body over it that declared no length is
 * refused here, as an error the router's error handler answers.
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
 * And it adds the proxy to `Via` (RFC 9110 §7.6.3), after the members the
 * request arrived with: the version of HTTP it arrived by and the pseudonym
 * `auth.proxy`. A caller naming `Via` in `Connection` drops its own members,
 * not the proxy's.
 *
 * Last, it gives the request an agent of its own that keeps no connection
 * alive (`agent: false`), so each request goes on a connection that carries
 * no other, as its `connection: close` says (RFC 9112 §9.6) — Node's global
 * agent would keep the connection for the next caller's request when the
 * upstream answers keep-alive.
 *
 * Outside the decorator, the stage turns off the library's own
 * `Accept-Charset` (`reqBodyEncoding: null`), which would replace the
 * caller's: the caller's goes on unchanged. And it sends the request itself
 * (`sendAsReceived`), so the body goes on as the bytes that arrived.
 *
 * What the decorator does not do: choose which fields are forwarded, beyond
 * the body's framing, the expectation, the connection's own fields and `Via`.
 * Every other choice is made before this stage, on `req.headers`.
 * express-http-proxy copies every inbound header except `connection` and
 * `host` onto the outbound request and sets `connection: close` before any
 * decorator runs (`reqHeaders` in `express-http-proxy/lib/requestOptions.js`).
 * Node lower-cases every inbound header name in `req.headers`, so that copy
 * already carries `authorization`. Node's `setHeader` dedups header names
 * case-insensitively and the last write wins, so the decorator's
 * `Authorization` replaces the name, not the value: `Authorization` is sent
 * once, and the `x-request-id` write changes nothing on the wire. That is why
 * `stripInboundAuthorization` takes effect by deleting the header from
 * `req.headers`, in the `forward_stripped` case of `injectionMiddleware`
 * (`src/modes/injection/router.mts`), rather than here.
 *
 * On the way back, the upstream's connection fields stay on its hop: its
 * `Connection`, the fields that names — except those the proxy set before
 * forwarding — and the hop-by-hop fields do not reach the caller. A field the
 * proxy set before forwarding keeps the proxy's value though the upstream
 * sends it too, except `Vary`, which lists both sides' members; and while the
 * proxy answers CORS, the upstream's CORS grant never reaches the caller
 * (`proxyOwnedCorsFields` in `cors.mts`). All of it is `screenUpstreamHead`.
 * Node keeps or closes the caller's connection and announces it, and the
 * answer still streams.
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
	const proxyOnly = new Set(proxyOwnedCorsFields(config));
	return (req, res, next) => {
		watchAnswer(res, next, screenUpstreamHead(res, proxyOnly));
		forward(req, res, next);
	};
};

/**
 * The library's options, with `sendProxyRequest`, which it reads
 * (`app/steps/sendProxyRequest.js`) though its type declarations leave it out.
 */
type StageProxyOptions = proxy.ProxyOptions & {
	sendProxyRequest: (exchange: LibraryExchange) => Promise<LibraryExchange>;
};

/** The library's handler, configured as `createUpstreamProxy` describes. */
const proxyTo = (config: UpstreamStageConfig): RequestHandler => {
	const options: StageProxyOptions = {
		limit: upstreamLimit(bodyLimitBytes(config)),
		// The library's default, utf-8, would be sent as `Accept-Charset` in
		// place of the caller's; null sends the caller's on. The body goes on
		// as the bytes that arrived (`sendAsReceived`), so no encoding is
		// needed for it.
		reqBodyEncoding: null,
		sendProxyRequest: sendAsReceived,
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
			// After the connection's own fields, so a caller naming `Via` in
			// `Connection` drops its members, not the proxy's.
			proxyReqOpts.headers.via = appendVia(proxyReqOpts.headers.via, srcReq.httpVersion);
			// A fresh agent that keeps no connection alive: the request says
			// `connection: close`, so its connection carries no other request
			// (RFC 9112 §9.6), whatever the upstream answers. Node's global
			// agent would keep it for the next caller's request. A forward proxy
			// from the environment (`NODE_USE_ENV_PROXY`), which Node applies
			// through that agent, does not apply here.
			proxyReqOpts.agent = false;
			return proxyReqOpts;
		},
	};
	return proxy(config.upstream.baseURL, options);
};
