// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream proxy stage is assembly shared by both modes. It is pinned by
 * the options it hands to express-http-proxy, not by a round trip: each
 * mode's router test already drives a real upstream, and what this module
 * owns is exactly which option is set from which config field.
 *
 * The decorator is modelled against the input it really gets. By the time it
 * runs, express-http-proxy has already copied every inbound header except
 * `connection` and `host` onto the outbound request (lowercase names, as Node
 * parses them) and set `connection: close` (`reqHeaders` in
 * `lib/requestOptions.js`). These tests pin the delta the decorator makes on
 * top of that: the body's inbound framing and the connection's own fields
 * dropped, and otherwise a casing-only no-op on the wire.
 */
import type { IncomingHttpHeaders } from "node:http";
import proxy from "express-http-proxy";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createUpstreamProxy, type UpstreamStageConfig, UpstreamUnavailableError } from "../upstream.mjs";

vi.mock("express-http-proxy", () => ({
	default: vi.fn(() => (_req: unknown, _res: unknown, next: () => void) => next()),
}));

const proxyMock = vi.mocked(proxy);

const config: UpstreamStageConfig = {
	http: { bodyLimitSize: "7331kb" },
	upstream: { baseURL: "http://upstream.test:65531" },
};

type Decorator = NonNullable<proxy.ProxyOptions["proxyReqOptDecorator"]>;
type ProxyReqOpts = Parameters<Decorator>[0];

const builtOptions = (): proxy.ProxyOptions => {
	expect(proxyMock).toHaveBeenCalledTimes(1);
	const [, options] = proxyMock.mock.calls[0];
	if (!options) throw new Error("proxy() was called without options");
	return options;
};

/**
 * The outbound headers exactly as the library hands them to the decorator:
 * every inbound header except `connection` and `host`, plus `connection: close`.
 */
const libraryHeaders = (inbound: IncomingHttpHeaders): ProxyReqOpts["headers"] => ({
	...Object.fromEntries(
		Object.entries(inbound).filter(([name]) => !["connection", "host"].includes(name)),
	),
	connection: "close",
});

const decorate = async (inbound: IncomingHttpHeaders) => {
	const decorator = builtOptions().proxyReqOptDecorator as Decorator;
	const proxyReqOpts = { headers: libraryHeaders(inbound) } as ProxyReqOpts;
	const srcReq = { headers: inbound } as unknown as Parameters<Decorator>[1];
	return decorator(proxyReqOpts, srcReq);
};

const inbound: IncomingHttpHeaders = {
	host: "proxy.test",
	connection: "keep-alive",
	accept: "application/json",
	authorization: "Bearer inbound-7f3a",
	"x-request-id": "rid-2c9e",
};

describe("createUpstreamProxy", () => {
	beforeEach(() => {
		proxyMock.mockClear();
		createUpstreamProxy(config);
	});

	// The stage wraps the response's head writer — the upstream's connection
	// fields are dropped there, which `upstream-wire.test.mts` pins — and
	// hands the request to the handler proxy() built.
	it("hands each request to the handler proxy() built", () => {
		const built = vi.fn();
		proxyMock.mockReturnValueOnce(built);
		const wrapped = createUpstreamProxy(config);
		const req = {};
		const res = { getHeaders: () => ({}), once: () => {}, setHeader: () => {}, writeHead: () => {} };
		const next = () => {};

		wrapped(req as never, res as never, next);

		expect(built).toHaveBeenCalledWith(req, res, next);
	});

	it("targets upstream.baseURL and sets exactly limit (= http.bodyLimitSize in bytes) and proxyReqOptDecorator", () => {
		expect(proxyMock).toHaveBeenCalledWith("http://upstream.test:65531", expect.anything());
		const options = builtOptions();
		expect(Object.keys(options).sort()).toEqual(["limit", "proxyErrorHandler", "proxyReqOptDecorator"]);
		expect(options.limit).toBe(7331 * 1024);
		expect(options.proxyReqOptDecorator).toEqual(expect.any(Function));
	});

	// The library resolves `limit || "1mb"`, so a numeric 0 would become a
	// 1 MiB limit; zero goes as "0", which the body reader reads as 0.
	it("passes a zero limit in a form the library keeps as zero", () => {
		proxyMock.mockClear();
		createUpstreamProxy({ ...config, http: { bodyLimitSize: "0" } });
		expect(builtOptions().limit).toBe("0");
	});

	// A string of a count this large is exponent notation, which the body
	// reader would read as 1 byte; any count but zero goes as the number.
	it("passes a limit too large for plain notation as the number", () => {
		proxyMock.mockClear();
		createUpstreamProxy({ ...config, http: { bodyLimitSize: "1000000pb" } });
		expect(builtOptions().limit).toBe(1_000_000 * 1024 ** 5);
	});

	// What the library rejects with, handed on: a failure of the connection to
	// the upstream becomes an UpstreamUnavailableError, and anything else — a
	// body refused, a coding refused — goes on as it came.
	describe("proxyErrorHandler", () => {
		const handedFrom = (err: unknown, res: object) => {
			const handler = builtOptions().proxyErrorHandler as (e: unknown, res: unknown, next: (e?: unknown) => void) => void;
			const outcome: { called: boolean; passed?: unknown } = { called: false };
			handler(err, res, (e) => {
				outcome.called = true;
				outcome.passed = e;
			});
			return outcome;
		};
		const handed = (err: unknown): unknown => handedFrom(err, { destroyed: false }).passed;
		const systemError = (code: string, syscall?: string) =>
			Object.assign(new Error(`${syscall ?? ""} ${code}`), { code, ...(syscall ? { syscall } : {}) });

		it.each([
			["a refused connection", 502, systemError("ECONNREFUSED", "connect")],
			["an unknown host", 502, systemError("ENOTFOUND", "getaddrinfo")],
			["a reset", 502, systemError("ECONNRESET", "read")],
			["a hang-up", 502, systemError("ECONNRESET")],
			["an answer that is not HTTP", 502, systemError("HPE_INVALID_CONSTANT")],
			["a host that is down", 502, systemError("EHOSTDOWN", "connect")],
			["a network that is down", 502, systemError("ENETDOWN", "connect")],
			["an expired upstream certificate", 502, systemError("CERT_HAS_EXPIRED")],
			["a certificate for another name", 502, systemError("ERR_TLS_CERT_ALTNAME_INVALID")],
			["a self-signed upstream certificate", 502, systemError("DEPTH_ZERO_SELF_SIGNED_CERT")],
			["a TLS handshake that failed", 502, systemError("EPROTO")],
			["a connect timeout", 504, systemError("ETIMEDOUT", "connect")],
		])("hands on %s as UpstreamUnavailableError %d, the cause kept", (_label, status, err) => {
			const passed = handed(err);
			expect(passed).toBeInstanceOf(UpstreamUnavailableError);
			expect(passed).toMatchObject({ status, cause: err });
		});

		// The caller hung up while the upstream had not answered: the library
		// aborts its own request, which fails as a hang-up. Nothing can be
		// answered, and the upstream did not fail, so nothing is handed on.
		it("hands nothing on once the caller has closed its connection", () => {
			const outcome = handedFrom(systemError("ECONNRESET"), { destroyed: true });
			expect(outcome.called).toBe(false);
		});

		// The body reader's refusal of a body the caller cut short carries its
		// own status, and arrives after the caller's socket is gone.
		it("hands on a refusal with a status of its own though the caller has closed its connection", () => {
			const aborted = Object.assign(new Error("request aborted"), { status: 400, code: "ECONNABORTED" });
			expect(handedFrom(aborted, { destroyed: true })).toEqual({ called: true, passed: aborted });
		});

		it.each([
			["a body over the limit", Object.assign(new Error("request entity too large"), { status: 413 })],
			["a body that ended early", Object.assign(new Error("request aborted"), { status: 400, code: "ECONNABORTED" })],
			["a refused coding", Object.assign(new Error("transfer coding not supported"), { status: 501 })],
			["an error of no known kind", new Error("something else")],
		])("hands on %s as it came", (_label, err) => {
			expect(handed(err)).toBe(err);
		});
	});

	describe("proxyReqOptDecorator on what the library already copied", () => {
		// The library reads the whole body and then frames what it sends by a
		// Content-Length it sets itself; a Transfer-Encoding left beside it
		// would frame the one message twice.
		it("drops the inbound Transfer-Encoding and Trailer, and changes nothing else", async () => {
			const chunked = { ...inbound, "transfer-encoding": "chunked", trailer: "X-Sum" };
			const result = await decorate(chunked);
			const { "transfer-encoding": _te, trailer: _trailer, ...rest } = libraryHeaders(chunked);
			expect(result.headers).toEqual({ ...rest, Authorization: "Bearer inbound-7f3a" });
		});

		// RFC 9110 §7.6.1: the fields the inbound Connection names, and the
		// hop-by-hop fields, are for the connection to this proxy. So is
		// Proxy-Authorization (§11.7.2), a credential for this hop the proxy
		// does not use.
		it("drops the fields the inbound Connection names and the hop-by-hop fields, and changes nothing else", async () => {
			const hopByHop = {
				connection: "close, X-Hop",
				"x-hop": "1",
				"keep-alive": "timeout=5",
				te: "trailers",
				upgrade: "h2c",
				"proxy-connection": "keep-alive",
				"proxy-authorization": "Basic cHJveHk6cHc=",
			};
			const result = await decorate({ ...inbound, ...hopByHop });
			expect(result.headers).toEqual({ ...libraryHeaders(inbound), Authorization: "Bearer inbound-7f3a" });
		});

		// The fields the proxy decides are not the caller's to remove by naming
		// them in Connection: what reaches the upstream as Authorization,
		// x-request-id and Connection stays the proxy's choice.
		it("keeps Authorization, x-request-id and the library's Connection though the inbound Connection names them", async () => {
			const result = await decorate({ ...inbound, connection: "Authorization, X-Request-Id, Connection" });
			expect(result.headers).toEqual({ ...libraryHeaders(inbound), Authorization: "Bearer inbound-7f3a" });
			expect(result.headers).toMatchObject({ connection: "close" });
		});

		it.each([["CHUNKED"], [" chunked "]])("reads %j as chunked", async (coding) => {
			const result = await decorate({ ...inbound, "transfer-encoding": coding });
			expect(result.headers).not.toHaveProperty("transfer-encoding");
		});

		it.each([["gzip, chunked"], ["deflate"], ["chunked, gzip"]])(
			"refuses the transfer coding %j with a 501 the router's error handler answers",
			async (coding) => {
				await expect(decorate({ ...inbound, "transfer-encoding": coding })).rejects.toMatchObject({
					status: 501,
				});
			},
		);
	});

	describe("proxyReqOptDecorator is otherwise a casing-only no-op on what the library already copied", () => {
		it("adds Authorization in canonical casing beside the lowercase copy, leaves x-request-id as copied, touches nothing else", async () => {
			const result = await decorate(inbound);
			expect(result.headers).toEqual({
				...libraryHeaders(inbound),
				Authorization: "Bearer inbound-7f3a",
			});
			expect(result.headers).toMatchObject({
				authorization: "Bearer inbound-7f3a",
				"x-request-id": "rid-2c9e",
			});
		});

		it("with only x-request-id inbound, changes nothing at all", async () => {
			const { authorization: _authorization, ...ridOnly } = inbound;
			const result = await decorate(ridOnly);
			expect(result.headers).toEqual(libraryHeaders(ridOnly));
		});

		it("with only Authorization inbound, the whole delta is the canonical-casing copy", async () => {
			const { "x-request-id": _rid, ...authOnly } = inbound;
			const result = await decorate(authOnly);
			expect(result.headers).toEqual({
				...libraryHeaders(authOnly),
				Authorization: "Bearer inbound-7f3a",
			});
		});

		it("adds nothing when the inbound request carries neither header", async () => {
			const { authorization: _authorization, "x-request-id": _rid, ...anonymous } = inbound;
			const result = await decorate(anonymous);
			expect(result.headers).toEqual(libraryHeaders(anonymous));
			expect(result.headers).toEqual({ accept: "application/json", connection: "close" });
		});
	});
});
