// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream proxy stage is assembly shared by both modes (#95 F18). It is
 * pinned by the options it hands to express-http-proxy, not by a round trip:
 * each mode's router test already drives a real upstream, and what this module
 * owns is exactly which option is set from which config field.
 *
 * The decorator is modelled against the input it really gets. By the time it
 * runs, express-http-proxy has already copied every inbound header except
 * `connection` and `host` onto the outbound request (lowercase names, as Node
 * parses them) and set `connection: close` (`reqHeaders` in
 * `lib/requestOptions.js`). What these tests pin is the delta the decorator
 * makes on top of that — a casing-only no-op on the wire.
 */
import type { IncomingHttpHeaders } from "node:http";
import proxy from "express-http-proxy";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createUpstreamProxy, type UpstreamStageConfig } from "../upstream.mjs";

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
	let stage: ReturnType<typeof createUpstreamProxy>;

	beforeEach(() => {
		proxyMock.mockClear();
		stage = createUpstreamProxy(config);
	});

	it("returns the handler proxy() built", () => {
		expect(stage).toBe(proxyMock.mock.results[0]?.value);
	});

	it("targets upstream.baseURL and sets exactly limit (= http.bodyLimitSize) and proxyReqOptDecorator", () => {
		expect(proxyMock).toHaveBeenCalledWith("http://upstream.test:65531", expect.anything());
		const options = builtOptions();
		expect(Object.keys(options).sort()).toEqual(["limit", "proxyReqOptDecorator"]);
		expect(options.limit).toBe("7331kb");
		expect(options.proxyReqOptDecorator).toEqual(expect.any(Function));
	});

	describe("proxyReqOptDecorator is a casing-only no-op on what the library already copied", () => {
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
