// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The upstream proxy stage is assembly shared by both modes (#95 F18). It is
 * pinned by the options it hands to express-http-proxy, not by a round trip:
 * each mode's router test already drives a real upstream, and what this module
 * owns is exactly which option is set from which config field.
 */
import proxy from "express-http-proxy";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../config/application.schema.mjs";
import { createUpstreamProxy } from "../upstream.mjs";

vi.mock("express-http-proxy", () => ({
	default: vi.fn(() => (_req: unknown, _res: unknown, next: () => void) => next()),
}));

const proxyMock = vi.mocked(proxy);

const config: AppConfig = {
	http: {
		hostname: "127.0.0.1",
		port: 0,
		pathPrefix: "/",
		bodyLimitSize: "1kb",
		cors: { origin: { pattern: null } },
	},
	auth: {
		mode: "validation",
		validation: {
			client: { clientId: null, clientSecret: null },
			introspect: {
				url: "http://provider.test/introspect",
				cacheTtlSec: 30,
				cacheMaxEntries: 100,
				timeoutMs: 5000,
			},
		},
	},
	upstream: { baseURL: "http://upstream.test:8080" },
};

type Decorator = NonNullable<proxy.ProxyOptions["proxyReqOptDecorator"]>;

const builtOptions = (): proxy.ProxyOptions => {
	expect(proxyMock).toHaveBeenCalledTimes(1);
	const [, options] = proxyMock.mock.calls[0];
	if (!options) throw new Error("proxy() was called without options");
	return options;
};

const decorate = async (inboundHeaders: Record<string, string>) => {
	const decorator = builtOptions().proxyReqOptDecorator as Decorator;
	const proxyReqOpts = { headers: {} } as Parameters<Decorator>[0];
	const srcReq = { headers: inboundHeaders } as unknown as Parameters<Decorator>[1];
	return decorator(proxyReqOpts, srcReq);
};

describe("createUpstreamProxy", () => {
	beforeEach(() => {
		proxyMock.mockClear();
		createUpstreamProxy(config);
	});

	it("targets upstream.baseURL and sets exactly limit (from http.bodyLimitSize) and proxyReqOptDecorator", () => {
		expect(proxyMock).toHaveBeenCalledWith("http://upstream.test:8080", expect.anything());
		const options = builtOptions();
		expect(Object.keys(options).sort()).toEqual(["limit", "proxyReqOptDecorator"]);
		expect(options.limit).toBe("1kb");
		expect(options.proxyReqOptDecorator).toEqual(expect.any(Function));
	});

	it("copies Authorization and x-request-id from the inbound request onto the proxied one", async () => {
		const result = await decorate({ authorization: "Bearer abc", "x-request-id": "rid-1" });
		expect(result.headers).toEqual({ Authorization: "Bearer abc", "x-request-id": "rid-1" });
	});

	it("copies each of the two headers independently of the other", async () => {
		expect((await decorate({ authorization: "Bearer abc" })).headers).toEqual({
			Authorization: "Bearer abc",
		});
		expect((await decorate({ "x-request-id": "rid-1" })).headers).toEqual({
			"x-request-id": "rid-1",
		});
	});

	it("adds neither header when the inbound request carries neither", async () => {
		const result = await decorate({});
		expect(result.headers).toEqual({});
	});
});
