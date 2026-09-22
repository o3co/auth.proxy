// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * What `createRouter` builds for the validation path when no `deps.introspect`
 * is supplied (#95 F3, F5): the provider's endpoint behind an
 * `IntrospectionClient`, a cache this router owns, and the TTL between them.
 * The two factories are mocked so each configured value is observed where it
 * is passed, with distinct numbers so a swapped one shows.
 */
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import { createIntrospectionCache } from "../introspection-cache.mjs";
import { createIntrospectionClient } from "../introspection-client.mjs";
import { createRouter } from "../router.mjs";

vi.mock("../introspection-client.mjs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../introspection-client.mjs")>();
	return { ...actual, createIntrospectionClient: vi.fn(actual.createIntrospectionClient) };
});
vi.mock("../introspection-cache.mjs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../introspection-cache.mjs")>();
	return { ...actual, createIntrospectionCache: vi.fn(actual.createIntrospectionCache) };
});

const clientFactory = vi.mocked(createIntrospectionClient);
const cacheFactory = vi.mocked(createIntrospectionCache);

const makeConfig = (client: { clientId: string | null; clientSecret: string | null }): AppConfig => ({
	http: {
		hostname: "127.0.0.1", port: 0, pathPrefix: "/",
		bodyLimitSize: "10mb", cors: { origin: { pattern: null } },
	},
	auth: { mode: "validation", validation: {
		client,
		introspect: { url: "http://provider.test/introspect-bound", cacheTtlSec: 31, cacheMaxEntries: 77, timeoutMs: 4321 },
	} },
	// Never reached: the stubbed provider answers `active: false`.
	upstream: { baseURL: "http://127.0.0.1:1" },
});

describe("the router's own introspector", () => {
	afterEach(() => {
		vi.clearAllMocks();
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("builds the client from the URL, the timeout and the resolved credentials, and the cache from maxEntries", () => {
		createRouter({ config: makeConfig({ clientId: "proxy", clientSecret: "s3cret" }) });

		expect(clientFactory).toHaveBeenCalledWith({
			url: "http://provider.test/introspect-bound",
			timeoutMs: 4321,
			credentials: { clientId: "proxy", clientSecret: "s3cret" },
		});
		expect(cacheFactory).toHaveBeenCalledWith({ maxEntries: 77 });
	});

	it("resolves no credentials unless both halves are configured", () => {
		createRouter({ config: makeConfig({ clientId: "proxy", clientSecret: null }) });

		expect(clientFactory).toHaveBeenCalledWith(expect.objectContaining({ credentials: null }));
	});

	it("gives each router its own cache, so one router's entries are not another's", () => {
		createRouter({ config: makeConfig({ clientId: null, clientSecret: null }) });
		createRouter({ config: makeConfig({ clientId: null, clientSecret: null }) });

		expect(cacheFactory).toHaveBeenCalledTimes(2);
		expect(cacheFactory.mock.results[0].value).not.toBe(cacheFactory.mock.results[1].value);
	});

	it("passes the configured TTL through: a second request inside it does not reach the provider", async () => {
		const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async () =>
			Response.json({ active: false }),
		);
		vi.stubGlobal("fetch", fetchMock);
		const app = express();
		app.use(createRouter({ config: makeConfig({ clientId: null, clientSecret: null }) }));

		const first = await request(app).get("/protected").set("Authorization", "Bearer tok");
		const second = await request(app).get("/protected").set("Authorization", "Bearer tok");

		expect(first.status).toBe(401);
		expect(second.status).toBe(401);
		// `cacheTtlSec: 31` is what makes the second answer come from the cache.
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(fetchMock.mock.calls[0][0]).toBe("http://provider.test/introspect-bound");
	});

	it("does not build either when the caller supplies its own introspector", () => {
		const introspect = vi.fn(async () => ({ active: false }));
		createRouter({ config: makeConfig({ clientId: null, clientSecret: null }), deps: { introspect } });

		expect(clientFactory).not.toHaveBeenCalled();
		expect(cacheFactory).not.toHaveBeenCalled();
	});
});
