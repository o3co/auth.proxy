// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * `bindIntrospect` (#95 F3): the concrete `introspect` receives the seven
 * arguments in order — the token, the router's URL, TTL, the request id, the
 * per-token credential choice, the cache bound and the timeout — with the
 * module mocked so each value is observed directly rather than through
 * `fetch`. Distinct values, so a swapped argument shows.
 */
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../../../config/application.schema.mjs";
import { introspect } from "../introspect.mjs";
import { createRouter } from "../router.mjs";

vi.mock("../introspect.mjs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../introspect.mjs")>();
	return { ...actual, introspect: vi.fn() };
});

const introspectMock = vi.mocked(introspect);

const makeConfig = (client: { clientId: string | null; clientSecret: string | null }): AppConfig => ({
	http: {
		hostname: "127.0.0.1", port: 0, pathPrefix: "/",
		bodyLimitSize: "10mb", cors: { origin: { pattern: null } },
	},
	auth: { mode: "validation", validation: {
		client,
		introspect: { url: "http://provider.test/introspect-bound", cacheTtlSec: 31, cacheMaxEntries: 77, timeoutMs: 4321 },
	} },
	// Never reached: the mocked introspector answers `active: false`.
	upstream: { baseURL: "http://127.0.0.1:1" },
});

describe("bindIntrospect", () => {
	afterEach(() => {
		vi.clearAllMocks();
	});

	it("hands the concrete introspect the seven arguments in order, with the Basic header when client credentials are set", async () => {
		introspectMock.mockResolvedValueOnce({ active: false });
		const app = express();
		app.use(createRouter({ config: makeConfig({ clientId: "proxy", clientSecret: "s3cret" }) }));

		const res = await request(app)
			.get("/protected")
			.set("Authorization", "Bearer tok extra")
			.set("x-request-id", "rid-bind");

		expect(res.status).toBe(401);
		expect(introspectMock).toHaveBeenCalledTimes(1);
		expect(introspectMock).toHaveBeenCalledWith(
			"tok",
			"http://provider.test/introspect-bound",
			31,
			"rid-bind",
			`Basic ${Buffer.from("proxy:s3cret").toString("base64")}`,
			77,
			4321,
		);
	});

	it("presents the token itself as the credential when no client credentials are configured", async () => {
		introspectMock.mockResolvedValueOnce({ active: false });
		const app = express();
		app.use(createRouter({ config: makeConfig({ clientId: null, clientSecret: null }) }));

		await request(app).get("/protected").set("Authorization", "Bearer tok").set("x-request-id", "rid-bind");

		expect(introspectMock).toHaveBeenCalledWith(
			"tok",
			"http://provider.test/introspect-bound",
			31,
			"rid-bind",
			"Bearer tok",
			77,
			4321,
		);
	});
});
