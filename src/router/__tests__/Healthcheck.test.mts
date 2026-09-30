// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Liveness (`Healthcheck.mts`). The path is an orchestrator's probe
 * configuration, and this proxy, `auth.provider` and the verifier all answer
 * on `/_healthcheck`, so it is pinned here rather than taken from a shared
 * default.
 */
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createRouter } from "../Healthcheck.mjs";

const app = () => express().use(createRouter());

describe("Healthcheck router", () => {
	it("answers 200 with an ok body on /_healthcheck", async () => {
		const res = await request(app()).get("/_healthcheck");
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ status: "ok" });
	});

	it("does not answer on the bare /healthcheck spelling", async () => {
		const res = await request(app()).get("/healthcheck");
		expect(res.status).toBe(404);
	});

	it("is a GET probe — it does not answer POST", async () => {
		const res = await request(app()).post("/_healthcheck");
		expect(res.status).toBe(404);
	});
});
