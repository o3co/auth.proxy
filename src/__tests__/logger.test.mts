// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The proxy's logger, moved in from `@o3co/auth.utils`.
 *
 * Moving it fixes a packaging defect as well as the indirection. `auth.utils`
 * took pino as an *optional* peer and fell back to `console` when the import
 * failed; this repo satisfied that peer from **devDependencies**, and the
 * Dockerfile runs `pnpm prune --prod` before copying `node_modules` into the
 * runtime stage. So the deployed proxy had no pino and logged bare
 * `[proxy] ...` lines through the console fallback — not the NDJSON its
 * operators' aggregator ingests, and not what any local run showed.
 *
 * pino is a direct dependency now, and these tests pin the output shape.
 */
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { createProxyLogger } from "../logger.mjs";

const original = process.env.LOG_LEVEL;
afterEach(() => {
	if (original === undefined) delete process.env.LOG_LEVEL;
	else process.env.LOG_LEVEL = original;
});

/** Collect one NDJSON line written by the logger. */
async function firstLine(write: (logger: ReturnType<typeof createProxyLogger>) => void) {
	const stream = new PassThrough();
	const lines: string[] = [];
	stream.on("data", (chunk: Buffer) => lines.push(chunk.toString()));
	write(createProxyLogger({ destination: stream }));
	await new Promise((resolve) => setImmediate(resolve));
	return JSON.parse(lines.join("").trim());
}

describe("createProxyLogger", () => {
	it("defaults to info", () => {
		delete process.env.LOG_LEVEL;
		expect(createProxyLogger().level).toBe("info");
	});

	it("honours LOG_LEVEL", () => {
		process.env.LOG_LEVEL = "debug";
		expect(createProxyLogger().level).toBe("debug");
	});

	it("prefers an explicit level over LOG_LEVEL", () => {
		process.env.LOG_LEVEL = "debug";
		expect(createProxyLogger({ level: "error" }).level).toBe("error");
	});

	it("emits NDJSON — one parseable object per line", async () => {
		const entry = await firstLine((logger) => logger.info("ready"));
		expect(entry.msg).toBe("ready");
		expect(entry.level).toBe(30);
	});

	it("names every line so a multi-service aggregator can filter", async () => {
		const entry = await firstLine((logger) => logger.info("ready"));
		expect(entry.name).toBe("proxy");
	});

	it("carries structured fields rather than interpolating them into the message", async () => {
		const entry = await firstLine((logger) => logger.warn({ status: 401 }, "rejected"));
		expect(entry.status).toBe(401);
		expect(entry.msg).toBe("rejected");
	});
});
