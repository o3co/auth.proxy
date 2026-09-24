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
import { createProxyLogger, serializeLoggedError } from "../logger.mjs";

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

	// #95 F48: pino serialises an Error only under `err`; validation logs its
	// failures under `error`, where JSON.stringify kept the enumerable fields
	// alone — no message, no stack, no cause.
	it("serialises an Error under `error` with its message, stack and cause chain", async () => {
		// The shape of a refused introspection call since F42: the wrapper, then
		// undici's `fetch failed`, then the socket's own error.
		const refused = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:1"), {
			code: "ECONNREFUSED",
		});
		const cause = new TypeError("fetch failed", { cause: refused });
		const entry = await firstLine((logger) =>
			logger.error({ error: new Error("introspect call failed", { cause }) }, "introspect failed"),
		);
		expect(entry.error).toMatchObject({
			type: "Error",
			message: "introspect call failed",
			cause: {
				type: "TypeError",
				message: "fetch failed",
				cause: { message: "connect ECONNREFUSED 127.0.0.1:1", code: "ECONNREFUSED" },
			},
		});
		expect(entry.error.stack).toContain("introspect call failed");
	});

	it("keeps a string `error` as it is, which is how injection logs", async () => {
		const entry = await firstLine((logger) => logger.error({ error: "session expired" }, "grant failed"));
		expect(entry.error).toBe("session expired");
	});

	// Codex on #95 F48: an allowlist, because undici's HTTPParserError keeps
	// the unparsed response in `data`, and a provider may echo the token.
	it("logs only the allowlisted fields of an error in the chain", async () => {
		const parser = Object.assign(new Error("Response does not match the HTTP/1.1 protocol"), {
			code: "HPE_INVALID_CONSTANT",
			data: "token=SECRET-ECHO",
			headers: { authorization: "Bearer SECRET" },
		});
		const entry = await firstLine((logger) =>
			logger.error(
				{ error: new Error("introspect call failed", { cause: new TypeError("fetch failed", { cause: parser }) }) },
				"introspect failed",
			),
		);
		expect(JSON.stringify(entry)).not.toContain("SECRET");
		expect(entry.error.cause.cause).toMatchObject({ code: "HPE_INVALID_CONSTANT" });
	});

	// The allowlist is keyed on a field name, so it has to cover both names an
	// Error is logged under: validation logs `error`, shutdown logs `err`, and
	// pino's own `err` serialiser copies every enumerable property.
	it("applies the same allowlist to an Error logged under `err`", async () => {
		const failure = Object.assign(
			new Error("close failed: https://proxy:hunter2@auth.test/introspect"),
			{ code: "ERR_SERVER_NOT_RUNNING", data: "token=SECRET-ECHO" },
		);
		const entry = await firstLine((logger) => logger.error({ err: failure }, "graceful shutdown: server close failed"));
		expect(JSON.stringify(entry)).not.toContain("SECRET");
		expect(JSON.stringify(entry)).not.toContain("hunter2");
		expect(entry.err).toMatchObject({ type: "Error", code: "ERR_SERVER_NOT_RUNNING" });
		expect(entry.err.message).toContain("https://***@auth.test/introspect");
	});

	it("redacts URL credentials from messages and stacks", async () => {
		const entry = await firstLine((logger) =>
			logger.error(
				{ error: new TypeError("Request cannot be constructed from a URL that includes credentials: https://proxy:hunter2@auth.test/introspect") },
				"introspect failed",
			),
		);
		expect(JSON.stringify(entry)).not.toContain("hunter2");
		expect(entry.error.message).toContain("https://***@auth.test/introspect");
	});

	// #140: `fetch` quotes a URL in its refusals exactly as it was given, not
	// normalised, so the redaction cannot rely on the WHATWG spelling — where a
	// space is `%20`, an interior `@` is `%40`, and `?` and `#` never appear in
	// userinfo at all.
	describe("URL credentials, quoted as they were given (#140)", () => {
		const messageOf = (text: string) =>
			(serializeLoggedError(new TypeError(text)) as { message: string }).message;

		it.each([
			["raw, with a space", "Failed to parse URL from https://proxy:my hunter2@auth exam ple/introspect"],
			["raw, with an interior '@'", "Failed to parse URL from https://proxy:p@hunter2@auth.test/introspect"],
			["raw, parseable, with a space", "Request cannot be constructed from a URL that includes credentials: https://proxy:my hunter2@auth.test/x"],
			["raw, with a '?'", "Failed to parse URL from https://proxy:pa?hunter2@auth.test/introspect"],
			["raw, with a '#'", "Failed to parse URL from https://proxy:pa#hunter2@auth.test/introspect"],
			["normalised, with %20", "fetch failed: https://proxy:my%20hunter2@auth.test/introspect"],
			["normalised, with %40", "fetch failed: https://proxy:p%40hunter2@auth.test/introspect"],
			["a username alone", "fetch failed: https://hunter2@auth.test/introspect"],
		])("redacts the whole userinfo: %s", (_, text) => {
			const message = messageOf(text);
			expect(message).not.toContain("hunter2");
			expect(message).toContain("://***@");
		});

		it("redacts every URL in one message", () => {
			const message = messageOf("from https://a:hunter2@one.test/x to https://b:hunter2@two.test/y");
			expect(message).not.toContain("hunter2");
			expect(message).toBe("from https://***@one.test/x to https://***@two.test/y");
		});

		it.each([
			"fetch failed: https://auth.test/introspect",
			"fetch failed: https://auth.test/introspect?requester=ops@example.test",
			"fetch failed: https://auth.test/introspect#owner@example.test",
		])("leaves a URL without userinfo as it is when it has a path: %j", (text) => {
			expect(messageOf(text)).toBe(text);
		});

		it("errs towards redacting after a bare origin: an '@' in its query or fragment takes the text before it", () => {
			expect(messageOf("fetch failed: https://auth.test#fragment@x")).toBe("fetch failed: https://***@x");
			expect(messageOf("fetch failed: https://auth.test?who=ops@x")).toBe("fetch failed: https://***@x");
		});

		it("does not reach across a line to an '@' on the next one", () => {
			const text = "fetch failed: https://auth.test\n    at owner@example.test";
			expect(messageOf(text)).toBe(text);
		});
	});

	it("stops at a cycle in the cause chain", () => {
		const a = new Error("a");
		const b = new Error("b", { cause: a });
		Object.defineProperty(a, "cause", { value: b });
		expect(() => JSON.stringify(serializeLoggedError(a))).not.toThrow();
	});

	it("passes a non-Error through, message-shaped or not", () => {
		const shaped = { message: "not an Error", data: "kept as given" };
		expect(serializeLoggedError(shaped)).toBe(shaped);
		expect(serializeLoggedError("session expired")).toBe("session expired");
	});
});
