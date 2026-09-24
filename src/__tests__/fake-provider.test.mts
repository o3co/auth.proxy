// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The fake provider itself (#143), through Node's own `fetch`: what it
 * records, and that each kind of answer is on the wire what the client tests
 * rely on it being. A client test that passes against a fake that does not do
 * what it says would pin nothing. The timeout the client tests fire mid-body
 * is pinned here for the same reason.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { type FakeProvider, json, redirect, startFakeProvider } from "./fake-provider.mjs";
import { controlledTimeout, timeoutAfterResponseHeaders } from "./provider-timeout.mjs";

describe("startFakeProvider", () => {
	let fake: FakeProvider;

	beforeAll(async () => {
		fake = await startFakeProvider();
	});
	afterAll(async () => {
		await fake.close();
	});
	afterEach(() => {
		fake.reset();
	});

	it("listens on a loopback origin", () => {
		expect(fake.origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
		expect(fake.url("/oauth/token")).toBe(`${fake.origin}/oauth/token`);
	});

	it("records the method, the target, the headers as sent and the raw body", async () => {
		fake.respond("/oauth/token", json(200, { ok: true }));

		const res = await fetch(fake.url("/oauth/token?x=1"), {
			method: "POST",
			headers: { "X-Request-Id": "rid-1", Cookie: "sid=abc" },
			body: "a=1&b=%2B",
		});

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
		expect(fake.requests).toHaveLength(1);
		const [req] = fake.requests;
		expect(req.method).toBe("POST");
		expect(req.path).toBe("/oauth/token?x=1");
		expect(req.headers["x-request-id"]).toBe("rid-1");
		expect(req.headers.cookie).toBe("sid=abc");
		expect(req.rawHeaders).toContain("X-Request-Id");
		expect(req.body.toString("utf8")).toBe("a=1&b=%2B");
		expect(req.connection).toBeGreaterThan(0);
	});

	it("answers 404 on a path nobody programmed, and records the request", async () => {
		const res = await fetch(fake.url("/nowhere"));

		expect(res.status).toBe(404);
		await res.body?.cancel();
		expect(fake.requests.map((r) => r.path)).toEqual(["/nowhere"]);
	});

	it("sends the programmed status and headers", async () => {
		fake.respond("/x", json(429, { error: "slow_down" }, { "Retry-After": "120" }));

		const res = await fetch(fake.url("/x"));

		expect(res.status).toBe(429);
		expect(res.headers.get("retry-after")).toBe("120");
		expect(await res.json()).toEqual({ error: "slow_down" });
	});

	it("computes an answer from the request, and may hold it back", async () => {
		let release: () => void = () => {};
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		fake.respond("/x", async (req) => {
			await held;
			return json(200, { echoed: req.body.toString("utf8") });
		});

		let answered = false;
		const pending = fetch(fake.url("/x"), { method: "POST", body: "hello" }).then((res) => {
			answered = true;
			return res;
		});
		await vi.waitFor(() => expect(fake.requests).toHaveLength(1));
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(answered).toBe(false);
		release();
		const res = await pending;

		expect(await res.json()).toEqual({ echoed: "hello" });
	});

	it("reports a responder that threw at the next reset, not as a dropped connection alone", async () => {
		fake.respond("/x", () => {
			throw new Error("a bug in the test");
		});

		await expect(fetch(fake.url("/x"))).rejects.toThrow();

		expect(() => fake.reset()).toThrow(/a responder threw/);
	});

	it("does not follow its own redirect when the client does not", async () => {
		fake.respond("/from", redirect(307, "/to"));

		const res = await fetch(fake.url("/from"), { redirect: "manual" });

		expect(res.status).toBe(307);
		expect(res.headers.get("location")).toBe("/to");
		expect(fake.requests.map((r) => r.path)).toEqual(["/from"]);
	});

	it("is a different origin from a second instance", async () => {
		const other = await startFakeProvider();
		try {
			other.respond("/to", json(200, {}));
			expect(other.origin).not.toBe(fake.origin);
			fake.respond("/from", redirect(302, other.url("/to")));

			const res = await fetch(fake.url("/from"));

			expect(res.status).toBe(200);
			expect(fake.requests).toHaveLength(1);
			expect(other.requests).toHaveLength(1);
		} finally {
			await other.close();
		}
	});

	it("trickles a body in chunks and ends it", async () => {
		fake.respond("/x", { status: 200, body: { trickle: ['{"a":', '"b"', "}"] } });

		const res = await fetch(fake.url("/x"));

		expect(res.headers.get("content-length")).toBeNull();
		expect(await res.json()).toEqual({ a: "b" });
	});

	it("holds a trickled body open, until the client gives up and closes the connection", async () => {
		fake.respond("/x", { status: 200, body: { trickle: ["{"], finish: "hold" } });

		const controller = new AbortController();
		const res = await fetch(fake.url("/x"), { signal: controller.signal });
		const read = res.text();
		controller.abort();

		await expect(read).rejects.toThrow();

		await fake.requests[0].connectionClosed;
	});

	it("drops the connection mid-body", async () => {
		fake.respond("/x", { status: 200, body: { trickle: ['{"a":'], finish: "drop" } });

		const res = await fetch(fake.url("/x"));

		await expect(res.text()).rejects.toThrow();
		await fake.requests[0].connectionClosed;
	});

	it("repeats a body until the client cancels it, and sees the connection close", async () => {
		fake.respond("/x", { status: 200, body: { repeat: "x".repeat(1024) } });

		const res = await fetch(fake.url("/x"));
		const reader = res.body?.getReader();
		let total = 0;
		while (reader !== undefined && total <= 256 * 1024) {
			const { value } = await reader.read();
			total += value?.byteLength ?? 0;
		}
		await reader?.cancel();

		expect(total).toBeGreaterThan(256 * 1024);
		await fake.requests[0].connectionClosed;
	});

	it("never answers a hung request", async () => {
		const controller = new AbortController();
		fake.respond("/x", () => {
			controller.abort();
			return { hang: true };
		});

		await expect(fetch(fake.url("/x"), { signal: controller.signal })).rejects.toMatchObject({
			name: "AbortError",
		});
		await fake.requests[0].connectionClosed;
	});

	it("forgets what it was programmed and what it received on reset", async () => {
		fake.respond("/x", json(200, {}));
		await (await fetch(fake.url("/x"))).body?.cancel();

		fake.reset();

		expect(fake.requests).toEqual([]);
		const res = await fetch(fake.url("/x"));
		expect(res.status).toBe(404);
		await res.body?.cancel();
	});
});

describe("controlledTimeout", () => {
	let fake: FakeProvider;

	beforeAll(async () => {
		fake = await startFakeProvider();
	});
	afterAll(async () => {
		await fake.close();
	});

	it("times out a call when fired, from a responder that holds the whole request", async () => {
		const timeout = controlledTimeout();
		try {
			fake.respond("/x", () => {
				timeout.fire();
				return { hang: true };
			});

			await expect(fetch(fake.url("/x"), { signal: AbortSignal.timeout(60_000) })).rejects.toMatchObject({
				name: "TimeoutError",
			});
			await fake.requests[0].connectionClosed;
		} finally {
			timeout.restore();
		}
	});

	it("hands out an already timed-out signal once fired", () => {
		const timeout = controlledTimeout();
		try {
			timeout.fire();

			expect(AbortSignal.timeout(60_000).reason).toMatchObject({ name: "TimeoutError" });
		} finally {
			timeout.restore();
		}
	});
});

describe("timeoutAfterResponseHeaders", () => {
	let fake: FakeProvider;

	beforeAll(async () => {
		fake = await startFakeProvider();
	});
	afterAll(async () => {
		await fake.close();
	});

	it("lets the headers arrive, then aborts the body read with a TimeoutError", async () => {
		fake.respond("/x", { status: 200, body: { trickle: ["{"], finish: "hold" } });
		const timeout = timeoutAfterResponseHeaders();
		try {
			const res = await fetch(fake.url("/x"), { signal: AbortSignal.timeout(60_000) });

			expect(res.status).toBe(200);
			await expect(res.text()).rejects.toMatchObject({ name: "TimeoutError" });
			await timeout.fired;
			await fake.requests[0].connectionClosed;
		} finally {
			timeout.restore();
		}
	});

	it("puts AbortSignal.timeout back", () => {
		const original = AbortSignal.timeout;
		timeoutAfterResponseHeaders().restore();

		expect(AbortSignal.timeout).toBe(original);
	});
});
