// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The introspector's own work (#95 F5): what it accepts on top of a valid
 * RFC 7662 response, and what it caches. The client is a fake here — its
 * request shape and response validation are `introspection-client.test.mts` —
 * and the cache is the real one, since the bound and the eviction are half of
 * what this composes.
 */
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createSingleFlight } from "../../../single-flight.mjs";
import { createIntrospector } from "../introspect.mjs";
import { createIntrospectionCache } from "../introspection-cache.mjs";
import { IntrospectHttpError, type IntrospectionResult } from "../introspection-client.mjs";

type Introspect = (token: string, requestId: string) => Promise<IntrospectionResult>;

const sha256 = (token: string): string => createHash("sha256").update(token).digest("hex");

const build = ({
	cacheTtlSec = 30,
	maxEntries = 100,
}: { cacheTtlSec?: number; maxEntries?: number } = {}) => {
	const introspect = vi.fn<Introspect>();
	const cache = createIntrospectionCache({ maxEntries });
	const singleFlight = createSingleFlight<IntrospectionResult>();
	const introspector = createIntrospector({
		client: { introspect },
		cache,
		singleFlight,
		cacheTtlSec,
	});
	return { introspector, cache, introspect, singleFlight };
};

// Injection has coalesced concurrent misses since it had a cache; validation
// asked the provider once per request, so a burst on one token multiplied
// into a burst at the provider — against the rate limit the root README
// warns about, and the more so the shorter the cache TTL (#95 F6).
describe("the single flight", () => {
	const deferred = () => {
		let resolve!: (value: IntrospectionResult) => void;
		let reject!: (reason: unknown) => void;
		const promise = new Promise<IntrospectionResult>((res, rej) => {
			resolve = res;
			reject = rej;
		});
		return { promise, resolve, reject };
	};

	it("calls the provider once for concurrent misses on one token, and answers both", async () => {
		const { introspector, introspect } = build();
		const first = deferred();
		introspect.mockReturnValueOnce(first.promise);

		const both = Promise.all([introspector("t", "r1"), introspector("t", "r2")]);
		first.resolve({ active: true, sub: "user-1" });

		expect(await both).toEqual([
			{ active: true, sub: "user-1" },
			{ active: true, sub: "user-1" },
		]);
		expect(introspect).toHaveBeenCalledTimes(1);
	});

	// The TTL turns the cache off, not the flight. An operator setting it to 0
	// to get a fresh provider check per request gets one per concurrent group.
	it("coalesces concurrent misses even with the cache disabled", async () => {
		const { introspector, introspect, cache } = build({ cacheTtlSec: 0 });
		const first = deferred();
		introspect.mockReturnValueOnce(first.promise);

		const both = Promise.all([introspector("t", "r1"), introspector("t", "r2")]);
		first.resolve({ active: true });

		await both;
		expect(introspect).toHaveBeenCalledTimes(1);
		expect(cache.size()).toBe(0);
	});

	// The key is the digest, not the token: the flight table must no more hold
	// a live credential than the cache does.
	it("keys the flight by the digest, so the table never holds the token", async () => {
		const { introspector, introspect, singleFlight } = build();
		const seen: string[] = [];
		const run = singleFlight.run.bind(singleFlight);
		vi.spyOn(singleFlight, "run").mockImplementation((key, fetch) => {
			seen.push(key);
			return run(key, fetch);
		});
		introspect.mockResolvedValue({ active: true });

		await introspector("a-live-token", "r1");

		expect(seen).toEqual([sha256("a-live-token")]);
	});

	it("does not coalesce two different tokens", async () => {
		const { introspector, introspect } = build();
		introspect.mockResolvedValue({ active: true });

		await Promise.all([introspector("one", "r1"), introspector("two", "r2")]);

		expect(introspect).toHaveBeenCalledTimes(2);
	});

	// The waiters share the leader's failure rather than each raising their
	// own, which is what the injection path does and what makes one flight
	// one provider call on the error path too.
	it("shares a rejection with every waiter without a second provider call", async () => {
		const { introspector, introspect } = build();
		const failure = new IntrospectHttpError(503, "introspect returned 503");
		const first = deferred();
		introspect.mockReturnValueOnce(first.promise);

		const both = Promise.allSettled([introspector("t", "r1"), introspector("t", "r2")]);
		first.reject(failure);

		expect(await both).toEqual([
			{ status: "rejected", reason: failure },
			{ status: "rejected", reason: failure },
		]);
		expect(introspect).toHaveBeenCalledTimes(1);
	});

	it("releases the key, so the next miss calls the provider again", async () => {
		const { introspector, introspect, singleFlight } = build({ cacheTtlSec: 0 });
		introspect.mockResolvedValue({ active: true });

		await introspector("t", "r1");
		expect(singleFlight._sizeForTesting()).toBe(0);

		await introspector("t", "r2");

		expect(introspect).toHaveBeenCalledTimes(2);
	});
});

describe("createIntrospector", () => {
	describe("the cache", () => {
		it("returns the cached result on a second call within the TTL, calling the provider once", async () => {
			const { introspector, introspect } = build();
			introspect.mockResolvedValueOnce({ active: true, sub: "user-1" });

			const first = await introspector("cached-token", "req-4");
			const second = await introspector("cached-token", "req-5");

			expect(introspect).toHaveBeenCalledTimes(1);
			expect(first).toEqual(second);
		});

		it("keys the entry by the digest of the token, never the token", async () => {
			const { introspector, cache, introspect } = build();
			cache.set(sha256("seeded-token"), { active: true, sub: "seeded" }, Date.now() + 60_000);

			await expect(introspector("seeded-token", "req")).resolves.toEqual({
				active: true,
				sub: "seeded",
			});
			expect(introspect).not.toHaveBeenCalled();
		});

		it("stops serving a warm entry at the token's exp", async () => {
			const start = 1_700_000_000_000;
			const clock = vi.spyOn(Date, "now").mockReturnValue(start);
			try {
				const { introspector, introspect } = build();
				introspect.mockResolvedValue({ active: true, exp: start / 1000 + 1 });

				expect((await introspector("t", "r")).active).toBe(true);
				clock.mockReturnValue(start + 1000);
				// The entry is not served, and the token the provider answers with
				// has expired by now, so the second answer is a refusal.
				expect((await introspector("t", "r")).active).toBe(false);
				expect(introspect).toHaveBeenCalledTimes(2);
			} finally {
				clock.mockRestore();
			}
		});

		it("anchors the bound at the request, not at the response", async () => {
			const start = 1_700_000_000_000;
			const clock = vi.spyOn(Date, "now").mockReturnValue(start);
			try {
				const { introspector, cache, introspect } = build({ cacheTtlSec: 10 });
				introspect.mockImplementationOnce(async () => {
					// The provider takes four seconds to answer.
					clock.mockReturnValue(start + 4000);
					return { active: true };
				});

				await introspector("t", "r");
				// min(requested + 10 s, no exp) — from the request, so it is gone at
				// +10 s rather than at +14 s.
				clock.mockReturnValue(start + 9_000);
				expect(cache.get(sha256("t"))).not.toBeNull();
				clock.mockReturnValue(start + 10_001);
				expect(cache.get(sha256("t"))).toBeNull();
			} finally {
				clock.mockRestore();
			}
		});

		it("neither reads nor writes the cache when caching is disabled", async () => {
			const { introspector, cache, introspect } = build({ cacheTtlSec: 0 });
			cache.set(sha256("t"), { active: true, sub: "seeded" }, Date.now() + 60_000);
			introspect.mockResolvedValue({ active: false });

			expect((await introspector("t", "r")).active).toBe(false);
			expect((await introspector("t", "r")).active).toBe(false);

			expect(introspect).toHaveBeenCalledTimes(2);
			expect(cache.get(sha256("t"))).toEqual({ active: true, sub: "seeded" });
		});

		it("evicts the oldest entry at maxEntries, so the evicted token is fetched again", async () => {
			const { introspector, introspect } = build({ maxEntries: 2 });
			introspect
				.mockResolvedValueOnce({ active: true, sub: "user-a" })
				.mockResolvedValueOnce({ active: true, sub: "user-b" })
				.mockResolvedValueOnce({ active: true, sub: "user-c" })
				.mockResolvedValueOnce({ active: true, sub: "user-a-re" });

			await introspector("token-a", "r1");
			await introspector("token-b", "r2");
			await introspector("token-c", "r3");
			await introspector("token-a", "r4");

			expect(introspect).toHaveBeenCalledTimes(4);
		});

		it("evicts once for a token two concurrent requests ask about (#95 F5, F6)", async () => {
			// One flight, so one write. Before F6 both requests called the
			// provider and both wrote, and the second write was for a key the
			// cache already held — which is where the fused function this
			// replaced would have dropped a second live entry. That double write
			// is no longer reachable here; `set` is idempotent for a held key
			// either way, which `introspection-cache.test.mts` owns.
			const { introspector, cache, introspect } = build({ maxEntries: 2 });
			introspect.mockResolvedValue({ active: true });
			await introspector("older", "r1");
			await introspector("newer", "r2");
			expect(cache.size()).toBe(2);

			await Promise.all([introspector("fresh", "r3"), introspector("fresh", "r4")]);

			expect(introspect).toHaveBeenCalledTimes(3);
			expect(cache.size()).toBe(2);
			expect(cache.get(sha256("older"))).toBeNull();
			expect(cache.get(sha256("newer"))).not.toBeNull();
			expect(cache.get(sha256("fresh"))).not.toBeNull();
		});

		it("caches a plain active: false, which is the provider's answer about the token", async () => {
			const { introspector, cache, introspect } = build();
			introspect.mockResolvedValueOnce({ active: false });

			await introspector("t", "r");

			expect(cache.get(sha256("t"))).toEqual({ active: false });
			expect((await introspector("t", "r")).active).toBe(false);
			expect(introspect).toHaveBeenCalledTimes(1);
		});
	});

	describe("what this path accepts", () => {
		it("accepts a case-insensitive Bearer token type", async () => {
			const { introspector, introspect } = build();
			introspect.mockResolvedValueOnce({ active: true, token_type: "bearer" });

			expect((await introspector("t", "r")).active).toBe(true);
		});

		it.each([
			{ cnf: { jkt: "proof-key" }, token_type: "DPoP" },
			{ cnf: { jkt: "proof-key" }, token_type: "Bearer" },
			{ cnf: { "x5t#S256": "certificate" }, token_type: "Bearer" },
			{ cnf: {} },
			{ cnf: null },
			{ token_type: "DPoP" },
		])("refuses unsupported possession evidence on the Bearer path: %j", async (claims) => {
			const { introspector, cache, introspect } = build();
			introspect.mockResolvedValueOnce({ active: true, ...claims });

			expect((await introspector("t", "r")).active).toBe(false);
			// A refusal this path made is not the provider's answer about the
			// token, so it is not held: the next request asks again.
			expect(cache.get(sha256("t"))).toBeNull();
		});

		it("refuses a positive response that expired during the provider call, and caches nothing", async () => {
			const start = 1_700_000_000_000;
			const clock = vi.spyOn(Date, "now").mockReturnValue(start);
			try {
				const { introspector, cache, introspect } = build();
				introspect.mockImplementationOnce(async () => {
					clock.mockReturnValue(start + 2000);
					return { active: true, exp: start / 1000 + 1 };
				});

				expect((await introspector("t", "r")).active).toBe(false);
				expect(cache.get(sha256("t"))).toBeNull();
			} finally {
				clock.mockRestore();
			}
		});

		it.each(["soon", null, {}, []].map((exp) => ({ exp })))(
			"refuses malformed exp $exp as the provider's bug (502)",
			async ({ exp }) => {
				const { introspector, introspect } = build();
				introspect.mockResolvedValueOnce({ active: true, exp } as IntrospectionResult);

				await expect(introspector("t", "r")).rejects.toMatchObject({
					name: "IntrospectHttpError",
					status: 502,
				});
			},
		);
	});
});
