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

import { createIntrospector } from "../introspect.mjs";
import { createIntrospectionCache } from "../introspection-cache.mjs";
import type { IntrospectionResult } from "../introspection-client.mjs";

type Introspect = (token: string, requestId: string) => Promise<IntrospectionResult>;

const sha256 = (token: string): string => createHash("sha256").update(token).digest("hex");

const build = ({
	cacheTtlSec = 30,
	maxEntries = 100,
}: { cacheTtlSec?: number; maxEntries?: number } = {}) => {
	const introspect = vi.fn<Introspect>();
	const cache = createIntrospectionCache({ maxEntries });
	const introspector = createIntrospector({ client: { introspect }, cache, cacheTtlSec });
	return { introspector, cache, introspect };
};

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
