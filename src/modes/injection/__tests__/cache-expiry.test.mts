import { describe, expect, it } from "vitest";
import { computeCacheExpiresAt } from "../cache-expiry.mjs";

describe("computeCacheExpiresAt", () => {
	const requestedAt = 1_800_000_000_000;
	const base = {
		requestedAt,
		now: requestedAt,
		ttlSeconds: 60,
		safetyMarginSeconds: 5,
		expiresIn: 300 as number | null,
		notAfter: null as number | null,
	};

	it("takes the smallest of ttl, expires_in and notAfter, minus the margin", () => {
		expect(computeCacheExpiresAt(base)).toBe(requestedAt + 55_000);
		expect(computeCacheExpiresAt({ ...base, expiresIn: 20 })).toBe(requestedAt + 15_000);
		expect(computeCacheExpiresAt({ ...base, notAfter: requestedAt + 30_000 })).toBe(
			requestedAt + 25_000,
		);
		expect(computeCacheExpiresAt({ ...base, expiresIn: null })).toBe(requestedAt + 55_000);
	});

	// expires_in counts from issuance, which cannot precede the request. A
	// response that arrives 10 s later must not move the entry 10 s further out.
	it("anchors ttl and expires_in at the request, not at the response", () => {
		const now = requestedAt + 10_000;
		expect(computeCacheExpiresAt({ ...base, now, expiresIn: 20 })).toBe(requestedAt + 15_000);
		expect(computeCacheExpiresAt({ ...base, now, expiresIn: null })).toBe(requestedAt + 55_000);
	});

	it("keeps an absolute notAfter where it is, however slow the response", () => {
		const now = requestedAt + 10_000;
		expect(
			computeCacheExpiresAt({ ...base, now, notAfter: requestedAt + 30_000 }),
		).toBe(requestedAt + 25_000);
	});

	it("returns null (do not cache) when the expiry is not after now", () => {
		expect(computeCacheExpiresAt({ ...base, expiresIn: 5 })).toBeNull();
		expect(computeCacheExpiresAt({ ...base, expiresIn: 0 })).toBeNull();
		expect(computeCacheExpiresAt({ ...base, notAfter: requestedAt - 1 })).toBeNull();
		// a response slower than expires_in - margin leaves nothing to cache
		expect(
			computeCacheExpiresAt({ ...base, now: requestedAt + 15_000, expiresIn: 20 }),
		).toBeNull();
		expect(
			computeCacheExpiresAt({ ...base, now: requestedAt + 16_000, expiresIn: 20 }),
		).toBeNull();
	});
});
