import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTokenCache } from "../token-cache.mjs";

describe("createTokenCache", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-04-24T00:00:00Z"));
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("returns null for unset key", () => {
		const cache = createTokenCache({ maxEntries: 10 });
		expect(cache.get("k1")).toBeNull();
	});

	it("returns cached token before expiry", () => {
		const cache = createTokenCache({ maxEntries: 10 });
		cache.set("k1", "tok1", Date.now() + 60_000);
		expect(cache.get("k1")).toBe("tok1");
	});

	it("returns null for expired entry and removes it from the map", () => {
		const cache = createTokenCache({ maxEntries: 10 });
		cache.set("k1", "tok1", Date.now() + 1000);
		vi.advanceTimersByTime(2000);
		expect(cache.get("k1")).toBeNull();
		expect(cache.size()).toBe(0);
	});

	it("evicts oldest insertion when at maxEntries", () => {
		const cache = createTokenCache({ maxEntries: 2 });
		cache.set("a", "ta", Date.now() + 60_000);
		cache.set("b", "tb", Date.now() + 60_000);
		cache.set("c", "tc", Date.now() + 60_000);

		expect(cache.get("a")).toBeNull();
		expect(cache.get("b")).toBe("tb");
		expect(cache.get("c")).toBe("tc");
	});

	it("sweeps expired entries before eviction check", () => {
		const cache = createTokenCache({ maxEntries: 2 });
		cache.set("a", "ta", Date.now() + 1000);
		cache.set("b", "tb", Date.now() + 60_000);
		vi.advanceTimersByTime(2000);
		cache.set("c", "tc", Date.now() + 60_000);

		expect(cache.get("a")).toBeNull();
		expect(cache.get("b")).toBe("tb");
		expect(cache.get("c")).toBe("tc");
		expect(cache.size()).toBe(2);
	});

	it("overwrites an existing entry and moves it to the end (LRU-by-set)", () => {
		const cache = createTokenCache({ maxEntries: 2 });
		cache.set("a", "ta", Date.now() + 60_000);
		cache.set("b", "tb", Date.now() + 60_000);
		cache.set("a", "ta2", Date.now() + 60_000);
		cache.set("c", "tc", Date.now() + 60_000);

		expect(cache.get("a")).toBe("ta2");
		expect(cache.get("b")).toBeNull();
		expect(cache.get("c")).toBe("tc");
	});

	it("clear() empties the cache", () => {
		const cache = createTokenCache({ maxEntries: 10 });
		cache.set("k1", "tok1", Date.now() + 60_000);
		cache.set("k2", "tok2", Date.now() + 60_000);
		cache.clear();
		expect(cache.size()).toBe(0);
		expect(cache.get("k1")).toBeNull();
	});
});
