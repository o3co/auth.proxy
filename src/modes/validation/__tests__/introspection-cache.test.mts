// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The introspection cache's own contract (#95 F5): what it serves, when it
 * stops, and how it stays bounded. Which responses are put in it, and with
 * what expiry, is `introspect.test.mts`.
 */
import { describe, expect, it, vi } from "vitest";

import { createIntrospectionCache } from "../introspection-cache.mjs";

const AT = 1_700_000_000_000;

describe("createIntrospectionCache", () => {
	it("serves an entry until its expiry and not after it", () => {
		const clock = vi.spyOn(Date, "now").mockReturnValue(AT);
		try {
			const cache = createIntrospectionCache({ maxEntries: 10 });
			cache.set("k", { active: true }, AT + 1000);

			expect(cache.get("k")).toEqual({ active: true });
			clock.mockReturnValue(AT + 999);
			expect(cache.get("k")).toEqual({ active: true });
			// The instant it reaches its expiry it stops being served — the
			// boundary the warm-entry case in the router test lands on.
			clock.mockReturnValue(AT + 1000);
			expect(cache.get("k")).toBeNull();
		} finally {
			clock.mockRestore();
		}
	});

	it("answers null for a key it does not hold", () => {
		expect(createIntrospectionCache({ maxEntries: 10 }).get("absent")).toBeNull();
	});

	it("sweeps expired entries before applying the bound, so a live entry is not evicted for a dead one", () => {
		const clock = vi.spyOn(Date, "now").mockReturnValue(AT);
		try {
			// `live` is the oldest insertion and `stale` the one that dies, so a
			// cache that dropped the oldest first would evict the usable entry
			// and keep the corpse.
			const cache = createIntrospectionCache({ maxEntries: 2 });
			cache.set("live", { active: true, sub: "live" }, AT + 5000);
			cache.set("stale", { active: true }, AT + 500);
			expect(cache.size()).toBe(2);

			clock.mockReturnValue(AT + 1000);
			cache.set("new", { active: true }, AT + 5000);

			expect(cache.size()).toBe(2);
			expect(cache.get("stale")).toBeNull();
			expect(cache.get("live")).toEqual({ active: true, sub: "live" });
		} finally {
			clock.mockRestore();
		}
	});

	it("below the bound, a re-set keeps its position: eviction is by insertion, not by use", () => {
		// The injection path's `TokenCache` re-inserts on every `set`; this one
		// does not, which is the behaviour it replaced. Refreshing `a` while
		// there is room does not save it from being the first one dropped.
		const cache = createIntrospectionCache({ maxEntries: 3 });
		const live = Date.now() + 60_000;
		cache.set("a", { active: true }, live);
		cache.set("b", { active: true }, live);
		cache.set("a", { active: true, sub: "refreshed" }, live);
		expect(cache.get("a")).toEqual({ active: true, sub: "refreshed" });

		cache.set("c", { active: true }, live);
		cache.set("d", { active: true }, live);

		expect(cache.get("a")).toBeNull();
		expect(cache.get("b")).not.toBeNull();
	});

	it("drops the oldest insertion at the bound", () => {
		const cache = createIntrospectionCache({ maxEntries: 2 });
		cache.set("a", { active: true }, Date.now() + 60_000);
		cache.set("b", { active: true }, Date.now() + 60_000);
		cache.set("c", { active: true }, Date.now() + 60_000);

		expect(cache.size()).toBe(2);
		expect(cache.get("a")).toBeNull();
		expect(cache.get("b")).not.toBeNull();
		expect(cache.get("c")).not.toBeNull();
	});

	it("evicts nothing when the write is a key it already holds, even at the bound", () => {
		// Reachable on the proxy's path as well as by a direct caller: with no
		// single-flight, two requests for one token both miss and both write, and
		// the second write is this case — see the composition-level test in
		// `introspect.test.mts`. The fused function this replaced evicted an
		// unrelated live entry here.
		const cache = createIntrospectionCache({ maxEntries: 2 });
		const live = Date.now() + 60_000;
		cache.set("a", { active: true, sub: "a" }, live);
		cache.set("b", { active: true, sub: "b" }, live);
		cache.set("b", { active: true, sub: "refreshed" }, live);

		expect(cache.size()).toBe(2);
		expect(cache.get("a")).toEqual({ active: true, sub: "a" });
		expect(cache.get("b")).toEqual({ active: true, sub: "refreshed" });
	});

	it("clears", () => {
		const cache = createIntrospectionCache({ maxEntries: 10 });
		cache.set("a", { active: true }, Date.now() + 60_000);
		cache.clear();
		expect(cache.size()).toBe(0);
		expect(cache.get("a")).toBeNull();
	});
});
