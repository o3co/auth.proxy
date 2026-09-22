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

	it("sweeps expired entries on the next write, so a stale one does not hold a slot", () => {
		const clock = vi.spyOn(Date, "now").mockReturnValue(AT);
		try {
			const cache = createIntrospectionCache({ maxEntries: 10 });
			cache.set("stale", { active: true }, AT + 500);
			cache.set("live", { active: true }, AT + 5000);
			expect(cache.size()).toBe(2);

			clock.mockReturnValue(AT + 1000);
			cache.set("new", { active: true }, AT + 5000);

			expect(cache.size()).toBe(2);
			expect(cache.get("stale")).toBeNull();
			expect(cache.get("live")).not.toBeNull();
		} finally {
			clock.mockRestore();
		}
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

	it("clears", () => {
		const cache = createIntrospectionCache({ maxEntries: 10 });
		cache.set("a", { active: true }, Date.now() + 60_000);
		cache.clear();
		expect(cache.size()).toBe(0);
		expect(cache.get("a")).toBeNull();
	});
});
