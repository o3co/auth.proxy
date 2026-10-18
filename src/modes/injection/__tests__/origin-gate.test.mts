// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether a browser request showed that it came from this proxy's own pages
 * (`origin-gate.mts`), the condition for answering it from the session cache.
 * The provider holds a session grant to the same check, and a cache hit never
 * reaches the provider.
 */
import { describe, expect, it } from "vitest";
import { isSameOriginRequest } from "../origin-gate.mjs";

const PUBLIC = "https://admin.example";

describe("isSameOriginRequest", () => {
	it("admits an Origin equal to the public origin", () => {
		expect(isSameOriginRequest({ origin: PUBLIC, secFetchSite: null }, PUBLIC)).toBe(true);
		expect(isSameOriginRequest({ origin: PUBLIC, secFetchSite: "same-origin" }, PUBLIC)).toBe(true);
	});

	it("admits Sec-Fetch-Site: same-origin when there is no Origin", () => {
		expect(isSameOriginRequest({ origin: null, secFetchSite: "same-origin" }, PUBLIC)).toBe(true);
		expect(isSameOriginRequest({ origin: null, secFetchSite: "same-origin" }, null)).toBe(true);
	});

	it("refuses any other Origin, even with Sec-Fetch-Site: same-origin", () => {
		for (const origin of ["https://elsewhere.example", "http://admin.example", "https://admin.example:8443", "null", ""]) {
			expect(isSameOriginRequest({ origin, secFetchSite: "same-origin" }, PUBLIC), origin).toBe(false);
		}
	});

	it("refuses an Origin when no public origin is configured", () => {
		expect(isSameOriginRequest({ origin: PUBLIC, secFetchSite: "same-origin" }, null)).toBe(false);
	});

	it("refuses a request with neither signal, or another Sec-Fetch-Site", () => {
		for (const secFetchSite of [null, "same-site", "cross-site", "none", "SAME-ORIGIN"]) {
			expect(isSameOriginRequest({ origin: null, secFetchSite }, PUBLIC), String(secFetchSite)).toBe(false);
		}
	});
});
