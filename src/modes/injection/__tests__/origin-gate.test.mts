// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether a browser request showed that it came from this proxy's own pages
 * (`origin-gate.mts`), the condition for answering it from the session cache.
 * The provider holds a session grant to the same check, and a cache hit never
 * reaches the provider.
 */
import { describe, expect, it } from "vitest";
import { createSameOriginGate } from "../origin-gate.mjs";
import type { CallerContext } from "../session-grant-client.mjs";

const PUBLIC = "https://admin.example";

type Signals = Pick<CallerContext, "origin" | "secFetchSite" | "referer" | "protocol">;

/** A request over https with neither signal; each test adds what it is about. */
const caller = (signals: Partial<Signals>): Signals => ({
	origin: null,
	secFetchSite: null,
	referer: null,
	protocol: "https",
	...signals,
});

/** The gate for `publicOrigin`, asked about one request. */
const isSameOriginRequest = (signals: Signals, publicOrigin: string | null): boolean =>
	createSameOriginGate(publicOrigin)(signals);

describe("createSameOriginGate", () => {
	// The public origin is read once, when the gate is built, not per request.
	it("reads the public origin when it is built, refusing one that is not a URL", () => {
		expect(() => createSameOriginGate("not an origin")).toThrow();
	});

	it("admits an Origin equal to the public origin", () => {
		expect(isSameOriginRequest(caller({ origin: PUBLIC }), PUBLIC)).toBe(true);
		expect(isSameOriginRequest(caller({ origin: PUBLIC, secFetchSite: "same-origin" }), PUBLIC)).toBe(true);
	});

	it("admits Sec-Fetch-Site: same-origin when there is no Origin", () => {
		expect(isSameOriginRequest(caller({ secFetchSite: "same-origin" }), PUBLIC)).toBe(true);
		expect(isSameOriginRequest(caller({ secFetchSite: "same-origin" }), null)).toBe(true);
	});

	it("refuses any other Origin, even with Sec-Fetch-Site: same-origin", () => {
		for (const origin of ["https://elsewhere.example", "http://admin.example", "https://admin.example:8443", "null", ""]) {
			expect(isSameOriginRequest(caller({ origin, secFetchSite: "same-origin" }), PUBLIC), origin).toBe(false);
		}
	});

	it("refuses an Origin equal to the public origin when Sec-Fetch-Site says anything but same-origin", () => {
		for (const secFetchSite of ["cross-site", "same-site", "none", ""]) {
			expect(isSameOriginRequest(caller({ origin: PUBLIC, secFetchSite }), PUBLIC), secFetchSite).toBe(false);
		}
	});

	it("refuses an Origin when no public origin is configured", () => {
		expect(isSameOriginRequest(caller({ origin: PUBLIC, secFetchSite: "same-origin" }), null)).toBe(false);
	});

	it("refuses a request with neither signal, or another Sec-Fetch-Site", () => {
		for (const secFetchSite of [null, "same-site", "cross-site", "none", "SAME-ORIGIN"]) {
			expect(isSameOriginRequest(caller({ secFetchSite }), PUBLIC), String(secFetchSite)).toBe(false);
		}
	});

	// The provider reads the Referer's origin as evidence beside Origin: one
	// that names another origin refuses, whatever the other signals say.
	describe("Referer", () => {
		it("admits a Referer on the public origin", () => {
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer: `${PUBLIC}/app/page?x=1` }), PUBLIC)).toBe(true);
			expect(isSameOriginRequest(caller({ origin: PUBLIC, referer: `${PUBLIC}/` }), PUBLIC)).toBe(true);
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer: "HTTPS://Admin.Example:443/x" }), PUBLIC)).toBe(true);
		});

		it("refuses a Referer on another origin, even with an Origin equal to the public origin", () => {
			for (const referer of ["https://elsewhere.example/", "http://admin.example/", "https://admin.example:8443/"]) {
				expect(isSameOriginRequest(caller({ origin: PUBLIC, secFetchSite: "same-origin", referer }), PUBLIC), referer).toBe(false);
				expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer }), PUBLIC), referer).toBe(false);
			}
		});

		it("reads a Referer that names no origin as no evidence", () => {
			for (const referer of ["", "not a url", "/relative/path", "about:blank", "data:text/plain,x", "null"]) {
				expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer }), PUBLIC), referer).toBe(true);
			}
		});

		it("refuses a Referer that names an origin while no public origin is configured", () => {
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer: `${PUBLIC}/` }), null)).toBe(false);
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", referer: "about:blank" }), null)).toBe(true);
		});
	});

	// The provider refuses a plain-http request when its cookies are secure,
	// which the proxy cannot see; it requires the public origin's scheme.
	describe("scheme", () => {
		it("refuses a request whose scheme is not the public origin's", () => {
			expect(isSameOriginRequest(caller({ origin: PUBLIC, protocol: "http" }), PUBLIC)).toBe(false);
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", protocol: "http" }), PUBLIC)).toBe(false);
			expect(isSameOriginRequest(caller({ origin: "http://localhost:8080", protocol: "https" }), "http://localhost:8080")).toBe(false);
		});

		it("admits a plain-http request to a plain-http public origin", () => {
			expect(isSameOriginRequest(caller({ origin: "http://localhost:8080", protocol: "http" }), "http://localhost:8080")).toBe(true);
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", protocol: "http" }), "http://localhost:8080")).toBe(true);
		});

		it("requires https while no public origin is configured", () => {
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", protocol: "http" }), null)).toBe(false);
			expect(isSameOriginRequest(caller({ secFetchSite: "same-origin", protocol: "https" }), null)).toBe(true);
		});
	});
});
