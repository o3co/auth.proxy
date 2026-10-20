// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a browser request came from, as this proxy can vouch for it
 * (`request-source.mts`): the address and the scheme the session grant and
 * the exchange tell the provider as `X-Forwarded-For` and `X-Forwarded-Proto`.
 * A forwarded header counts only when the peer that sent it is one of
 * `auth.injection.trustedProxies`; anything else is the client's own claim.
 */
import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { createRequestSource, forwardedHeaders, trustAllEntries } from "../request-source.mjs";

interface FakeRequest {
	peer?: string;
	encrypted?: boolean;
	forwardedFor?: string;
	forwardedProto?: string;
}

const request = ({ peer, encrypted, forwardedFor, forwardedProto }: FakeRequest): IncomingMessage =>
	({
		socket: { remoteAddress: peer, ...(encrypted === undefined ? {} : { encrypted }) },
		headers: {
			...(forwardedFor === undefined ? {} : { "x-forwarded-for": forwardedFor }),
			...(forwardedProto === undefined ? {} : { "x-forwarded-proto": forwardedProto }),
		},
	}) as unknown as IncomingMessage;

const sourceOf = (trustedProxies: string[], req: FakeRequest) =>
	createRequestSource(trustedProxies)(request(req));

describe("createRequestSource", () => {
	describe("with no trusted proxies", () => {
		it("is the socket's peer and scheme, whatever the forwarded headers claim", () => {
			expect(
				sourceOf([], { peer: "198.51.100.7", forwardedFor: "203.0.113.1", forwardedProto: "https" }),
			).toEqual({ address: "198.51.100.7", protocol: "http" });
		});

		it("is https on a TLS socket", () => {
			expect(sourceOf([], { peer: "198.51.100.7", encrypted: true })).toEqual({
				address: "198.51.100.7",
				protocol: "https",
			});
		});

		it("has no address when the socket has none (it already closed)", () => {
			expect(sourceOf([], {})).toEqual({ address: null, protocol: "http" });
		});
	});

	describe("the address, behind trusted proxies", () => {
		const TRUSTED = ["10.0.0.0/8", "fd00::/8"];

		it("walks X-Forwarded-For from the right to the first address that is not a trusted proxy", () => {
			expect(
				sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "198.51.100.9, 203.0.113.5, 10.0.0.7" }).address,
			).toBe("203.0.113.5");
		});

		it("is the leftmost address when every hop is trusted", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "10.0.0.9, 10.0.0.7" }).address).toBe(
				"10.0.0.9",
			);
		});

		it("is the trusted peer itself when it sent no X-Forwarded-For", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2" }).address).toBe("10.0.0.2");
		});

		it("ignores X-Forwarded-For from a peer that is not trusted", () => {
			expect(sourceOf(TRUSTED, { peer: "198.51.100.7", forwardedFor: "203.0.113.1" }).address).toBe(
				"198.51.100.7",
			);
		});

		it("stops at the last address it could read when a hop is not an IP address", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "garbage, 10.0.0.7" }).address).toBe(
				"10.0.0.7",
			);
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "203.0.113.5:443" }).address).toBe(
				"10.0.0.2",
			);
		});

		it("stops at a hop with an IPv6 zone ID, which names no address another host can reach", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "fe80::1%eth0" }).address).toBe("10.0.0.2");
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedFor: "fd00::1%eth0, 10.0.0.7" }).address).toBe(
				"10.0.0.7",
			);
		});

		it("matches an IPv4-mapped peer against an IPv4 range, and IPv6 against IPv6", () => {
			expect(
				sourceOf(TRUSTED, { peer: "::ffff:10.0.0.2", forwardedFor: "203.0.113.5" }).address,
			).toBe("203.0.113.5");
			expect(sourceOf(TRUSTED, { peer: "fd00::1", forwardedFor: "2001:db8::5" }).address).toBe("2001:db8::5");
		});
	});

	describe("the scheme, behind trusted proxies", () => {
		const TRUSTED = ["10.0.0.0/8"];

		it("is a trusted peer's single X-Forwarded-Proto", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "https" }).protocol).toBe("https");
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "HTTPS" }).protocol).toBe("https");
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "http" }).protocol).toBe("http");
		});

		it("is the socket's when the value is a list or not http(s)", () => {
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "https, http" }).protocol).toBe("http");
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "wss" }).protocol).toBe("http");
			expect(sourceOf(TRUSTED, { peer: "10.0.0.2", forwardedProto: "" }).protocol).toBe("http");
		});

		it("is the socket's when the peer is not trusted", () => {
			expect(sourceOf(TRUSTED, { peer: "198.51.100.7", forwardedProto: "https" }).protocol).toBe("http");
		});
	});

	describe("trustAllEntries", () => {
		it("names the entries that trust every address of their family", () => {
			expect(trustAllEntries(["10.0.0.0/8", "0.0.0.0/0", "::/0", "::1"])).toEqual(["0.0.0.0/0", "::/0"]);
		});

		it("is empty for a list that names its proxies", () => {
			expect(trustAllEntries(["10.0.0.0/8", "192.0.2.1"])).toEqual([]);
		});

		// An IPv4 address is checked against IPv6 entries as its IPv4-mapped
		// form, so an IPv6 range that holds all of ::ffff:0:0/96 trusts every
		// IPv4 client.
		it("names an IPv6 entry whose range holds every IPv4-mapped address", () => {
			const entries = ["::ffff:0:0/96", "::ffff:0.0.0.0/96", "::/80", "::/1", "::ffff:1.2.3.4/90"];
			expect(trustAllEntries(entries)).toEqual(entries);
		});

		it("does not name an IPv6 entry that holds only part of the IPv4-mapped range, or none of it", () => {
			expect(trustAllEntries(["::ffff:0:0/97", "::/81", "8000::/1", "fd00::/8", "::ffff:10.0.0.0/104"])).toEqual([]);
		});

		it("names an IPv4 /0 whatever address it is written with", () => {
			expect(trustAllEntries(["10.0.0.0/0"])).toEqual(["10.0.0.0/0"]);
		});
	});

	// The source as the provider is told it: set whole, so nothing a client
	// sent under these names goes on.
	describe("forwardedHeaders", () => {
		it("says the address and the scheme", () => {
			expect(forwardedHeaders({ address: "203.0.113.7", protocol: "https" })).toEqual({
				"X-Forwarded-For": "203.0.113.7",
				"X-Forwarded-Proto": "https",
			});
		});

		it("says only the scheme when the address is unknown", () => {
			expect(forwardedHeaders({ address: null, protocol: "http" })).toEqual({ "X-Forwarded-Proto": "http" });
		});
	});

	it("refuses an entry that is not an address or a range, naming it", () => {
		expect(() => createRequestSource(["10.0.0.0/8", "proxy.internal"])).toThrow(/proxy\.internal/);
	});
});
