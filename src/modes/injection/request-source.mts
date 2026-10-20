// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a browser request came from, as this proxy can vouch for it:
 * `createRequestSource` builds, from `auth.injection.trustedProxies`, the
 * function that reads a request's address and scheme, and `forwardedHeaders`
 * says them to the provider as `X-Forwarded-For` and `X-Forwarded-Proto` on
 * the session grant and the exchange alike, so they are this proxy's own
 * statement, never a client's claim passed on.
 *
 * The address starts at the socket's peer. Only while the address in hand is a
 * trusted proxy is the hop it reported believed: `X-Forwarded-For` is walked
 * from the right, and the walk stops at the first address that is not a
 * trusted proxy — the browser, as far as the trusted chain can tell. Every
 * address to the left of it was written by someone this proxy does not trust.
 * A hop that is not an IP address — a host name, a port, an IPv6 zone ID —
 * ends the walk at the last address read. With
 * an empty list, nothing is trusted: the address is the socket's peer.
 *
 * The scheme is the socket's (`https` on a TLS socket, otherwise `http`),
 * unless the peer is a trusted proxy that sent exactly one `X-Forwarded-Proto`
 * value, `http` or `https`. A list is not read, because a proxy that appends
 * to the header leaves the client's own value at its head.
 */

import type { IncomingMessage } from "node:http";
import net from "node:net";
import { type AddressRange, ipVersion, parseAddressRange } from "../../address-range.mjs";

export type RequestProtocol = "http" | "https";

export interface RequestSource {
	/** The browser's address; `null` when the socket no longer has a peer. */
	address: string | null;
	protocol: RequestProtocol;
}

const headerValue = (value: string | string[] | undefined): string | undefined =>
	Array.isArray(value) ? value.join(",") : value;

/** `auth.injection.trustedProxies` as a list to check addresses against. Throws naming an entry it cannot read. */
const buildTrustList = (trustedProxies: readonly string[]): net.BlockList => {
	const list = new net.BlockList();
	for (const entry of trustedProxies) {
		const range = parseAddressRange(entry);
		if (range === null) {
			throw new Error(
				`auth.injection.trustedProxies: ${JSON.stringify(entry)} is not an IP address or an address/prefix range`,
			);
		}
		list.addSubnet(range.address, range.prefix, range.family);
	}
	return list;
};

/** The first IPv4-mapped IPv6 address: an IPv6 range of prefix 96 or shorter that holds it holds them all. */
const FIRST_IPV4_MAPPED = "::ffff:0:0";

/** Whether `range` holds every address of a family. */
const trustsAll = (range: AddressRange): boolean => {
	if (range.prefix === 0) return true;
	if (range.family === "ipv4" || range.prefix > 96) return false;
	// An IPv4 address is checked against an IPv6 range as its IPv4-mapped form.
	const one = new net.BlockList();
	one.addSubnet(range.address, range.prefix, "ipv6");
	return one.check(FIRST_IPV4_MAPPED, "ipv6");
};

/**
 * The entries that, each on its own, trust every IPv4 address or every IPv6
 * address (`0.0.0.0/0`, `::/0`, `::ffff:0:0/96`, any IPv6 range that holds
 * `::ffff:0:0/96`): with one, any client can tell the provider any address and
 * scheme it likes. The router warns about them when it is built. Several
 * entries that cover a family only together are not named. Entries it cannot
 * read are left to `createRequestSource`, which refuses them.
 */
export const trustAllEntries = (trustedProxies: readonly string[]): string[] =>
	trustedProxies.filter((entry) => {
		const range = parseAddressRange(entry);
		return range !== null && trustsAll(range);
	});

/**
 * The headers that tell the provider `source`: this proxy's own statement, set
 * whole, so nothing a client sent under these names goes on. No
 * `X-Forwarded-For` when the address is unknown.
 */
export const forwardedHeaders = (source: RequestSource): Record<string, string> => ({
	...(source.address !== null ? { "X-Forwarded-For": source.address } : {}),
	"X-Forwarded-Proto": source.protocol,
});

export const createRequestSource = (
	trustedProxies: readonly string[],
): ((req: IncomingMessage) => RequestSource) => {
	const list = buildTrustList(trustedProxies);
	const trusted = (address: string): boolean => {
		const version = net.isIP(address);
		return version !== 0 && list.check(address, version === 4 ? "ipv4" : "ipv6");
	};

	return (req) => {
		const peer = req.socket.remoteAddress ?? null;
		const socketProtocol: RequestProtocol =
			(req.socket as { encrypted?: boolean }).encrypted === true ? "https" : "http";
		if (peer === null || !trusted(peer)) {
			return { address: peer, protocol: socketProtocol };
		}

		let address = peer;
		const hops = (headerValue(req.headers["x-forwarded-for"]) ?? "")
			.split(",")
			.map((hop) => hop.trim())
			.filter((hop) => hop.length > 0);
		for (let i = hops.length - 1; i >= 0 && trusted(address); i--) {
			const hop = hops[i] as string;
			if (ipVersion(hop) === 0) break;
			address = hop;
		}

		const proto = headerValue(req.headers["x-forwarded-proto"])?.trim().toLowerCase();
		const protocol = proto === "http" || proto === "https" ? proto : socketProtocol;
		return { address, protocol };
	};
};
