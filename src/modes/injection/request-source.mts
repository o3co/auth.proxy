// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a browser request came from, as this proxy can vouch for it:
 * `createRequestSource` builds, from `auth.injection.trustedProxies`, the
 * function that reads a request's address and scheme. The session grant
 * forwards them to the provider as `X-Forwarded-For` and `X-Forwarded-Proto`,
 * so they are this proxy's own statement, never a client's claim passed on.
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
import { ipVersion, parseAddressRange } from "../../address-range.mjs";

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
