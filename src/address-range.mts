// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * An IP address range as `auth.injection.trustedProxies` writes it: an address
 * (`192.0.2.1`, `::1`), or an address and a prefix length (`10.0.0.0/8`,
 * `fd00::/8`). Read once by the schema, which refuses anything else at boot,
 * and by the injection path, which builds its trust list from the same
 * grammar.
 *
 * An address with a port, a host name or surrounding space is not a range: a
 * trust list that silently dropped such an entry would trust less than the
 * operator wrote, and one that guessed would trust more.
 */

import net from "node:net";

export interface AddressRange {
	address: string;
	prefix: number;
	family: "ipv4" | "ipv6";
}

const PREFIX = /^(0|[1-9][0-9]{0,2})$/;

/** The range `entry` names, or `null` when it is not an address or an address/prefix. */
export const parseAddressRange = (entry: string): AddressRange | null => {
	const parts = entry.split("/");
	if (parts.length > 2) return null;
	const [address, prefixText] = parts as [string, string | undefined];
	const version = net.isIP(address);
	if (version === 0) return null;
	const family = version === 4 ? "ipv4" : "ipv6";
	const width = version === 4 ? 32 : 128;
	if (prefixText === undefined) return { address, prefix: width, family };
	if (!PREFIX.test(prefixText)) return null;
	const prefix = Number(prefixText);
	return prefix <= width ? { address, prefix, family } : null;
};
