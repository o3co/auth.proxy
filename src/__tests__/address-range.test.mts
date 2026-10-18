// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * An `auth.injection.trustedProxies` entry (`address-range.mts`): an IP
 * address, or an address and a prefix length. The schema refuses anything else
 * at boot, and the injection path reads the same grammar.
 */
import { describe, expect, it } from "vitest";
import { parseAddressRange } from "../address-range.mjs";

describe("parseAddressRange", () => {
	it.each([
		["10.0.0.0/8", { address: "10.0.0.0", prefix: 8, family: "ipv4" }],
		["192.0.2.1", { address: "192.0.2.1", prefix: 32, family: "ipv4" }],
		["0.0.0.0/0", { address: "0.0.0.0", prefix: 0, family: "ipv4" }],
		["::1", { address: "::1", prefix: 128, family: "ipv6" }],
		["fd00::/8", { address: "fd00::", prefix: 8, family: "ipv6" }],
		["2001:db8::/32", { address: "2001:db8::", prefix: 32, family: "ipv6" }],
	])("reads %j", (entry, range) => {
		expect(parseAddressRange(entry)).toEqual(range);
	});

	it.each([
		[""],
		["10.0.0.0/33"],
		["::/129"],
		["10.0.0.0/"],
		["/8"],
		["10.0.0.0/08"],
		["10.0.0.0/8/9"],
		["10.0.0.0/-1"],
		["proxy.internal"],
		["10.0.0.1:80"],
		[" 10.0.0.1"],
		["10.0.0.256"],
		["fe80::1%eth0"],
		["fe80::%eth0/64"],
	])("refuses %j", (entry) => {
		expect(parseAddressRange(entry)).toBeNull();
	});
});
