// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * `http.bodyLimitSize` as a byte count (`byte-size.mts`). The grammar is the
 * one the upstream stage's body reader has always read (`bytes`, through
 * `raw-body`): a number, optionally a unit, 1 kb = 1024 bytes, fractions
 * floored. What that reader turned into a different limit, or into none, is
 * refused instead.
 */
import { describe, expect, it } from "vitest";
import { parseByteSize } from "../byte-size.mjs";

describe("parseByteSize", () => {
	it.each([
		["10mb", 10 * 1024 * 1024],
		["1kb", 1024],
		["1KB", 1024],
		["1 kb", 1024],
		["1.5kb", 1536],
		["1gb", 1024 ** 3],
		["2tb", 2 * 1024 ** 4],
		["1pb", 1024 ** 5],
		["100b", 100],
		["1024", 1024],
		["1.9", 1],
		["0", 0],
	])("reads %j as %d bytes", (value, bytes) => {
		expect(parseByteSize(value)).toBe(bytes);
	});

	// `bytes` reads "10 megabytes" as 10 (parseInt) and "abc" or "" as NaN,
	// which `raw-body` then applies as no limit at all.
	it.each([["10 megabytes"], ["abc"], [""], [" 10mb"], ["-1kb"], ["+1kb"], ["1e3"], ["kb"]])(
		"refuses %j",
		(value) => {
			expect(parseByteSize(value)).toBeNull();
		},
	);
});
