// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * `http.bodyLimitSize` as a number of bytes, read once by the schema and by
 * the router that enforces it, so the limit refused ahead of a mode and the
 * limit the upstream stage reads a body against are one number.
 *
 * A byte size is a non-negative decimal number, optionally signed `+`, then
 * optionally a unit — `b`, `kb`, `mb`, `gb`, `tb` or `pb`, any case, 1 kb =
 * 1024 bytes — with any fraction of a byte dropped. The upstream stage's body
 * reader (`raw-body`, through `bytes`) reads every such value as the same
 * count. It reads some other values too, but not as a limit anyone meant:
 * `"10 megabytes"` as 10 bytes, `"ten"` as no limit at all. Those are not
 * byte sizes here.
 */

const UNITS = ["b", "kb", "mb", "gb", "tb", "pb"] as const;
const BYTE_SIZE = /^\+?(\d+(?:\.\d+)?) *(b|kb|mb|gb|tb|pb)?$/i;

/** The byte count `value` names, or `null` when it is not a byte size. */
export const parseByteSize = (value: string): number | null => {
	const match = BYTE_SIZE.exec(value);
	if (match === null) return null;
	const unit = (match[2] ?? "b").toLowerCase() as (typeof UNITS)[number];
	return Math.floor(Number(match[1]) * 1024 ** UNITS.indexOf(unit));
};
