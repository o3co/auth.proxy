// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * `http.bodyLimitSize` as a number of bytes, read once by the schema and by
 * the router that enforces it, so the limit refused ahead of a mode and the
 * limit the upstream stage reads a body against are one number.
 *
 * The grammar is the one the upstream stage's body reader (`raw-body`,
 * through `bytes`) has always accepted, and the value means what it meant
 * there: a non-negative decimal number, optionally followed by a unit — `b`,
 * `kb`, `mb`, `gb`, `tb` or `pb`, any case, 1 kb = 1024 bytes — with any
 * fraction of a byte dropped. What that reader turned into a different limit
 * (`"10 megabytes"` is 10 bytes to it) or into none at all (`"ten"`) is not a
 * byte size here.
 */

const UNITS = ["b", "kb", "mb", "gb", "tb", "pb"] as const;
const BYTE_SIZE = /^(\d+(?:\.\d+)?) *(b|kb|mb|gb|tb|pb)?$/i;

/** The byte count `value` names, or `null` when it is not a byte size. */
export const parseByteSize = (value: string): number | null => {
	const match = BYTE_SIZE.exec(value);
	if (match === null) return null;
	const unit = (match[2] ?? "b").toLowerCase() as (typeof UNITS)[number];
	return Math.floor(Number(match[1]) * 1024 ** UNITS.indexOf(unit));
};
