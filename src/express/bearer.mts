// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/** A parsed `Authorization: Bearer <token>` header. */
export interface BearerToken {
	/** The credential itself, with the scheme stripped. */
	token: string;
	/** The header as received, for forwarding it on unchanged. */
	raw: string;
}

/**
 * Parses an `Authorization` header, returning null for anything that is not a
 * `Bearer` credential.
 *
 * The scheme comparison is case-sensitive, which is stricter than RFC 7235's
 * case-insensitive `auth-scheme`. That is the behaviour this proxy shipped
 * with, and loosening it here would start admitting requests the upstream has
 * never seen — a widening of what reaches the protected service, decided as a
 * side effect of moving a file. It stays as it was; changing it is its own
 * decision with its own tests.
 */
export function extractBearerToken(header: string | undefined): BearerToken | null {
	if (!header) return null;
	const [type, token] = header.split(" ");
	if (type !== "Bearer" || !token) return null;
	return { token, raw: header };
}
