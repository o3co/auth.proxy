// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Parses an `Authorization` header, answering the credential it carries with
 * the scheme stripped, or null for anything that is not a `Bearer` credential.
 *
 * A bare string rather than a one-field object (#95 F36): the object held the
 * header as received beside the token until F15 removed it, and what remained
 * was a record with one field, one caller and nothing substituting it. The
 * absent case is the null, which is what the caller branches on either way.
 *
 * The scheme comparison is case-sensitive, which is stricter than RFC 7235's
 * case-insensitive `auth-scheme`. That is the behaviour this proxy shipped
 * with, and loosening it here would start admitting requests the upstream has
 * never seen — a widening of what reaches the protected service, decided as a
 * side effect of moving a file. It stays as it was; changing it is its own
 * decision with its own tests.
 *
 * What is returned is the first SP-delimited word, which is not always what is
 * forwarded: the upstream receives the header as received. See "Inputs and
 * outputs" in `src/modes/validation/README.md`.
 */
export function extractBearerToken(header: string | undefined): string | null {
	if (!header) return null;
	const [type, token] = header.split(" ");
	if (type !== "Bearer" || !token) return null;
	return token;
}
