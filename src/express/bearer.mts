// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The `Authorization: Bearer` grammar the validation path reads with:
 * `extractBearerToken` answers the token a header carries, and
 * `namesBearerScheme` whether a header it refused still named `Bearer`.
 */

/**
 * Parses an `Authorization` header, answering the credential it carries with
 * the scheme stripped, or null for anything that is not a `Bearer` credential.
 *
 * The scheme comparison is case-sensitive, stricter than RFC 7235's
 * case-insensitive `auth-scheme`. Loosening it would admit requests the
 * upstream has never seen, widening what reaches the protected service, so it
 * changes only as its own decision, with its own tests.
 *
 * What is returned is the first SP-delimited word, which is not always what is
 * forwarded: the upstream receives the header as received (an invariant of
 * `src/modes/validation`, stated in its README).
 */
export function extractBearerToken(header: string | undefined): string | null {
	if (!header) return null;
	const [type, token] = header.split(" ");
	if (type !== "Bearer" || !token) return null;
	return token;
}

/**
 * Whether a header {@link extractBearerToken} refused named the `Bearer`
 * scheme by this module's own rule — so it was a malformed Bearer credential
 * (`Bearer`, `Bearer  t`), not another method. RFC 6750 §3.1
 * answers the two differently: `invalid_request` for the first, no error
 * code for the second. A lowercase `bearer` is the second here, since
 * `extractBearerToken` does not admit it.
 */
export function namesBearerScheme(header: string): boolean {
	return header.split(" ")[0] === "Bearer";
}
