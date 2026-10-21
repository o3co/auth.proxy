// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The `Authorization: Bearer` grammar the validation path reads with:
 * `extractBearerToken` answers the token a header carries, and
 * `namesBearerScheme` whether a header it refused still named `Bearer`.
 */

/**
 * RFC 6750 §2.1 `credentials = "Bearer" 1*SP b64token`, with exactly one SP,
 * and nothing before or after:
 *
 *   b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 */
const BEARER_CREDENTIALS = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/;

/**
 * The scheme `Bearer` as a whole RFC 9110 auth-scheme token: followed by the
 * end of the header or by a character that cannot continue a token.
 */
const BEARER_SCHEME = /^Bearer(?![!#$%&'*+\-.^_`|~0-9A-Za-z])/;

/**
 * Parses an `Authorization` header, answering the token it carries, or null
 * for anything that is not exactly `Bearer`, one SP and a b64token.
 *
 * The whole header is the credential: the upstream receives it as received
 * (an invariant of `src/modes/validation`, stated in its README), so a header
 * with anything after the token — a second word, a second token, trailing
 * whitespace — is refused rather than read in part, and no upstream can find
 * in it a token that was not introspected.
 *
 * Stricter than the RFCs on purpose, in two ways, each narrowing what reaches
 * the protected service to the one form it is sure to read the same way:
 *
 *   - the scheme is compared case-sensitively, where RFC 9110 §11.1 makes an
 *     `auth-scheme` case-insensitive;
 *   - exactly one SP separates scheme and token, where RFC 6750 §2.1 allows
 *     `1*SP`.
 *
 * Either changes only as its own decision, with its own tests.
 */
export function extractBearerToken(header: string | undefined): string | null {
	if (header === undefined) return null;
	return BEARER_CREDENTIALS.exec(header)?.[1] ?? null;
}

/**
 * Whether a header {@link extractBearerToken} refused still names the `Bearer`
 * scheme by this module's own rule — its auth-scheme token is exactly
 * `Bearer` — so it was a malformed Bearer credential (`Bearer`, `Bearer  t`,
 * `Bearer t extra`), not another method. RFC 6750 §3.1 answers the two
 * differently: `invalid_request` for the first, no error code for the second.
 * A lowercase `bearer` is the second here, since `extractBearerToken` does not
 * admit it.
 */
export function namesBearerScheme(header: string): boolean {
	return BEARER_SCHEME.test(header);
}
