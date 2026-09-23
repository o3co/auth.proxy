/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What the two token clients do with a provider's error text: reduce the
 * provider-controlled `error` and `error_description` to something safe to log
 * or relay, and bound how much of an error body is read. Both clients use it;
 * it belongs to neither, like `token-endpoint.mts`.
 */

/** Recorded in place of a provider `error` value that failed validation. */
export const INVALID_ERROR_CODE = "invalid_error_code";

/**
 * RFC 6749 section 5.2 `error = 1*( %x20-21 / %x23-5B / %x5D-7E )`, without
 * %x20: a code never contains a space, and refusing whitespace keeps a value
 * from passing for something it is not in a log line.
 */
const ERROR_CODE_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const MAX_ERROR_CODE_LENGTH = 64;
/** Three dot-separated base64url runs anywhere in the value: a JWS/JWT. */
const JWT_SHAPE_RE = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;

/**
 * Whether a provider's text carries one of the credentials this request sent,
 * anywhere inside it and at any length (#95 F30).
 *
 * There used to be a length below which only an exact echo counted, on the
 * reasoning that a substring test on a one- or two-character value refuses
 * ordinary text for no gain. It is not for no gain: one of these credentials
 * is the caller's session cookie value, whose length the proxy does not
 * choose and cannot bound, and with the threshold a cookie value of `abc` sat
 * inside `bad abc` in a log line and in the `error_description` relayed to the
 * client.
 *
 * Only one of the three credentials can realistically be short. An assertion
 * is at least nine characters by the time `JWS_COMPACT_RE` and the two
 * base64url JSON segments have admitted it, so this is a no-op there; a client
 * secret is the operator's own configuration; the cookie value is the
 * caller's, and nothing bounds it. The rule is uniform anyway because this
 * function is deliberately anonymous — it does not know which string is
 * which, and buying diagnostics back for a three-character client secret is
 * not worth breaking that.
 *
 * The cost is real and bounded: a very short credential refuses almost any
 * text. What that loses is the provider's diagnostic — every caller classifies
 * the raw value before sanitising, and substitutes its own wording for a
 * refusal, so the status, the code and the logged event are unaffected and
 * only the relayed or logged text changes. A lost diagnostic is cheaper than a
 * credential in a log. The two costs differ in reach: a short cookie degrades
 * that caller's requests, a short secret degrades every exchange refusal until
 * it is rotated — which is a loud nudge to rotate it.
 *
 * An empty credential is skipped: `value.includes("")` is true of every
 * string, so one would otherwise refuse everything.
 */
const echoesCredential = (value: string, credentials: readonly string[]): boolean =>
	credentials.some((credential) => credential.length > 0 && value.includes(credential));

/**
 * The provider's `error` value, reduced to something safe to log.
 *
 * The value is provider-controlled. A malformed or compromised provider that
 * echoed the submitted assertion or the proxy's client secret back as `error`
 * would otherwise put a credential into the proxy's logs. Only a value that is
 * shaped like an OAuth error code survives: the RFC 6749 charset without
 * whitespace, at most 64 characters, nothing shaped like a JWT, and none of
 * `credentials` inside it, at any length (#95 F30). Anything else is recorded as
 * {@link INVALID_ERROR_CODE}; an absent `error` is `null`.
 *
 * Classifying a response still compares the raw value against known codes —
 * a match is by definition one of those constants — so validation only
 * decides what is recorded, never how a response is answered.
 */
export const sanitizeErrorCode = (
	value: unknown,
	credentials: readonly string[],
): string | null => {
	if (value === undefined) {
		return null;
	}
	if (
		typeof value !== "string" ||
		value.length > MAX_ERROR_CODE_LENGTH ||
		!ERROR_CODE_RE.test(value) ||
		JWT_SHAPE_RE.test(value) ||
		echoesCredential(value, credentials)
	) {
		return INVALID_ERROR_CODE;
	}
	return value;
};

/** RFC 6749 section 5.2 `error_description = 1*( %x20-21 / %x23-5B / %x5D-7E )`. */
const ERROR_DESCRIPTION_RE = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;
const MAX_ERROR_DESCRIPTION_LENGTH = 256;

/**
 * The provider's `error_description`, or `null` when it is not safe to log or
 * relay. The same reasoning as {@link sanitizeErrorCode}, for free text: only
 * the RFC 6749 charset (spaces allowed, no other whitespace, DQUOTE or
 * backslash), at most 256 characters, nothing shaped like a JWT, and none of
 * `credentials` inside it. The caller substitutes its own wording for `null`.
 */
export const sanitizeErrorDescription = (
	value: unknown,
	credentials: readonly string[],
): string | null =>
	typeof value === "string" &&
	value.length <= MAX_ERROR_DESCRIPTION_LENGTH &&
	ERROR_DESCRIPTION_RE.test(value) &&
	!JWT_SHAPE_RE.test(value) &&
	!echoesCredential(value, credentials)
		? value
		: null;

/** How much of a provider error body is read before giving up on it. */
export const MAX_ERROR_BODY_BYTES = 16 * 1024;

