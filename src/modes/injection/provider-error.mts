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
 * Below this length a credential is only matched exactly: a substring test on
 * a one- or two-character value would refuse ordinary text for no gain.
 */
const MIN_CONTAINED_CREDENTIAL_LENGTH = 8;

const echoesCredential = (value: string, credentials: readonly string[]): boolean =>
	credentials.some((credential) =>
		credential.length >= MIN_CONTAINED_CREDENTIAL_LENGTH
			? value.includes(credential)
			: credential.length > 0 && value === credential,
	);

/**
 * The provider's `error` value, reduced to something safe to log.
 *
 * The value is provider-controlled. A malformed or compromised provider that
 * echoed the submitted assertion or the proxy's client secret back as `error`
 * would otherwise put a credential into the proxy's logs. Only a value that is
 * shaped like an OAuth error code survives: the RFC 6749 charset without
 * whitespace, at most 64 characters, nothing shaped like a JWT, and none of
 * `credentials` inside it (a credential shorter than 8 characters only as an
 * exact match). Anything else is recorded as
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

/**
 * How both paths turn a body's bytes into text.
 *
 * `TextDecoder` rather than `Buffer.toString("utf8")` because the two differ
 * on one input: a leading BOM. `TextDecoder` drops it (`ignoreBOM` defaults to
 * `false`), `Buffer` keeps it, and `JSON.parse` then refuses the body. Dropping
 * it is what `Response.text()` does, which is what the success path used until
 * it started reading through here (#95 F35) — so this keeps both paths reading
 * a BOM-prefixed body the way the success path always did. Neither is `fatal`,
 * so invalid UTF-8 is U+FFFD in both.
 */
const utf8 = new TextDecoder();

/**
 * A provider response's body as a JSON object, or `null` — read at most
 * `maxBytes` of it, decoded as UTF-8.
 *
 * There is no reason to buffer an unbounded body on either path: a body over
 * the limit is abandoned (the stream is cancelled) rather than read to the
 * end. An empty, non-JSON or non-object body, an array, or a stream that fails
 * mid-read, is `null` — never an exception that would change how the response
 * is answered.
 *
 * The bound is the caller's, and each path has its own: an error body is
 * consulted only for its diagnostic `error` code ({@link MAX_ERROR_BODY_BYTES}),
 * while a token response is the answer itself and is allowed more
 * (`MAX_TOKEN_BODY_BYTES` in `token-endpoint.mts`, #95 F35). `maxBytes`
 * defaults to the error bound because this module owns that path; a caller on
 * any other one passes its own rather than inheriting it.
 */
export const readBoundedJsonObject = async (
	resp: Response,
	maxBytes: number = MAX_ERROR_BODY_BYTES,
): Promise<Record<string, unknown> | null> => {
	if (resp.body === null) {
		return null;
	}
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		// Inside the try with the read itself: getReader throws on a body that
		// is already locked or read, and this answers null for a body it cannot
		// read rather than making its caller handle an exception.
		const reader = resp.body.getReader();
		for (;;) {
			const { done, value } = await reader.read();
			if (done) {
				break;
			}
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel().catch(() => undefined);
				return null;
			}
			chunks.push(value);
		}
	} catch {
		return null;
	}
	try {
		// TextDecoder, not Buffer.toString("utf8"): it is the UTF-8 decode
		// Response.text() performs, which drops a leading BOM. Buffer keeps it
		// and JSON.parse then refuses the body — which would cost the diagnostic
		// here, and a whole token response on the success path (#95 F35).
		const parsed: unknown = JSON.parse(utf8.decode(Buffer.concat(chunks)));
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
};
