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
 * The provider's `error` value, reduced to something safe to log.
 *
 * The value is provider-controlled. A malformed or compromised provider that
 * echoed the submitted assertion or the proxy's client secret back as `error`
 * would otherwise put a credential into the proxy's logs. Only a value that is
 * shaped like an OAuth error code survives: the RFC 6749 charset without
 * whitespace, at most 64 characters, nothing shaped like a JWT, and none of
 * `credentials` inside it. Anything else is recorded as
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
		credentials.some((credential) => credential.length > 0 && value.includes(credential))
	) {
		return INVALID_ERROR_CODE;
	}
	return value;
};
