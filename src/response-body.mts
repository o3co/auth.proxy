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
 * What to do with a provider response once the answer has been decided
 * without it. Both modes need this, and it belongs to neither, the way
 * `single-flight.mts` does not.
 */

/**
 * Releases a body nothing is going to read (#95 F28, F37).
 *
 * Every client in this proxy answers some statuses from the status alone — a
 * refusal, a redirect, an outage — and throws without touching the body.
 * What an unread body costs depends on its size, measured on Node 26 /
 * undici 8. Within undici's read-ahead buffer (64 KiB) it costs nothing:
 * undici has already read the whole body and returned the socket to the pool,
 * cancelled or not — and every realistic refusal body is tens of bytes.
 * Beyond that buffer an unread body holds its socket until the `Response` is
 * garbage-collected, and a provider sending large refusal bodies under load
 * accumulates held sockets for as long as the collector allows. Cancelling
 * bounds that: the socket is closed rather than returned to the pool, so the
 * next request connects afresh, but nothing accumulates.
 *
 * So this is defensive rather than a fix for anything a well-behaved provider
 * does, and it is cheap enough to be right to call anyway.
 *
 * A cancel that itself fails is swallowed. It is not the answer: a stream
 * that is already errored — the connection reset before anything read it —
 * rejects its own cancel with the stored error, and letting that propagate
 * would replace the refusal the caller is about to throw with a failure of
 * releasing a stream nobody wanted.
 */
export const discardBody = async (resp: Response): Promise<void> => {
	await resp.body?.cancel().catch(() => undefined);
};

/**
 * How every bounded read turns a body's bytes into text.
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
 * The bound is the caller's and has no default, because every path has its
 * own and a default would be one path's bound inherited silently by another:
 * an error body is consulted only for its diagnostic `error` code
 * (`MAX_ERROR_BODY_BYTES` in `modes/injection/provider-error.mts`), a token
 * response is the answer itself and is allowed more (`MAX_TOKEN_BODY_BYTES`,
 * #95 F35), and so is an introspection response (#95 F39).
 */
export const readBoundedJsonObject = async (
	resp: Response,
	maxBytes: number,
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
