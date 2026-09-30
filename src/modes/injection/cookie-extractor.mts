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
 * `extractCookie`: the session cookie's value from a `Cookie` header, refused
 * unless it is an RFC 6265 section 4.1.1 `cookie-value`:
 *
 *   cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 *   cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 *                  ; US-ASCII characters excluding CTLs, whitespace,
 *                  ; DQUOTE, comma, semicolon, and backslash
 *
 * The value is interpolated verbatim into the outbound `Cookie` header of the
 * session grant call (session-grant-client.mts), where a delimiter (`;`, `,`,
 * whitespace), a CTL or a non-ASCII byte could malform the header or smuggle a
 * second cookie-pair into the provider request. The runtime does not catch
 * it: Node's `fetch` (undici) rejects only CR / LF / NUL and code points above
 * 0xFF, and `http.validateHeaderValue` only CTLs and DEL.
 *
 * A surrounding DQUOTE pair is accepted and forwarded with the quotes: RFC
 * 6265 section 5.2 has user agents store the cookie-value opaquely, so the
 * proxy hands back the bytes the provider set and lets the provider's parser
 * decide what the quotes mean; the interior is still cookie-octet only. A lone
 * or interior DQUOTE is refused, and so is an empty value, bare or quoted:
 * there is no session identifier to exchange.
 *
 * Whitespace: RFC 6265 section 4.2.1 allows only the SP after ";" (plus OWS at
 * the ends of the header), so SP / HTAB touching a ";" or a header end is
 * separator slack, trimmed from the pair and from the name (which is only
 * compared, never forwarded). The value is taken verbatim after "=", so
 * `sid= abc` is refused rather than normalised. Only SP / HTAB are slack (RFC
 * 7230 OWS): `String.prototype.trim` would also strip a latin-1 NBSP and other
 * Unicode whitespace, which must stay in the value and be refused as
 * non-ASCII.
 *
 * The result tells `absent` (no pair with the name: an anonymous request)
 * from `rejected` (a pair the proxy will not forward: worth an operator's
 * attention). `rejected` carries only a bounded reason, so it can be logged
 * without the value bytes: `empty` (`` or `""`), `quoting` (a DQUOTE anywhere
 * other than exactly one surrounding pair) or `grammar` (a character outside
 * cookie-octet in the unwrapped value).
 *
 * Same-name pairs: a user agent may send a name twice (RFC 6265 section 5.4
 * orders them by path length, then creation time), so a malformed pair does
 * not stop the scan. The first well-formed pair wins; the reason of the first
 * malformed pair before it is reported as `found.skipped`, for the router to
 * log. When every same-name pair is malformed the result is `rejected` with
 * the first pair's reason.
 */
const COOKIE_OCTETS_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

const trimOws = (s: string): string => s.replace(/^[ \t]+|[ \t]+$/g, "");

export type CookieRejectReason = "empty" | "quoting" | "grammar";

export type CookieExtraction =
	| { kind: "absent" }
	| { kind: "rejected"; reason: CookieRejectReason }
	| { kind: "found"; value: string; skipped: CookieRejectReason | null };

type ValueClass =
	| { kind: "rejected"; reason: CookieRejectReason }
	| { kind: "found"; value: string };

const classifyValue = (value: string): ValueClass => {
	if (value === "" || value === '""') return { kind: "rejected", reason: "empty" };
	const wrapped = value.length >= 2 && value.startsWith('"') && value.endsWith('"');
	const interior = wrapped ? value.slice(1, -1) : value;
	if (interior.includes('"')) return { kind: "rejected", reason: "quoting" };
	if (!COOKIE_OCTETS_RE.test(interior)) return { kind: "rejected", reason: "grammar" };
	return { kind: "found", value };
};

export const extractCookie = (
	cookieHeader: string | undefined,
	name: string,
): CookieExtraction => {
	if (!cookieHeader) return { kind: "absent" };
	let skipped: CookieRejectReason | null = null;
	for (const raw of cookieHeader.split(";")) {
		const pair = trimOws(raw);
		const eq = pair.indexOf("=");
		if (eq === -1) continue;
		const cookieName = trimOws(pair.slice(0, eq));
		if (cookieName !== name) continue;
		const classified = classifyValue(pair.slice(eq + 1));
		if (classified.kind === "found") return { ...classified, skipped };
		skipped ??= classified.reason;
	}
	return skipped === null ? { kind: "absent" } : { kind: "rejected", reason: skipped };
};
