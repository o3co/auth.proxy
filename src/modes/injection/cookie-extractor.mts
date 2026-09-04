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
 * RFC 6265 section 4.1.1:
 *
 *   cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 *   cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 *                  ; US-ASCII characters excluding CTLs, whitespace,
 *                  ; DQUOTE, comma, semicolon, and backslash
 *
 * Why the proxy enforces this itself (#23): the extracted value is interpolated
 * verbatim into the outbound `Cookie` header of the session grant call (see
 * session-grant-client.mts). A value carrying a delimiter (`;`, `,`, whitespace),
 * a CTL, or a non-ASCII byte could malform that header or smuggle a second
 * cookie-pair into the provider request, and the runtime does not catch it:
 * Node's `fetch` (undici) rejects only CR / LF / NUL and code points above 0xFF,
 * and `http.validateHeaderValue` rejects only CTLs and DEL. Everything else in
 * the excluded set passes straight through, so a non-conforming value is
 * refused here rather than forwarded.
 *
 * DQUOTE decision: the optional surrounding DQUOTE pair is accepted and the
 * quotes are preserved on the outbound header. RFC 6265 section 5.2 has user
 * agents store the cookie-value opaquely (the quotes are not stripped), so a
 * browser echoes back exactly the bytes the provider chose in `Set-Cookie`. The
 * proxy is a relay for the provider's own cookie; handing back the same bytes
 * and letting the provider's parser decide what the quotes mean is the faithful
 * choice, and it is still safe because the interior is restricted to
 * cookie-octet and cannot carry a delimiter. A lone or interior DQUOTE is
 * outside the grammar and rejected. An empty quoted value (`""`) is rejected
 * just like an empty bare value: there is no session identifier to exchange.
 *
 * Whitespace decision (#23 review): RFC 6265 section 4.2.1 is
 *
 *   cookie-string = cookie-pair *( ";" SP cookie-pair )
 *
 * so the only whitespace the grammar allows is the SP after ";" (plus OWS at the
 * ends of the header). Whitespace touching the ";" separator or the header ends
 * is therefore separator slack: the cookie-pair token is trimmed of OWS so that
 * `a=1;  sid=abc ; b=2` still yields `abc`, and the name is trimmed as well
 * because it is only compared, never forwarded. The value is taken verbatim
 * after "=": whitespace there touches no separator, so it is part of the value,
 * fails the cookie-octet check, and `sid= abc` is rejected instead of being
 * normalised into a valid outbound value. Only SP / HTAB count as slack (RFC 7230
 * OWS); String.prototype.trim would also strip a latin-1 NBSP and other Unicode
 * whitespace, which must stay in the value and be rejected as non-ASCII.
 *
 * Result shape (#73): the caller needs to tell a header that simply lacks the
 * cookie (`absent`, an expected anonymous request) from one that carries the
 * cookie in a form the proxy refuses to forward (`rejected`, worth an operator's
 * attention). The rejected variant carries only a bounded reason class so it can
 * be logged without ever leaking the value bytes:
 *
 *   - `empty`    the value is `` or `""` — nothing to exchange
 *   - `quoting`  a DQUOTE anywhere other than as exactly one surrounding pair
 *   - `grammar`  a character outside cookie-octet in the (unwrapped) value
 */
const COOKIE_OCTETS_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

const trimOws = (s: string): string => s.replace(/^[ \t]+|[ \t]+$/g, "");

export type CookieRejectReason = "empty" | "quoting" | "grammar";

export type CookieExtraction =
	| { kind: "absent" }
	| { kind: "rejected"; reason: CookieRejectReason }
	| { kind: "found"; value: string };

const classifyValue = (value: string): CookieExtraction => {
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
	const parts = cookieHeader.split(";");
	for (const raw of parts) {
		const pair = trimOws(raw);
		const eq = pair.indexOf("=");
		if (eq === -1) continue;
		const cookieName = trimOws(pair.slice(0, eq));
		if (cookieName !== name) continue;
		return classifyValue(pair.slice(eq + 1));
	}
	return { kind: "absent" };
};
