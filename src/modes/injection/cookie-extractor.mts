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
 * treated as missing here rather than forwarded.
 *
 * DQUOTE decision: the optional surrounding DQUOTE pair is accepted and the
 * quotes are preserved on the outbound header. RFC 6265 section 5.2 has user
 * agents store the cookie-value opaquely (the quotes are not stripped), so a
 * browser echoes back exactly the bytes the provider chose in `Set-Cookie`. The
 * proxy is a relay for the provider's own cookie; handing back the same bytes
 * and letting the provider's parser decide what the quotes mean is the faithful
 * choice, and it is still safe because the interior is restricted to
 * cookie-octet and cannot carry a delimiter. A lone or interior DQUOTE is
 * outside the grammar and rejected. An empty quoted value (`""`) is treated as
 * missing just like an empty bare value: there is no session identifier to
 * exchange.
 */
const COOKIE_VALUE_RE =
	/^(?:[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*|"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*")$/;

export const extractCookie = (
	cookieHeader: string | undefined,
	name: string,
): string | null => {
	if (!cookieHeader) return null;
	const parts = cookieHeader.split(";");
	for (const raw of parts) {
		const trimmed = raw.trim();
		const eq = trimmed.indexOf("=");
		if (eq === -1) continue;
		const cookieName = trimmed.slice(0, eq).trim();
		if (cookieName !== name) continue;
		const value = trimmed.slice(eq + 1).trim();
		if (!COOKIE_VALUE_RE.test(value)) return null;
		return value === "" || value === '""' ? null : value;
	}
	return null;
};
