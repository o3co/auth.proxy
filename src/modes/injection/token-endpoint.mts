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
 * What every call to the provider's token endpoint needs, wherever it is made
 * from (#95 F19). The session grant, the jwt-bearer exchange and the exchange
 * handler each had to reach into one of the others for these; they belong to
 * none of them, the way `provider-error.mts` belongs to none of them.
 */

/** The token endpoint on a provider origin. */
export const buildTokenUrl = (providerOrigin: string): string => {
	// providerOrigin is validated as origin-only by the Zod schema, so the
	// absolute path replaces nothing an operator meant to keep.
	return new URL("/oauth/token", providerOrigin).toString();
};

/**
 * A response body as an object, or `null` when it is not one — empty, not
 * JSON, or JSON that is not an object. Never throws: a provider that answers
 * an error with HTML, or cuts the body short, is answering badly rather than
 * saying something the caller must parse.
 *
 * `typeof === "object"` is the whole test, so a JSON array comes back as it
 * is. No provider sends one for an error body, and a caller reading `error`
 * off it gets `undefined` and treats the body as unusable.
 */
export const parseJsonBody = async (resp: Response): Promise<Record<string, unknown> | null> => {
	try {
		const text = await resp.text();
		// A fast path, not what makes this total: `JSON.parse("")` throws and the
		// `catch` below answers `null` for it just the same.
		if (text.length === 0) return null;
		const parsed = JSON.parse(text);
		return typeof parsed === "object" && parsed !== null
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
};
