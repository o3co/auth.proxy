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

import { readBoundedJsonObject } from "../../response-body.mjs";

/**
 * What every call to the provider's token endpoint needs. The session grant,
 * the jwt-bearer exchange and the exchange handler all use it; it belongs to
 * none of them, the way `provider-error.mts` belongs to none of them.
 */

/** The token endpoint on a provider origin. */
export const buildTokenUrl = (providerOrigin: string): string => {
	// providerOrigin is validated as origin-only by the Zod schema, so the
	// absolute path replaces nothing an operator meant to keep.
	return new URL("/oauth/token", providerOrigin).toString();
};

/**
 * How much of a token response is read before giving up on it. It is a memory
 * bound, not a validity check.
 *
 * Four times the error path's bound: an error body carries a code and a
 * sentence, while a token response can carry an `id_token` with a full claim
 * set beside the access and refresh tokens. A large token response is
 * single-digit kilobytes, so only a provider streaming something that is not a
 * token response reaches the bound. The headroom is deliberate: the issued
 * token goes out in an upstream `Authorization` header, where typical limits
 * are 8-16 KB, so a response anywhere near this bound is unusable downstream
 * anyway.
 */
export const MAX_TOKEN_BODY_BYTES = 64 * 1024;

/**
 * A response body as an object, or `null` when it is not one — empty, not
 * JSON, JSON that is not an object (arrays included), or larger than
 * {@link MAX_TOKEN_BODY_BYTES}. Never throws: a provider that answers with
 * HTML, cuts the body short, or does not stop sending is answering badly
 * rather than saying something the caller must parse.
 *
 * The reading is `readBoundedJsonObject`'s, with this bound in place of the
 * error path's. A caller cannot tell an over-bound body from an unparseable
 * one — both are `null`, and a provider that reaches either is refused the
 * same way.
 */
export const parseJsonBody = async (resp: Response): Promise<Record<string, unknown> | null> =>
	readBoundedJsonObject(resp, MAX_TOKEN_BODY_BYTES);
