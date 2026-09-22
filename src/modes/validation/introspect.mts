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
import crypto from "node:crypto";
import type { Introspector } from "./decision.mjs";
import type { IntrospectionCache } from "./introspection-cache.mjs";
import {
	IntrospectHttpError,
	type IntrospectionClient,
	type IntrospectionResult,
} from "./introspection-client.mjs";

/**
 * The cache key: SHA-256 of the token, so the map never holds a live
 * credential — the same reason the injection path hashes the cookie value.
 */
const cacheKey = (token: string): string =>
	crypto.createHash("sha256").update(token).digest("hex");

export interface IntrospectorConfig {
	client: IntrospectionClient;
	cache: IntrospectionCache;
	/** `auth.validation.introspect.cacheTtlSec`; `0` or less disables the cache on both sides. */
	cacheTtlSec: number;
}

/**
 * What this proxy accepts as a live token, on top of what RFC 7662 makes the
 * provider say (#95 F5) — and what may be cached.
 *
 * The client answers what the provider said, validated as a response. This is
 * the reading of it: a response carrying possession evidence this path cannot
 * check is refused, a token that expired while the call was in flight is
 * refused, and a malformed `exp` is the provider's bug rather than an answer.
 * None of those refusals is cached: a plain `active: false` from the provider
 * is a statement about the token and is held for the same bound as a positive
 * one, but "we refused to read this response" is not.
 *
 * `cacheTtlSec` is the one knob: at `0` or less nothing is read from the cache
 * and nothing is written to it.
 */
export const createIntrospector = ({
	client,
	cache,
	cacheTtlSec,
}: IntrospectorConfig): Introspector => {
	const caching = cacheTtlSec > 0;

	return async (token: string, requestId: string): Promise<IntrospectionResult> => {
		const key = cacheKey(token);
		// Captured before the call goes out: the entry's lifetime is measured
		// from when this request asked, not from when the provider answered.
		const now = Date.now();

		if (caching) {
			const cached = cache.get(key);
			if (cached !== null) {
				return cached;
			}
		}

		const data = await client.introspect(token, requestId);

		// This path authenticates Bearer tokens only; introspection does not prove
		// possession of a DPoP key or a client certificate for the inbound request.
		if (
			Object.hasOwn(data, "cnf") ||
			(data.token_type !== undefined &&
				(typeof data.token_type !== "string" || data.token_type.toLowerCase() !== "bearer"))
		) {
			return { active: false };
		}
		if (Object.hasOwn(data, "exp") && (typeof data.exp !== "number" || !Number.isFinite(data.exp))) {
			throw new IntrospectHttpError(502, "introspect returned an invalid exp");
		}
		const tokenExpiresAt = typeof data.exp === "number" ? data.exp * 1000 : Infinity;
		const receivedAt = Date.now();
		// A token can expire while fetch/body parsing is in flight. Refuse it on
		// this request too, even if the provider returned active: true.
		if (tokenExpiresAt <= receivedAt) {
			return { active: false };
		}

		const expiresAt = Math.min(now + cacheTtlSec * 1000, tokenExpiresAt);
		if (!caching || expiresAt <= receivedAt) {
			return data;
		}
		cache.set(key, data, expiresAt);
		return data;
	};
};
