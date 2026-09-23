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
 * Where an issued token is held until it expires: the store behind the
 * session path's cache and, separately, the exchange path's. The flight table
 * the router pairs with each is `SingleFlight`, from `src/single-flight.mts`.
 *
 * `get` deletes an expired entry it declines to serve, and `set` re-inserts
 * the key, so a refreshed entry moves to the newest position. Validation's
 * `IntrospectionCache` has the same shape with different `get` / `set`
 * behaviour; the differences are recorded in its doc comment.
 */
export interface TokenCache {
	get(key: string): string | null;
	set(key: string, token: string, expiresAt: number): void;
	clear(): void;
	size(): number;
}

interface CacheEntry {
	token: string;
	expiresAt: number;
}

export const createTokenCache = ({ maxEntries }: { maxEntries: number }): TokenCache => {
	const entries = new Map<string, CacheEntry>();

	const sweepExpired = (now: number): void => {
		for (const [k, e] of entries) {
			if (e.expiresAt <= now) {
				entries.delete(k);
			}
		}
	};

	return {
		get(key) {
			const entry = entries.get(key);
			if (entry === undefined) return null;
			if (entry.expiresAt <= Date.now()) {
				entries.delete(key);
				return null;
			}
			return entry.token;
		},
		set(key, token, expiresAt) {
			const now = Date.now();
			// Overwrites move to end (Map insertion order) after delete.
			entries.delete(key);
			sweepExpired(now);
			if (entries.size >= maxEntries) {
				const oldest = entries.keys().next().value;
				if (oldest !== undefined) entries.delete(oldest);
			}
			entries.set(key, { token, expiresAt });
		},
		clear() {
			entries.clear();
		},
		size() {
			return entries.size;
		},
	};
};
