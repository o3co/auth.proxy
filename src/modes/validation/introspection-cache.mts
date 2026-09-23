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
import type { IntrospectionResult } from "./introspection-client.mjs";

/**
 * Where a validated introspection response is held until it expires (#95 F5).
 * Keyed by the digest of the token, never the token itself.
 *
 * An entry is served only while `expiresAt` is still ahead; a stale one is not
 * served and is swept on the next write, so a cache that is never written to
 * again keeps its dead entries and serves none of them.
 *
 * Two deliberate differences from the injection path's `TokenCache`, both of
 * them the behaviour this replaced: `get` does not delete the stale entry it
 * declines to serve, so the bound is enforced on write alone; and `set` does
 * not re-insert a key it already holds, so a refreshed entry keeps its
 * position and is evicted on its original age. Eviction is by insertion
 * rather than by use.
 *
 * Writing a key the map already holds evicts nothing: it cannot push the map
 * past its bound, and the fused function this replaced dropped an unrelated
 * live entry for it. That is a deliberate difference. It used to be reachable
 * through the composition — with no single-flight, two requests for one token
 * both missed, both called the provider and both wrote — and since #95 F6 it
 * is not: one flight means one write. The property is the cache's own either
 * way, and `introspection-cache.test.mts` is where it is pinned.
 */
export interface IntrospectionCache {
	get(key: string): IntrospectionResult | null;
	set(key: string, result: IntrospectionResult, expiresAt: number): void;
	clear(): void;
	size(): number;
}

export interface IntrospectionCacheOptions {
	/** `auth.validation.introspect.cacheMaxEntries`. */
	maxEntries: number;
}

interface CacheEntry {
	result: IntrospectionResult;
	expiresAt: number;
}

export const createIntrospectionCache = ({
	maxEntries,
}: IntrospectionCacheOptions): IntrospectionCache => {
	const entries = new Map<string, CacheEntry>();

	return {
		get(key) {
			const cached = entries.get(key);
			return cached !== undefined && cached.expiresAt > Date.now() ? cached.result : null;
		},

		set(key, result, expiresAt) {
			const now = Date.now();
			// Sweep first: the bound is on live entries, and dropping the oldest
			// insertion while expired ones sit in the map would evict a usable
			// entry to make room.
			for (const [k, entry] of entries) {
				if (entry.expiresAt <= now) {
					entries.delete(k);
				}
			}
			// Only a new key can push the map past its bound. Dropping the oldest
			// for a key already held would evict a live entry to make room for
			// one that needs none, and leave the map one under its bound.
			if (!entries.has(key) && entries.size >= maxEntries) {
				const oldestKey = entries.keys().next().value;
				if (oldestKey !== undefined) {
					entries.delete(oldestKey);
				}
			}
			entries.set(key, { result, expiresAt });
		},

		clear() {
			entries.clear();
		},

		size() {
			return entries.size;
		},
	};
};
