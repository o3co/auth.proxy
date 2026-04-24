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
