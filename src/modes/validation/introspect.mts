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
import axios from "axios";

export interface IntrospectionResult {
	active: boolean;
	[key: string]: unknown;
}

interface CacheEntry {
	result: IntrospectionResult;
	expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

export const clearCache = (): void => {
	cache.clear();
};

export interface ClientCredentials {
	clientId: string;
	clientSecret: string;
}

const pctEncode = (s: string): string => encodeURIComponent(s);

export const buildAuthHeader = (credentials: ClientCredentials | null, token: string): string =>
	credentials !== null
		? `Basic ${Buffer.from(`${pctEncode(credentials.clientId)}:${pctEncode(credentials.clientSecret)}`).toString("base64")}`
		: `Bearer ${token}`;

const getCacheKey = (token: string): string =>
	crypto.createHash("sha256").update(token).digest("hex");

export const introspect = async (
	token: string,
	introspectUrl: string,
	cacheTtlSec: number,
	requestId: string,
	authHeader: string,
	cacheMaxEntries = 10000,
	timeoutMs = 5000,
): Promise<IntrospectionResult> => {
	const key = getCacheKey(token);
	const now = Date.now();

	const cached = cache.get(key);
	if (cached && cached.expiresAt > now) {
		return cached.result;
	}

	const { data } = await axios.post<IntrospectionResult>(
		introspectUrl,
		new URLSearchParams({ token }).toString(),
		{
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: authHeader,
				"x-request-id": requestId,
			},
			timeout: timeoutMs,
		},
	);

	for (const [k, entry] of cache) {
		if (entry.expiresAt <= now) {
			cache.delete(k);
		}
	}
	if (cache.size >= cacheMaxEntries) {
		const oldestKey = cache.keys().next().value;
		if (oldestKey !== undefined) {
			cache.delete(oldestKey);
		}
	}
	cache.set(key, { result: data, expiresAt: now + cacheTtlSec * 1000 });
	return data;
};
