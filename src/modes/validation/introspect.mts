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

export interface IntrospectionResult {
	active: boolean;
	[key: string]: unknown;
}

export class IntrospectHttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
	) {
		super(message);
		this.name = "IntrospectHttpError";
	}
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
	if (cacheTtlSec > 0 && cached && cached.expiresAt > now) {
		return cached.result;
	}

	const resp = await fetch(introspectUrl, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Authorization: authHeader,
			"x-request-id": requestId,
		},
		body: new URLSearchParams({ token }).toString(),
		signal: AbortSignal.timeout(timeoutMs),
	});

	if (!resp.ok) {
		throw new IntrospectHttpError(resp.status, `introspect returned ${resp.status}`);
	}

	let parsed: unknown;
	try {
		parsed = await resp.json();
	} catch {
		// Provider returned 200 with a non-JSON body — treat as provider bug, not auth decision.
		throw new IntrospectHttpError(502, "introspect returned 200 with a non-JSON body");
	}

	// RFC 7662 §2.2: `active` MUST be a boolean. Reject anything else so a provider
	// returning {"active":"false"} or a non-object cannot bypass auth via truthy coercion.
	if (
		parsed === null ||
		typeof parsed !== "object" ||
		Array.isArray(parsed) ||
		typeof (parsed as { active?: unknown }).active !== "boolean"
	) {
		throw new IntrospectHttpError(
			502,
			"introspect returned 200 but the body is not a valid introspection response (RFC 7662)",
		);
	}
	const data = parsed as IntrospectionResult;

	// This path authenticates Bearer tokens only; introspection does not prove
	// possession of a DPoP key or a client certificate for the inbound request.
	if (Object.hasOwn(data, "cnf") || (data.token_type !== undefined &&
		(typeof data.token_type !== "string" || data.token_type.toLowerCase() !== "bearer"))) {
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
	if (cacheTtlSec <= 0 || expiresAt <= receivedAt) {
		return data;
	}

	for (const [k, entry] of cache) {
		if (entry.expiresAt <= receivedAt) {
			cache.delete(k);
		}
	}
	if (cache.size >= cacheMaxEntries) {
		const oldestKey = cache.keys().next().value;
		if (oldestKey !== undefined) {
			cache.delete(oldestKey);
		}
	}
	cache.set(key, { result: data, expiresAt });
	return data;
};
