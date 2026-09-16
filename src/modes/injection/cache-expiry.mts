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
 * The absolute instant (epoch ms) a cached token stops being injected, or
 * `null` when it must not be cached at all:
 *
 *   min(requestedAt + ttl, requestedAt + expires_in, notAfter) - safety margin
 *
 * cached only when that is after `now`.
 *
 * The relative lifetimes are anchored at `requestedAt`, the instant captured
 * immediately BEFORE the token request was sent — never at the response.
 * `expires_in` counts from issuance, and issuance cannot precede the request,
 * so the request is the latest instant the token's real expiry can be measured
 * from without overshooting it. Anchoring at the response would let a slow
 * provider push the entry past the token's expiry by the whole response time,
 * and the proxy would go on injecting an expired token. `notAfter` is already
 * absolute (an assertion's `exp`) and stays where it is.
 */
export const computeCacheExpiresAt = ({
	requestedAt,
	now,
	ttlSeconds,
	safetyMarginSeconds,
	expiresIn,
	notAfter = null,
}: {
	requestedAt: number;
	now: number;
	ttlSeconds: number;
	safetyMarginSeconds: number;
	expiresIn: number | null;
	notAfter?: number | null;
}): number | null => {
	const expiresAt =
		Math.min(
			requestedAt + ttlSeconds * 1000,
			expiresIn === null ? Number.POSITIVE_INFINITY : requestedAt + expiresIn * 1000,
			notAfter ?? Number.POSITIVE_INFINITY,
		) -
		safetyMarginSeconds * 1000;
	return expiresAt > now ? expiresAt : null;
};
