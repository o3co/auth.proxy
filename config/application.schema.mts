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
import { z } from "zod";

/**
 * RFC 6265 section 4.1.1 `cookie-name = token`, with RFC 9110 section 5.6.2
 *
 *   token = 1*tchar
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 *
 * The configured name is interpolated verbatim into the outbound `Cookie` header
 * of the session grant call (session-grant-client.mts). A separator or
 * whitespace in it (`"sid "`, `"a=b"`) would malform that header, or smuggle a
 * second cookie-pair, on every request, so it is refused at boot (#75).
 */
const COOKIE_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

export const AppConfigSchema = z.object({
	http: z.object({
		hostname: z.string().default("0.0.0.0"),
		port: z.coerce.number().default(80),
		pathPrefix: z.string().default("/"),
		bodyLimitSize: z.string().default("10mb"),
		cors: z.object({
			origin: z.object({
				pattern: z.string().nullable().default(null),
			}),
		}),
	}),
	auth: z.discriminatedUnion("mode", [
		z.object({
			mode: z.literal("validation"),
			validation: z.object({
				client: z
					.object({
						clientId: z
							.string()
							.nullable()
							.default(null)
							.transform((v) => (v === "" ? null : v)),
						clientSecret: z
							.string()
							.nullable()
							.default(null)
							.transform((v) => (v === "" ? null : v)),
					})
					.refine(
						(c) => (c.clientId === null) === (c.clientSecret === null),
						{
							message:
								"auth.validation.client.clientId and auth.validation.client.clientSecret must both be set or both be unset",
						},
					),
				introspect: z.object({
					url: z.string(),
					cacheTtlSec: z.coerce.number().default(30),
					cacheMaxEntries: z.coerce.number().int().positive().default(10000),
					timeoutMs: z.coerce.number().int().positive().default(5000),
				}),
			}),
		}),
		z.object({
			mode: z.literal("injection"),
			injection: z.object({
				providerOrigin: z
					.string()
					.url()
					.refine(
						(u) => {
							const parsed = new URL(u);
							return (
								(parsed.protocol === "http:" || parsed.protocol === "https:") &&
								parsed.username === "" &&
								parsed.password === "" &&
								(parsed.pathname === "" || parsed.pathname === "/") &&
								!parsed.search &&
								!parsed.hash
							);
						},
						{
							message:
								"providerOrigin must be an http(s) origin only (scheme://host[:port]), no userinfo/path/query/fragment",
						},
					),
				clientId: z.string().min(1),
				scope: z.string().min(1),
				sessionCookieName: z.string().regex(COOKIE_NAME_RE, {
					message:
						"auth.injection.sessionCookieName must be an RFC 6265 cookie-name (RFC 9110 token: one or more of !#$%&'*+-.^_`|~ DIGIT ALPHA; no whitespace, '=' or other separators)",
				}),
				tokenCache: z
					.object({
						ttlSeconds: z.coerce.number().int().positive().default(60),
						maxEntries: z.coerce.number().int().positive().default(10000),
						safetyMarginSeconds: z.coerce.number().int().nonnegative().default(5),
					})
					.refine(
						(tc) => tc.safetyMarginSeconds < tc.ttlSeconds,
						{
							message:
								"auth.injection.tokenCache.safetyMarginSeconds must be less than auth.injection.tokenCache.ttlSeconds",
						},
					),
				timeoutMs: z.coerce.number().int().positive().default(5000),
			}),
		}),
	]),
	upstream: z.object({
		baseURL: z.string(),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
