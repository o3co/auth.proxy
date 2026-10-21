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
 * CORS, which the proxy answers itself when `http.cors.origin.pattern` is set
 * and `app.mts` mounts under `http.pathPrefix`, ahead of the mode router. An
 * origin the pattern admits is granted, with credentials. Any other origin,
 * and a request without one, is granted nothing: the proxy sets no
 * `Access-Control-*` field on its answer, on a preflight or otherwise, only
 * `Vary: Origin`. Without a pattern the proxy does no CORS.
 *
 * Only a CORS preflight (Fetch: `OPTIONS` with `Origin` and
 * `Access-Control-Request-Method`) is answered here, `204`, before the mode
 * router: it carries no credential and is never forwarded or logged. Any
 * other `OPTIONS` is an ordinary request, which goes to the mode router
 * without CORS fields: an answer to `OPTIONS` is not cacheable
 * (RFC 9110 §9.3.7), so `Vary: Origin` says nothing on it, and a browser
 * cannot send one cross-origin, since the preflight's allowed methods leave
 * `OPTIONS` out. Every other method gets the grant's fields and goes on.
 *
 * While the proxy answers CORS, the grant on an answer is the proxy's alone:
 * the upstream stage drops the upstream's `Access-Control-Allow-Origin` and
 * `Access-Control-Allow-Credentials` (`proxyOwnedCorsFields`), whether or not
 * the proxy granted the origin, so the upstream cannot widen the pattern.
 *
 * When CORS is built, at boot, a pattern that likely admits more than its
 * author meant is warned about, once per concern, and still used
 * (`warnIfBroad`).
 */

import type { IncomingMessage } from "node:http";
import cors from "cors";
import type { RequestHandler } from "express";
import defaultLogger, { type Logger } from "../logger.mjs";

/** The config field CORS reads. `AppConfig` satisfies it structurally. */
export interface CorsConfig {
	http: { cors: { origin: { pattern: string | null } } };
}

/** The pattern the proxy answers CORS by, or null when it does no CORS: none is set, or an empty one. */
const corsPattern = (config: CorsConfig): string | null => config.http.cors.origin.pattern || null;

/** The fields that grant an origin access to an answer, lower-cased. */
const GRANT_FIELDS: readonly string[] = ["access-control-allow-origin", "access-control-allow-credentials"];

/**
 * The CORS fields only the proxy sets on an answer: the grant while it
 * answers CORS, none otherwise. Other `Access-Control-*` fields are the
 * upstream's to send — `Access-Control-Expose-Headers` names its own fields,
 * and the proxy sets none.
 */
export const proxyOwnedCorsFields = (config: CorsConfig): readonly string[] =>
	corsPattern(config) === null ? [] : GRANT_FIELDS;

/** A CORS preflight, as the Fetch standard defines one. */
const isPreflight = (req: IncomingMessage): boolean =>
	req.method === "OPTIONS" &&
	req.headers.origin !== undefined &&
	req.headers["access-control-request-method"] !== undefined;

/**
 * Origins no deployment serves (RFC 2606 reserves `.invalid`): a pattern that
 * admits one admits strangers.
 */
const FOREIGN_ORIGINS: readonly string[] = ["https://attacker.invalid", "http://attacker.invalid"];

/** A letter or a digit: what a host name's labels are made of. */
const NAME_CHARACTER = /[A-Za-z0-9]/;

/**
 * A pattern's top-level alternatives; whether a `.` that matches any
 * character stands right before a letter or a digit, where a host name's dot
 * was meant; and whether a `*`, `+` or `{…}` quantifier does, so the wildcard
 * runs into a host name with no dot to end it. Escapes and character classes
 * are stepped over for all three, and groups for the alternatives, so a `|`
 * inside a group does not count.
 */
const scanPattern = (source: string): { alternatives: string[]; hostDot: boolean; openWildcard: boolean } => {
	const alternatives: string[] = [];
	let start = 0;
	let depth = 0;
	let inClass = false;
	let hostDot = false;
	let openWildcard = false;
	const nameFollows = (at: number): boolean => NAME_CHARACTER.test(source[at] ?? "");
	for (let i = 0; i < source.length; i++) {
		const c = source[i];
		if (c === "\\") {
			i++;
		} else if (inClass) {
			if (c === "]") inClass = false;
		} else if (c === "[") {
			inClass = true;
		} else if (c === "(") {
			depth++;
		} else if (c === ")") {
			depth--;
		} else if (c === "|" && depth === 0) {
			alternatives.push(source.slice(start, i));
			start = i + 1;
		} else if (c === "." && nameFollows(i + 1)) {
			hostDot = true;
		} else if ((c === "*" || c === "+" || c === "}") && nameFollows(source[i + 1] === "?" ? i + 2 : i + 1)) {
			openWildcard = true;
		}
	}
	alternatives.push(source.slice(start));
	return { alternatives, hostDot, openWildcard };
};

/** Starts with `^` and ends with a `$` that is not escaped. */
const isAnchored = (alternative: string): boolean =>
	alternative.startsWith("^") && /(?:^|[^\\])(?:\\\\)*\$$/.test(alternative);

/**
 * Warns, once per concern, about a pattern that likely admits origins its
 * author did not mean to grant credentialed reads to: one not anchored as
 * `^…$` on every top-level alternative (`https://app\.example` also admits
 * `https://app.example.evil.net`), one that admits `null` (what a sandboxed
 * iframe or a redirected request sends, from any site), one that admits an
 * origin no deployment serves, one with a host name's dot left unescaped
 * (`app.example` also admits `appxexample`), and one whose wildcard runs into
 * a host name (`.*example\.com` also admits `evilexample.com`). A warning,
 * not a refusal: a syntactic check misses some broad patterns and flags some
 * narrow ones (an alternation wrapped in a group).
 */
const warnIfBroad = (pattern: string, origin: RegExp, logger: Logger): void => {
	const { alternatives, hostDot, openWildcard } = scanPattern(pattern);
	if (!alternatives.every(isAnchored)) {
		logger.warn(
			{ event: "cors.origin_pattern_unanchored", pattern },
			"http.cors.origin.pattern is not anchored as ^…$ on every alternative: it also admits any origin that merely contains a match, with credentials",
		);
	}
	if (origin.test("null")) {
		logger.warn(
			{ event: "cors.origin_pattern_admits_null", pattern },
			"http.cors.origin.pattern admits the origin null, which a sandboxed iframe or a redirected request sends from any site: it is granted credentialed reads",
		);
	}
	const foreign = FOREIGN_ORIGINS.filter((candidate) => origin.test(candidate));
	if (foreign.length > 0) {
		logger.warn(
			{ event: "cors.origin_pattern_admits_foreign_origin", pattern, origins: foreign },
			"http.cors.origin.pattern admits an origin no deployment serves: it likely admits any origin, with credentials",
		);
	}
	if (hostDot) {
		logger.warn(
			{ event: "cors.origin_pattern_unescaped_dot", pattern },
			"http.cors.origin.pattern has an unescaped . before a host name character, which matches any character: escape it as \\.",
		);
	}
	if (openWildcard) {
		logger.warn(
			{ event: "cors.origin_pattern_unbounded_wildcard", pattern },
			"http.cors.origin.pattern has a wildcard that runs straight into a host name, so it also admits names that merely end the same way: end the wildcard at a dot, as in [^.]+\\.example\\.com",
		);
	}
};

/** What `createCors` takes besides the config. */
export interface CorsDeps {
	/** Where the boot-time warnings go; the process logger by default. */
	logger?: Logger;
}

/** The CORS middleware, as the header of this file describes it. */
export const createCors = (config: CorsConfig, { logger = defaultLogger }: CorsDeps = {}): RequestHandler => {
	const pattern = corsPattern(config);
	if (pattern === null) return (_req, _res, next) => next();
	const origin = new RegExp(pattern);
	warnIfBroad(pattern, origin, logger);
	const granted: cors.CorsOptions = { origin, credentials: true };
	// `cors` would still send `Access-Control-Allow-Credentials` and, on a
	// preflight, the allowed methods and headers to an origin it refuses; empty
	// lists and no credentials leave it only `Vary: Origin` and the `204`.
	const refused: cors.CorsOptions = { origin, credentials: false, methods: [], allowedHeaders: [] };
	const answer = cors((req, done) => {
		const requestOrigin = req.headers.origin;
		done(null, requestOrigin !== undefined && origin.test(requestOrigin) ? granted : refused);
	});
	return (req, res, next) => {
		if (req.method === "OPTIONS" && !isPreflight(req)) return next();
		answer(req, res, next);
	};
};
