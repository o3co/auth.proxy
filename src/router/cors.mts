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
 * origin the pattern admits is granted, with credentials; any other is
 * granted nothing. Without a pattern the proxy does no CORS.
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
 */

import type { IncomingMessage } from "node:http";
import cors from "cors";
import type { RequestHandler } from "express";

/** The config field CORS reads. `AppConfig` satisfies it structurally. */
export interface CorsConfig {
	http: { cors: { origin: { pattern: string | null } } };
}

/** Whether the proxy answers CORS: a pattern is set, and not empty. */
const answersCors = (config: CorsConfig): boolean => Boolean(config.http.cors.origin.pattern);

/** The fields that grant an origin access to an answer, lower-cased. */
const GRANT_FIELDS: readonly string[] = ["access-control-allow-origin", "access-control-allow-credentials"];

/**
 * The CORS fields only the proxy sets on an answer: the grant while it
 * answers CORS, none otherwise. Other `Access-Control-*` fields are the
 * upstream's to send — `Access-Control-Expose-Headers` names its own fields,
 * and the proxy sets none.
 */
export const proxyOwnedCorsFields = (config: CorsConfig): readonly string[] =>
	answersCors(config) ? GRANT_FIELDS : [];

/** A CORS preflight, as the Fetch standard defines one. */
const isPreflight = (req: IncomingMessage): boolean =>
	req.method === "OPTIONS" &&
	req.headers.origin !== undefined &&
	req.headers["access-control-request-method"] !== undefined;

/** The CORS middleware, as the header of this file describes it. */
export const createCors = (config: CorsConfig): RequestHandler => {
	const { pattern } = config.http.cors.origin;
	if (!answersCors(config) || pattern === null) return (_req, _res, next) => next();
	const answer = cors({ origin: new RegExp(pattern), credentials: true });
	return (req, res, next) => {
		if (req.method === "OPTIONS" && !isPreflight(req)) return next();
		answer(req, res, next);
	};
};
