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
import pino, { type DestinationStream } from "pino";

/**
 * The logging surface the proxy uses.
 *
 * Kept as a structural interface rather than pino's own type so a caller can
 * pass a double, and so swapping the backend does not ripple into every
 * module that only ever calls `.warn`.
 */
export interface Logger {
	info(...args: [string] | [Record<string, unknown>, string]): void;
	warn(...args: [string] | [Record<string, unknown>, string]): void;
	error(...args: [string] | [Record<string, unknown>, string]): void;
	debug(...args: [string] | [Record<string, unknown>, string]): void;
}

/**
 * The fields of an Error that reach a log line (#95 F48). An allowlist, not
 * pino's `errWithCause`: that copies every enumerable property, and some
 * errors carry bytes nobody chose to log — undici's `HTTPParserError.data` is
 * the unparsed rest of the provider's response, which may echo the token the
 * proxy just sent. What is kept is what diagnoses a failed call: the class, the
 * message, the stack, the socket's `code` / `errno` / `syscall`, and the
 * provider's `status` with the bundled clients' classification.
 */
const LOGGED_ERROR_FIELDS = ["code", "errno", "syscall", "status", "refusedCredential"] as const;

/** Deep enough for wrapper → undici → socket, with room; bounded against a cycle. */
const MAX_CAUSE_DEPTH = 5;

/**
 * `scheme://user:pass@host` → `scheme://***@host`. undici puts the request URL
 * in some rejection messages, and the configured introspection URL is only a
 * string to the schema, so it may carry userinfo.
 */
const redactUrlCredentials = (text: string): string =>
	text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]*@/gi, "$1***@");

/**
 * The serialiser for the `error` key. A non-Error passes through as it is —
 * injection logs a string there.
 */
export const serializeLoggedError = (value: unknown, depth = 0): unknown => {
	if (!(value instanceof Error)) return value;
	const out: Record<string, unknown> = {
		type: value.name,
		message: redactUrlCredentials(value.message),
	};
	if (typeof value.stack === "string") out.stack = redactUrlCredentials(value.stack);
	const fields = value as unknown as Record<string, unknown>;
	for (const key of LOGGED_ERROR_FIELDS) {
		const field = fields[key];
		if (typeof field === "string" || typeof field === "number") {
			out[key] = typeof field === "string" ? redactUrlCredentials(field) : field;
		}
	}
	if (value.cause !== undefined && depth < MAX_CAUSE_DEPTH) {
		out.cause =
			value.cause instanceof Error ? serializeLoggedError(value.cause, depth + 1) : "[non-Error cause]";
	}
	return out;
};

export interface ProxyLoggerOptions {
	/** Defaults to `LOG_LEVEL`, then `info`. */
	level?: string;
	/** Test seam; production writes to stdout. */
	destination?: DestinationStream;
}

/**
 * Newline-delimited JSON on stdout — the shape a log aggregator ingests
 * without a parser.
 *
 * The level is read here rather than at module load so a test can set
 * `LOG_LEVEL` without re-importing the module.
 */
export function createProxyLogger(options?: ProxyLoggerOptions): pino.Logger {
	const level = options?.level ?? process.env.LOG_LEVEL ?? "info";
	const config = {
		name: "proxy",
		level,
		// pino serialises an Error only under `err`; the validation path logs
		// its failures under `error`, where an Error became `{}` plus whatever
		// fields it declared — no message, no stack, no cause (#95 F48). Not
		// pino's own serialiser: see `LOGGED_ERROR_FIELDS`.
		serializers: { error: (value: unknown) => serializeLoggedError(value) },
	};
	return options?.destination ? pino(config, options.destination) : pino(config);
}

const logger: Logger = createProxyLogger();
export default logger;
