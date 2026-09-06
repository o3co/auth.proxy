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
	const config = { name: "proxy", level };
	return options?.destination ? pino(config, options.destination) : pino(config);
}

const logger: Logger = createProxyLogger();
export default logger;
