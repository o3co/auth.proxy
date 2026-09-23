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
 * What to do with a provider response once the answer has been decided
 * without it. Both modes need this, and it belongs to neither, the way
 * `single-flight.mts` does not.
 */

/**
 * Releases a body nothing is going to read (#95 F28, F37).
 *
 * Every client in this proxy answers some statuses from the status alone — a
 * refusal, a redirect, an outage — and throws without touching the body.
 * What an unread body costs depends on its size, measured on Node 26 /
 * undici 8. Within undici's read-ahead buffer (64 KiB) it costs nothing:
 * undici has already read the whole body and returned the socket to the pool,
 * cancelled or not — and every realistic refusal body is tens of bytes.
 * Beyond that buffer an unread body holds its socket until the `Response` is
 * garbage-collected, and a provider sending large refusal bodies under load
 * accumulates held sockets for as long as the collector allows. Cancelling
 * bounds that: the socket is closed rather than returned to the pool, so the
 * next request connects afresh, but nothing accumulates.
 *
 * So this is defensive rather than a fix for anything a well-behaved provider
 * does, and it is cheap enough to be right to call anyway.
 *
 * A cancel that itself fails is swallowed. It is not the answer: a stream
 * that is already errored — the connection reset before anything read it —
 * rejects its own cancel with the stored error, and letting that propagate
 * would replace the refusal the caller is about to throw with a failure of
 * releasing a stream nobody wanted.
 */
export const discardBody = async (resp: Response): Promise<void> => {
	await resp.body?.cancel().catch(() => undefined);
};
