// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A provider call's timeout, fired by the test at a point it can name rather
 * than after a guessed number of milliseconds (#143). Test-only: nothing
 * outside a test imports it.
 *
 * The real `AbortSignal.timeout` is enough to show that a call whose provider
 * never answers ends: whenever the timer fires, the answer is the same. It is
 * not enough for anything that depends on where the call was when it fired.
 * On a loaded runner a short timer can fire before the request has reached
 * the fake, so the fake has no connection to watch close; and a timer meant
 * to fire while the body is read can fire before the headers have been
 * processed, which the clients answer differently.
 *
 * So this takes over `AbortSignal.timeout` — the clients' only cancellation —
 * and aborts every signal it handed out when the test says: from a
 * responder, once the fake holds the whole request, or once undici reports a
 * response's headers (the `undici:request:headers` diagnostics channel) and
 * one `setImmediate` has passed. By then `fetch` has resolved: what is left
 * between the headers and the resolution is promise reactions, which run
 * before any `setImmediate`. The abort reason is the `TimeoutError` a real
 * timeout carries, and the real `fetch` on the real socket does the rest.
 */

import { subscribe, unsubscribe } from "node:diagnostics_channel";
import { vi } from "vitest";

const HEADERS_CHANNEL = "undici:request:headers";

const timeoutReason = (): DOMException =>
	new DOMException("The operation was aborted due to timeout", "TimeoutError");

export interface ControlledTimeout {
	/** Times out every signal `AbortSignal.timeout` has handed out, and any it hands out later. */
	fire(): void;
	/** Resolves once `fire` has run. */
	readonly fired: Promise<void>;
	/** Puts `AbortSignal.timeout` back, and stops listening where it listened. */
	restore(): void;
}

/** Takes over `AbortSignal.timeout`: its signals time out when `fire` is called, and not before. */
export const controlledTimeout = (): ControlledTimeout => {
	const controllers: AbortController[] = [];
	let hasFired = false;
	const spy = vi.spyOn(AbortSignal, "timeout").mockImplementation(() => {
		if (hasFired) {
			return AbortSignal.abort(timeoutReason());
		}
		const controller = new AbortController();
		controllers.push(controller);
		return controller.signal;
	});
	let markFired: () => void = () => {};
	const fired = new Promise<void>((resolve) => {
		markFired = resolve;
	});
	return {
		fire() {
			hasFired = true;
			for (const controller of controllers) {
				controller.abort(timeoutReason());
			}
			markFired();
		},
		fired,
		restore() {
			spy.mockRestore();
		},
	};
};

/**
 * Makes the next provider call time out as soon as its response headers have
 * arrived: while the body is being read.
 */
export const timeoutAfterResponseHeaders = (): ControlledTimeout => {
	const timeout = controlledTimeout();
	const onHeaders = (): void => {
		setImmediate(() => timeout.fire());
	};
	subscribe(HEADERS_CHANNEL, onHeaders);
	return {
		fire: () => timeout.fire(),
		fired: timeout.fired,
		restore() {
			unsubscribe(HEADERS_CHANNEL, onHeaders);
			timeout.restore();
		},
	};
};
