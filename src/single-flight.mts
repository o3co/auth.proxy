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
 * Request coalescing: `SingleFlight`, and its in-memory default. One flight
 * per key; every waiter shares the leader's result or rejection; the slot is
 * cleared in `finally`, settled either way — a fetcher that throws before it
 * returns a promise included — so the next call for the key starts a new
 * flight. Both modes coalesce with it, and it belongs to neither.
 */

export interface SingleFlightResult<T> {
	value: T;
	wasWaiter: boolean;
}

export interface SingleFlight<T> {
	run(key: string, fetch: () => Promise<T>): Promise<SingleFlightResult<T>>;
	_sizeForTesting(): number;
}

export const createSingleFlight = <T,>(): SingleFlight<T> => {
	const pending = new Map<string, Promise<T>>();
	return {
		async run(key, fetch) {
			const existing = pending.get(key);
			if (existing !== undefined) {
				const value = await existing;
				return { value, wasWaiter: true };
			}
			// Started here, before `run` yields, as a leader always has been. A
			// fetcher that throws synchronously becomes this flight's rejection:
			// inside an async wrapper its `finally` would run before the entry
			// was set, and the rejection would then be pinned under the key.
			let started: Promise<T>;
			try {
				started = Promise.resolve(fetch());
			} catch (err) {
				started = Promise.reject(err);
			}
			// The waiters await this promise, and `finally` settles it only after
			// the key is cleared, so none of them resumes into a stale entry.
			const promise = started.finally(() => {
				pending.delete(key);
			});
			pending.set(key, promise);
			const value = await promise;
			return { value, wasWaiter: false };
		},
		_sizeForTesting() {
			return pending.size;
		},
	};
};
