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

export interface SingleFlight<T> {
	run(key: string, fetch: () => Promise<T>): Promise<T>;
	_sizeForTesting(): number;
}

export const createSingleFlight = <T,>(): SingleFlight<T> => {
	const pending = new Map<string, Promise<T>>();
	return {
		run(key, fetch) {
			const existing = pending.get(key);
			if (existing !== undefined) return existing;
			const promise = (async () => {
				try {
					return await fetch();
				} finally {
					pending.delete(key);
				}
			})();
			pending.set(key, promise);
			return promise;
		},
		_sizeForTesting() {
			return pending.size;
		},
	};
};
