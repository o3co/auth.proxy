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

export const extractCookie = (
	cookieHeader: string | undefined,
	name: string,
): string | null => {
	if (!cookieHeader) return null;
	const parts = cookieHeader.split(";");
	for (const raw of parts) {
		const trimmed = raw.trim();
		const eq = trimmed.indexOf("=");
		if (eq === -1) continue;
		const cookieName = trimmed.slice(0, eq).trim();
		if (cookieName !== name) continue;
		const value = trimmed.slice(eq + 1).trim();
		return value === "" ? null : value;
	}
	return null;
};
