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

export interface ClientCredentials {
	clientId: string;
	clientSecret: string;
}

/**
 * The `Authorization` header value for `client_secret_basic` client
 * authentication at the provider.
 *
 * RFC 6749 section 2.3.1 has both halves `application/x-www-form-urlencoded`
 * encoded BEFORE they are joined with ":" and base64'd. Without that a ":"
 * inside either half re-splits the credential in the wrong place and the
 * provider reads a different pair than the one configured. The provider decodes
 * with the matching form-urlencoded decoder, so every byte round-trips;
 * `encodeURIComponent` writes a space as `%20`, which that decoder reads back as
 * a space just as it would `+`.
 */
export const clientSecretBasic = ({ clientId, clientSecret }: ClientCredentials): string =>
	`Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64")}`;
