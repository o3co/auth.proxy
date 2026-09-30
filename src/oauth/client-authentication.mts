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
 * How one provider call authenticates the proxy's client: by
 * `client_secret_basic` or by `private_key_jwt`, whichever is configured.
 */

import { type ClientCredentials, clientSecretBasic } from "./client-secret-basic.mjs";
import {
	CLIENT_ASSERTION_TYPE,
	type ClientKey,
	signClientAssertion,
} from "./private-key-jwt.mjs";

/** A client that authenticates with `private_key_jwt`. */
export interface ClientKeyCredentials {
	clientId: string;
	clientKey: ClientKey;
	/** The provider's issuer identifier, the assertion's audience. */
	audience: string;
}

/** How the proxy authenticates as a client: a secret, or a key. */
export type ClientAuthentication = ClientCredentials | ClientKeyCredentials;

/** What one call carries to authenticate the client. */
export interface ClientAuthenticationParts {
	/** The `Authorization` header value, or `null` when the body carries the credential. */
	authorization: string | null;
	/** Form parameters the request body carries. */
	params: Record<string, string>;
	/**
	 * The credential as sent — the secret, or the assertion — for keeping it
	 * out of any provider text the proxy relays or logs.
	 */
	credential: string;
}

/**
 * What one call carries. A secret is sent as the Basic header; a key signs a
 * new assertion, sent in the body with the `client_id` and no `Authorization`
 * header, since the provider refuses a request that authenticates two ways.
 */
export const authenticateClient = async (
	auth: ClientAuthentication,
): Promise<ClientAuthenticationParts> => {
	if ("clientKey" in auth) {
		const assertion = await signClientAssertion({
			clientId: auth.clientId,
			audience: auth.audience,
			key: auth.clientKey,
		});
		return {
			authorization: null,
			params: {
				client_id: auth.clientId,
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: assertion,
			},
			credential: assertion,
		};
	}
	return { authorization: clientSecretBasic(auth), params: {}, credential: auth.clientSecret };
};
