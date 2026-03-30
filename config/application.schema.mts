/*
 * Copyright 2026 1o1 Inc.
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
import { z } from "zod";

export const AppConfigSchema = z.object({
	http: z.object({
		hostname: z.string().default("0.0.0.0"),
		port: z.coerce.number().default(80),
		pathPrefix: z.string().default("/"),
	}),
	introspect: z.object({
		url: z.string(),
		cacheTtlSec: z.coerce.number().default(30),
	}),
	endpoint: z.object({
		baseURL: z.string(),
	}),
	proxy: z.object({
		bodyLimitSize: z.string().default("10mb"),
	}),
	cors: z.object({
		origin: z.object({
			pattern: z.string().nullable().default(null),
		}),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
