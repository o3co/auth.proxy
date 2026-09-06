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

import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import cors from "cors";
import express from "express";
import { type AppConfig, AppConfigSchema } from "../config/application.schema.mjs";
import { resolveRouter } from "./app-internal.mjs";
import logger from "./logger.mjs";
import * as routers from "./router/index.mjs";
import { installGracefulShutdown } from "./shutdown.mjs";

const config: AppConfig = validate(
	parseFile(new URL("../config/application.conf", import.meta.url).pathname),
	AppConfigSchema,
);

const app = express();

const corsOrigin = config.http.cors.origin.pattern
	? new RegExp(config.http.cors.origin.pattern)
	: false;

const server = app
	.use(routers.Healthcheck.createRouter())
	.use(
		cors({
			origin: corsOrigin,
			credentials: true,
		}),
	)
	.use(config.http.pathPrefix, resolveRouter(config))
	.listen(config.http.port, config.http.hostname, () => {
		logger.info(`Server ready at http://${config.http.hostname}:${config.http.port}`);
	});

installGracefulShutdown(server, { logger });
