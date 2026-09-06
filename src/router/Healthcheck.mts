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
import express from "express";

/** Liveness only: the process is up and the event loop is turning. */
const HEALTHCHECK_PATH = "/_healthcheck";

/**
 * Liveness probe.
 *
 * This says nothing about the provider being reachable — a proxy that answers
 * here can still fail every introspection. Readiness against upstreams would
 * be a separate route with a separate contract.
 */
export const createRouter = (): express.Router => {
	const router = express.Router();
	router.get(HEALTHCHECK_PATH, (_req, res) => {
		res.status(200).json({ status: "ok" });
	});
	return router;
};
