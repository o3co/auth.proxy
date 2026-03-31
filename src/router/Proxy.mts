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
import crypto from 'node:crypto';
import axios from 'axios';
import type { Request, Response } from 'express';
import express from 'express';
import proxy from 'express-http-proxy';
import type { AppConfig } from '../../config/application.schema.mjs';
import logger from '../logger.mjs';

interface IntrospectionResult {
  active: boolean;
  [key: string]: unknown;
}

interface CacheEntry {
  result: IntrospectionResult;
  expiresAt: number;
}

// インメモリキャッシュ（トークンハッシュ → introspection 結果）
const cache = new Map<string, CacheEntry>();

const getCacheKey = (token: string): string =>
  crypto.createHash('sha256').update(token).digest('hex');

const generateRequestId = (): string => {
  const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
  const uid = crypto.randomUUID().replace(/-/g, '')
  return `${ts}_${uid}`
}

const introspect = async (
  token: string,
  introspectUrl: string,
  cacheTtlSec: number,
  requestId: string,
  authHeader: string,
): Promise<IntrospectionResult> => {
  const key = getCacheKey(token);
  const now = Date.now();

  const cached = cache.get(key);
  if (cached && cached.expiresAt > now) {
    return cached.result;
  }

  const { data } = await axios.post<IntrospectionResult>(
    introspectUrl,
    `token=${encodeURIComponent(token)}`,
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': authHeader, 'x-request-id': requestId } },
  );

  cache.set(key, { result: data, expiresAt: now + cacheTtlSec * 1000 });
  return data;
};

export const createRouter = ({ config }: { config: AppConfig }): express.Router => {
  const router = express.Router();
  const introspectUrl: string = config.auth.introspect.url;
  const cacheTtlSec: number = config.auth.introspect.cacheTtlSec;

  const clientCredentials = config.auth.client.clientId !== null
    ? `Basic ${Buffer.from(`${config.auth.client.clientId}:${config.auth.client.clientSecret}`).toString('base64')}`
    : null;

  router
    .use((req: Request, res: Response, next) => {
      const requestId = (req.headers['x-request-id'] as string | undefined) ?? generateRequestId()
      req.headers['x-request-id'] = requestId
      res.setHeader('x-request-id', requestId)
      logger.info({ 'x-request-id': requestId, method: req.method, path: req.path }, 'incoming request')
      return next()
    })
    .use(async (req: Request, res: Response, next) => {
      if (!req?.headers?.authorization) {
        return next();
      }

      const requestId = req.headers['x-request-id'] as string
      const [tokenType, token] = req.headers.authorization.split(' ');

      if (tokenType !== 'Bearer' || !token) {
        return res.status(400).json({ code: 400, message: 'Invalid Token Type' });
      }

      const authHeader = clientCredentials ?? `Bearer ${token}`;

      try {
        const result = await introspect(token, introspectUrl, cacheTtlSec, requestId, authHeader);
        if (!result.active) {
          return res.status(401).json({ code: 401, message: 'Invalid Token' });
        }
      } catch (e) {
        logger.error({ 'x-request-id': requestId, error: e }, 'introspect failed');
        if (axios.isAxiosError(e) && e.response?.status === 401) {
          return res.status(401).json({ code: 401, message: 'Invalid Token' });
        }
        return res.status(500).json({ code: 500, message: 'Internal Server Error' });
      }

      return next();
    })
    .use(
      proxy(config.upstream.baseURL, {
        limit: config.http.bodyLimitSize,
        proxyReqOptDecorator: async (proxyReqOpts, srcReq) => {
          if (srcReq?.headers?.authorization) {
            proxyReqOpts.headers.AUTHORIZATION = srcReq.headers.authorization;
          }
          if (srcReq?.headers?.['x-request-id']) {
            proxyReqOpts.headers['x-request-id'] = srcReq.headers['x-request-id'];
          }
          return proxyReqOpts;
        },
      }),
    );

  return router;
};
