##############################################
FROM node:24-alpine AS base

RUN npm install -g corepack --force

ENV HOME=/home/node
ENV NODE_ENV=production

WORKDIR ${HOME}

COPY package.json pnpm-lock.yaml .npmrc* ./

RUN corepack enable && corepack prepare --activate

##############################################
FROM base AS builder

RUN pnpm install --frozen-lockfile

COPY config ./config
COPY src ./src
COPY tsconfig.json tsconfig.build.json ./

# tsconfig.build.json leaves the tests out of dist/.
RUN pnpm run build

##############################################
FROM builder AS pre

RUN pnpm prune --prod

##############################################
# The runtime starts from the plain Node image, not from `base`: it runs node
# itself, so it carries neither corepack nor pnpm, nor the `.npmrc` the build
# installed with. The files stay owned by root and are only read, so the
# process cannot rewrite its own code or configuration, and the image can run
# with a read-only root filesystem.
FROM node:24-alpine AS runtime

ENV HOME=/home/node
ENV NODE_ENV=production

WORKDIR ${HOME}

COPY --from=pre /home/node/package.json ./
COPY --from=pre /home/node/node_modules ./node_modules/
COPY --from=pre /home/node/dist ./dist/
# The entry point reads the configuration next to its compiled schema,
# dist/config/application.conf; tsc emits only the schema there.
COPY --from=pre /home/node/config/application.conf ./dist/config/application.conf

USER node

# A port above 1023, which a non-root process can bind without a capability.
# Not 3000: the defaults of UPSTREAM_BASEURL and INTROSPECT_URL name
# localhost:3000, and a container that kept them would proxy to itself.
ENV HTTP_PORT=8080
EXPOSE 8080

# Liveness on the root path, outside HTTP_PATH_PREFIX. Shell form, so the
# probe follows an operator's HTTP_PORT. busybox wget ships in the base image;
# `-Y off` keeps an http_proxy in the environment from taking the probe
# elsewhere. 127.0.0.1 reaches the default listen address, 0.0.0.0.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=1s --retries=3 \
  CMD wget -q -Y off -O /dev/null "http://127.0.0.1:${HTTP_PORT}/_healthcheck" || exit 1

# node is PID 1 and receives SIGTERM itself, which starts the graceful
# shutdown. No package manager sits in between to resolve at start or to add
# its own lines to the output.
CMD ["node", "dist/src/app.mjs"]

##############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
