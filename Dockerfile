##############################################
FROM node:24-alpine AS base

RUN npm install -g corepack --force

ENV HOME=/home/node
ENV NODE_ENV=production

WORKDIR ${HOME}

ADD package.json .npmrc* ./

RUN corepack enable

##############################################
FROM base AS builder

RUN pnpm install

ADD config ./config
ADD src ./src
ADD tsconfig.json ./

RUN pnpm run build

##############################################
FROM builder AS pre 

RUN pnpm prune --prod

##############################################
FROM base AS runtime

COPY --from=pre /home/node/node_modules ./node_modules/
COPY --from=pre /home/node/dist ./dist/
COPY --from=pre /home/node/config ./config/
RUN ln -s /home/node/dist /home/node/src \
 && cp /home/node/config/application.conf /home/node/dist/config/application.conf

CMD ["pnpm", "run", "start"]

##############################################
FROM builder AS develop

CMD ["pnpm", "run", "debug"]
