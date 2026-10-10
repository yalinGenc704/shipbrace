# The reviewer container on Cloudflare (wrangler.jsonc). Built for linux/amd64,
# which is what Cloudflare runs. Same packages as the server image, without
# the dashboard; runs as the unprivileged `node` user.
FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY app/package.json app/
COPY server/package.json server/
COPY cloud/package.json cloud/
COPY packages/guardrails/package.json packages/guardrails/
COPY packages/scaffold/package.json packages/scaffold/
RUN npm ci --ignore-scripts --omit=dev --workspace @shipbrace/server

FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules node_modules
COPY package.json ./
COPY server/package.json server/
COPY server/src server/src
COPY packages/guardrails/package.json packages/guardrails/
COPY packages/guardrails/src packages/guardrails/src
USER node
EXPOSE 8080
CMD ["node", "--experimental-strip-types", "server/src/sandbox/reviewer-http.ts"]
