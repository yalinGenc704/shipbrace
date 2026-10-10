# ShipBrace: one image, two roles (the server and the sealed reviewer), chosen by
# the command in deploy/compose.yaml. Base images are pinned by digest so a
# rebuild cannot silently pick up a different one.

# --- build the dashboard ---------------------------------------------------------
FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY app/package.json app/
COPY server/package.json server/
COPY packages/guardrails/package.json packages/guardrails/
COPY packages/scaffold/package.json packages/scaffold/
COPY cloud/package.json cloud/
# Install scripts stay off: nothing in the tree needs one, and they are the
# usual way a compromised package runs code at install time.
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build --workspace @shipbrace/app

# --- runtime packages only ---------------------------------------------------------
FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY app/package.json app/
COPY server/package.json server/
COPY packages/guardrails/package.json packages/guardrails/
COPY packages/scaffold/package.json packages/scaffold/
COPY cloud/package.json cloud/
RUN npm ci --ignore-scripts --omit=dev --workspace @shipbrace/server

# --- what runs --------------------------------------------------------------------
FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules node_modules
COPY package.json ./
COPY server/package.json server/
COPY server/src server/src
COPY packages/guardrails/package.json packages/guardrails/
COPY packages/guardrails/src packages/guardrails/src
COPY --from=build /app/app/dist app/dist
# The socket folder shared with the reviewer, owned by the unprivileged user
# that ships with the image. Everything runs as that user, never as root.
RUN mkdir -p /run/shipbrace && chown node:node /run/shipbrace
USER node
EXPOSE 3000
CMD ["node", "--experimental-strip-types", "server/src/index.ts"]
