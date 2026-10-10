import type { GeneratedFile, Module, ScaffoldSpec } from "../types.ts";

const f = (path: string, contents: string): GeneratedFile => ({ path, contents });

/**
 * Everything every generated app gets. Secure defaults live here rather than in
 * documentation, because a default that has to be read and applied is not a
 * default -- and the users this product targets will not read it.
 */
export const baseModule: Module = {
  id: "base",

  appDeps: {
    react: "19.2.8",
    "react-dom": "19.2.8",
    "@tanstack/react-router": "1.170.32",
    "@tanstack/react-query": "5.102.8",
    tailwindcss: "4.3.3",
    "lucide-react": "1.35.0",
  },

  serverDeps: {
    hono: "4.13.5",
    "hono-rate-limiter": "0.5.4",
    zod: "4.5.2",
  },

  env: [
    {
      name: "PORT",
      description: "Port the API server listens on inside the container.",
      secret: false,
      example: "3000",
    },
    {
      name: "ALLOWED_ORIGINS",
      description:
        "Comma-separated list of sites allowed to call this API. Never use * -- that lets any website act as your logged-in users.",
      secret: false,
      example: "http://localhost:5173",
    },
    {
      name: "TUNNEL_TOKEN",
      description: "Cloudflare Tunnel token. Grants ingress to this deployment.",
      secret: true,
    },
  ],

  files: (spec) => {
    const files = [
      f("README.md", readme(spec)),
      f(".gitignore", GITIGNORE),
      f("docker-compose.yml", dockerCompose(spec)),
      f("Dockerfile", DOCKERFILE),
      f(".dockerignore", DOCKERIGNORE),
      f("tsconfig.json", TSCONFIG),
      f(".oxlintrc.json", OXLINTRC),
      f("app/vite.config.ts", VITE_CONFIG),
      f("app/index.html", indexHtml(spec)),
      f("app/src/main.tsx", MAIN_TSX),
      f("app/src/styles.css", '@import "tailwindcss";\n'),
      f("app/src/api.ts", API_CLIENT),
      f("server/src/index.ts", SERVER_INDEX),
      f("server/src/env.ts", SERVER_ENV),
    ];

    if (spec.database !== "none") files.push(f("scripts/backup.sh", BACKUP_SH));
    return files;
  },
};

/**
 * The first-run steps, in the order they have to happen.
 *
 * Step 2 exists because a lockfile cannot be generated ahead of time -- it is
 * produced by the install. Until it is committed, builds are not reproducible,
 * and the security review will keep saying so.
 */
const readme = (spec: ScaffoldSpec): string => `# ${spec.name}

## First run

1. Copy the example settings and fill them in:

   \`\`\`
   cp .env.example .env
   \`\`\`

   Every value marked \`CHANGE_ME\` is a secret. Generate a fresh one per
   environment -- \`openssl rand -base64 32\` produces a suitable value. The app
   refuses to start rather than fall back to a built-in default.

2. Install dependencies, then **commit the lockfile it creates**:

   \`\`\`
   bun install
   git add bun.lock && git commit -m "Add lockfile"
   \`\`\`

   The lockfile records the exact version of every package. Without it, a build
   next month can pull different code than the one you tested.

3. Start everything:

   \`\`\`
   docker compose up --build
   \`\`\`

## What is already handled

- The database is not reachable from outside the application.
- The API is reached only through the Cloudflare tunnel.
- Login tokens are stored in cookies that page scripts cannot read.
- Requests are rate limited${spec.features.includes("auth") ? ", with a much stricter limit on signing in" : ""}.
- The server refuses to start with a missing or weak signing key.

## Built in, ready to use

- **Charts** -- \`BarChart\`, \`LineChart\` and \`DoughnutChart\` from
  \`app/src/components/charts.tsx\` (Chart.js).
- **Excel import and export** -- \`readSpreadsheet(file)\` and
  \`downloadSpreadsheet(rows, "name")\` from \`app/src/lib/spreadsheet.ts\`
  (SheetJS). Uploaded files are size-limited and never run formulas; exported
  cells that would run as formulas are made into plain text.
- **MySQL** -- set \`MYSQL_URL\` in \`.env\` to connect to an existing MySQL
  database, then use \`\` query\`SELECT ... \${value}\` \`\` from \`server/src/mysql.ts\`.
  Values are always sent separately from the query text.

Run the security review before deploying. It reports what it could check and
what is still yours to judge.
`;

const GITIGNORE = `node_modules/
dist/
backups/
.env
.env.*
!.env.example
*.log
.DS_Store
`;

const DOCKERIGNORE = `node_modules
dist
.git
.env
backups
*.log
`;

/**
 * Neither the database nor the API publishes a port to the host. The Cloudflare
 * tunnel is the only route in, which means a misconfigured host firewall cannot
 * expose either one -- they were never listening on a public interface.
 */
function dockerCompose(spec: ScaffoldSpec): string {
  const hasDb = spec.database !== "none";

  const dbServices = hasDb
    ? `
  db:
    image: postgres:18-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: \${POSTGRES_DB}
      POSTGRES_USER: \${POSTGRES_USER}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
    volumes:
      - db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5

  backup:
    image: postgres:18-alpine
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      PGHOST: db
      PGUSER: \${POSTGRES_USER}
      PGDATABASE: \${POSTGRES_DB}
      PGPASSWORD: \${POSTGRES_PASSWORD}
      RETENTION_DAYS: "14"
    volumes:
      - ./backups:/backups
      - ./scripts/backup.sh:/backup.sh:ro
    entrypoint: ["sh", "/backup.sh"]
`
    : "";

  const apiEnv = [
    "      PORT: ${PORT}",
    "      ALLOWED_ORIGINS: ${ALLOWED_ORIGINS}",
    "      JWT_SECRET: ${JWT_SECRET}",
    ...(hasDb ? ["      DATABASE_URL: ${DATABASE_URL}"] : []),
    "      MYSQL_URL: ${MYSQL_URL:-}",
  ].join("\n");

  const apiDependsOn = hasDb
    ? "    depends_on:\n      db:\n        condition: service_healthy\n"
    : "";

  const volumes = hasDb ? "\nvolumes:\n  db-data:\n" : "";

  return `name: ${spec.name}

services:
  api:
    build: .
    restart: unless-stopped
    environment:
${apiEnv}
${apiDependsOn}    # No "ports:" on purpose -- the tunnel below is the only way in.
    expose:
      - "\${PORT}"

  tunnel:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: \${TUNNEL_TOKEN}
    depends_on:
      - api
${dbServices}${volumes}`;
}

/** Kept out of docker-compose.yml so the shell is not nested inside YAML. */
const BACKUP_SH = `#!/bin/sh
# Nightly logical backup. Runs in its own container so a crash here can never
# take the application down with it.
set -eu

RETENTION_DAYS="\${RETENTION_DAYS:-14}"

while true; do
  stamp="$(date +%Y%m%d-%H%M%S)"
  target="/backups/\${stamp}.sql.gz"

  # Write to a temporary name first, then rename. A backup interrupted halfway
  # through is worse than no backup, because it looks like a real one.
  if pg_dump --no-owner | gzip > "\${target}.partial"; then
    mv "\${target}.partial" "$target"
    echo "backup ok: $target"
  else
    rm -f "\${target}.partial"
    echo "backup FAILED at $stamp" >&2
  fi

  find /backups -name '*.sql.gz' -mtime "+\${RETENTION_DAYS}" -delete
  sleep 86400
done
`;

/**
 * Multi-stage so the published image contains the built frontend and production
 * dependencies only -- no source, no build tools, no dev dependencies.
 */
const DOCKERFILE = `# syntax=docker/dockerfile:1

FROM oven/bun:1.4-alpine AS deps
WORKDIR /app
# bun.lock* rather than bun.lock: a freshly generated project has no lockfile
# until \`bun install\` has been run once, and a bare \`bun.lock\` here fails the
# build on a missing file before anything else happens.
COPY package.json bun.lock* ./
COPY app/package.json ./app/
COPY server/package.json ./server/

# Reproducible when a lockfile is committed, still buildable before it is. The
# security review flags the missing lockfile until you commit one, so this
# fallback cannot quietly become permanent.
RUN if [ -f bun.lock ]; then bun install --frozen-lockfile; else bun install; fi

FROM deps AS build
COPY . .
RUN bun run --filter './app' build

FROM oven/bun:1.4-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Run as an unprivileged user so a compromised process cannot rewrite the image.
RUN addgroup -S app && adduser -S app -G app

COPY --from=deps  --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/app/dist   ./app/dist
COPY --from=build --chown=app:app /app/server     ./server

USER app
EXPOSE 3000
CMD ["bun", "run", "server/src/index.ts"]
`;

const TSCONFIG = `{
  "compilerOptions": {
    "target": "ES2023",
    "lib": ["ES2023", "DOM", "DOM.Iterable"],
    "module": "Preserve",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "allowImportingTsExtensions": true,
    "verbatimModuleSyntax": true,
    "noEmit": true,

    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "skipLibCheck": true
  },
  "include": ["app/src", "server/src"]
}
`;

const OXLINTRC = `{
  "categories": { "correctness": "error", "suspicious": "warn" },
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "typescript/no-explicit-any": "warn"
  },
  "ignorePatterns": ["dist", "node_modules"]
}
`;

const VITE_CONFIG = `import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The API is reached through this proxy in development, so browser code
    // always calls a same-origin path and never needs a CORS exception.
    proxy: { "/api": { target: "http://localhost:3000", changeOrigin: true } },
  },
  build: { sourcemap: false },
});
`;

const indexHtml = (spec: ScaffoldSpec): string => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${spec.name}</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
`;

const MAIN_TSX = `import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const queryClient = new QueryClient();

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <main className="mx-auto max-w-3xl p-8">
        <h1 className="text-2xl font-semibold">It works.</h1>
      </main>
    </QueryClientProvider>
  </StrictMode>,
);
`;

/**
 * Every request sends cookies. Login state therefore lives in an httpOnly
 * cookie the browser attaches automatically, never in a token page scripts
 * can read.
 */
const API_CLIENT = `export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(\`/api\${path}\`, {
    ...init,
    credentials: "include",
    headers: { "content-type": "application/json", ...init.headers },
  });

  if (!response.ok) {
    throw new ApiError(response.status, \`Request to \${path} failed\`);
  }
  return response.json() as Promise<T>;
}
`;

/**
 * Validated once at startup and exported as plain values. There is deliberately
 * no fallback for any secret: a missing JWT_SECRET must stop the process, not
 * silently substitute a value that is published in the repository.
 */
const SERVER_ENV = `import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  ALLOWED_ORIGINS: z
    .string()
    .min(1)
    .refine((value) => !value.includes("*"), {
      message: "ALLOWED_ORIGINS must list real origins; * would let any site call this API",
    }),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  DATABASE_URL: z.string().url().optional(),
  // Optional second database; an empty value means "not used".
  MYSQL_URL: z.preprocess((v) => (v === "" ? undefined : v), z.string().url().optional()),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(\`  \${issue.path.join(".")}: \${issue.message}\`);
  }
  process.exit(1);
}

export const env = parsed.data;
export const allowedOrigins = env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim());
`;

const SERVER_INDEX = `import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { rateLimiter } from "hono-rate-limiter";
import { allowedOrigins, env } from "./env.ts";

const app = new Hono();

// Sets CSP, X-Frame-Options and friends. Cheap, and closes a whole class of
// problems that stay invisible until someone exploits one.
app.use("*", secureHeaders());

/**
 * Identifies the caller for rate limiting.
 *
 * Requests arrive through the Cloudflare tunnel, so the original address is in
 * cf-connecting-ip. Cloudflare overwrites that header on the way in, which is
 * what makes it safe to trust -- an ordinary client header such as
 * x-forwarded-for can be set to anything by the caller, so using one would let
 * an attacker reset their own limit by changing a header on every request.
 */
const callerKey = (c: { req: { header: (name: string) => string | undefined } }): string =>
  c.req.header("cf-connecting-ip") ?? "unidentified";

/**
 * A ceiling on how often anyone can call the API.
 *
 * Counts are held in memory, so they reset when the container restarts and are
 * not shared if you ever run more than one copy of this service. That is fine
 * for a single deployment; move the store to Redis before scaling out.
 */
app.use(
  "/api/*",
  rateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: callerKey }),
);

app.use(
  "/api/*",
  cors({
    // An explicit allowlist, never "*". Credentials are honoured only for
    // origins this deployment actually owns.
    origin: (origin) => (allowedOrigins.includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ["GET", "POST", "PATCH", "DELETE"],
  }),
);

app.get("/api/health", (c) => c.json({ ok: true }));

export default { port: env.PORT, fetch: app.fetch };
`;
