import type { GeneratedFile, Module } from "../types.ts";

const f = (path: string, contents: string): GeneratedFile => ({ path, contents });

/**
 * Accounts and sessions, as a module rather than a baked-in assumption.
 *
 * Whether generated apps ship with logins is a product decision that can be made
 * per-app and changed later; keeping it here means neither answer requires
 * touching the base scaffold. Auth needs somewhere to store users, so this
 * module is only included when a database was selected.
 */
export const authModule: Module = {
  id: "auth",

  when: (spec) => spec.features.includes("auth") && spec.database !== "none",

  // Declared here as well as in base: a module names what it imports, and the
  // composer merges identical versions without complaint.
  serverDeps: { jose: "6.2.10", postgres: "3.4.9", "hono-rate-limiter": "0.5.4" },

  env: [
    {
      name: "JWT_SECRET",
      description:
        "Signs login tokens. Anyone holding this can log in as any user, so it must differ per environment and never be committed.",
      secret: true,
    },
    {
      name: "DATABASE_URL",
      description: "Postgres connection string. Reachable only from inside the Docker network.",
      secret: true,
    },
  ],

  files: () => [
    f("server/src/db.ts", DB),
    f("server/migrations/001_users.sql", MIGRATION),
    f("server/src/auth/tokens.ts", TOKENS),
    f("server/src/auth/routes.ts", ROUTES),
    f("server/src/auth/middleware.ts", MIDDLEWARE),
  ],
};

/**
 * The `postgres` driver's tagged template parameterises every interpolated
 * value, so `sql`...${value}`` is safe by construction. Exporting only the
 * tagged template -- never a raw query string helper -- removes the unsafe path
 * rather than documenting it.
 */
const DB = `import postgres from "postgres";
import { env } from "./env.ts";

if (!env.DATABASE_URL) {
  console.error("DATABASE_URL is required when accounts are enabled.");
  process.exit(1);
}

export const sql = postgres(env.DATABASE_URL, {
  max: 10,
  idle_timeout: 20,
  // Values interpolated into sql\`...\` are always sent as parameters, never
  // spliced into the query text. Do not add a raw-query escape hatch here.
});
`;

const MIGRATION = `-- Users and refresh sessions.

CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL,
  password_hash text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Case-insensitive uniqueness. Without this, "Ada@x.com" and "ada@x.com"
-- register as two accounts and either can claim the other's password reset.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (lower(email));

CREATE TABLE IF NOT EXISTS refresh_sessions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The token itself is never stored, only its hash. A leaked database backup
  -- therefore does not hand out usable sessions.
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS refresh_sessions_user_id_idx ON refresh_sessions (user_id);
`;

/**
 * Short-lived access token, long-lived rotating refresh token, both delivered as
 * httpOnly cookies so no page script can read them.
 */
const TOKENS = `import { SignJWT, jwtVerify } from "jose";
import { env } from "../env.ts";

const secret = new TextEncoder().encode(env.JWT_SECRET);

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

export async function signAccessToken(userId: string): Promise<string> {
  return new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(\`\${ACCESS_TTL_SECONDS}s\`)
    .sign(secret);
}

export async function verifyAccessToken(token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });
    return typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    // Expired or tampered-with. Indistinguishable to the caller on purpose --
    // telling an attacker *why* a token failed helps them forge a better one.
    return null;
  }
}

/** Opaque and random: a refresh token carries no claims, so it cannot be forged. */
export function createRefreshToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, "");
}

export async function hashRefreshToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * httpOnly  - page scripts cannot read it, so one XSS is not an account takeover.
 * secure    - never sent over plain http.
 * sameSite  - not attached to requests started by other sites (CSRF).
 * path      - the refresh cookie is only sent to the one endpoint that needs it.
 */
export const accessCookie = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  path: "/",
  maxAge: ACCESS_TTL_SECONDS,
} as const;

export const refreshCookie = {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  path: "/api/auth/refresh",
  maxAge: REFRESH_TTL_SECONDS,
} as const;
`;

const ROUTES = `import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { rateLimiter } from "hono-rate-limiter";
import { z } from "zod";
import { sql } from "../db.ts";
import {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  accessCookie,
  createRefreshToken,
  hashRefreshToken,
  refreshCookie,
  signAccessToken,
} from "./tokens.ts";

const credentials = z.object({
  email: z.string().email().max(254),
  // Length is the property that actually resists guessing. Composition rules
  // ("one symbol") mostly push people toward predictable substitutions.
  password: z.string().min(12).max(200),
});

export const authRoutes = new Hono();

/**
 * A far tighter limit than the rest of the API.
 *
 * Guessing a password is only practical if you can try many of them, so this is
 * the single most valuable place to put a ceiling. Ten attempts per fifteen
 * minutes is generous for a person who has forgotten their password and useless
 * to someone working through a list.
 *
 * Keyed on the caller's address rather than the submitted email: keying on the
 * email would let an attacker lock a victim out of their own account by failing
 * logins on purpose.
 */
const signInLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  keyGenerator: (c) => c.req.header("cf-connecting-ip") ?? "unidentified",
});

authRoutes.use("/login", signInLimiter);
authRoutes.use("/register", signInLimiter);

async function issueSession(c: Parameters<Parameters<Hono["post"]>[1]>[0], userId: string) {
  const refresh = createRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000);

  await sql\`
    INSERT INTO refresh_sessions (user_id, token_hash, expires_at)
    VALUES (\${userId}, \${await hashRefreshToken(refresh)}, \${expiresAt})
  \`;

  setCookie(c, "access", await signAccessToken(userId), accessCookie);
  setCookie(c, "refresh", refresh, refreshCookie);
}

authRoutes.post("/register", async (c) => {
  const body = credentials.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "Invalid email or password" }, 400);

  const { email, password } = body.data;
  const hash = await Bun.password.hash(password, { algorithm: "argon2id" });

  const rows = await sql\`
    INSERT INTO users (email, password_hash)
    VALUES (\${email}, \${hash})
    ON CONFLICT DO NOTHING
    RETURNING id
  \`;

  // A distinct "email already registered" reply would let anyone test which
  // addresses have accounts here. Same response either way.
  if (rows.length === 0) return c.json({ ok: true }, 201);

  await issueSession(c, rows[0]!.id as string);
  return c.json({ ok: true }, 201);
});

authRoutes.post("/login", async (c) => {
  const body = credentials.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "Invalid email or password" }, 400);

  const rows = await sql\`
    SELECT id, password_hash FROM users WHERE lower(email) = lower(\${body.data.email}) LIMIT 1
  \`;
  const user = rows[0];

  // Verify even when no user matched, so the reply takes the same time either
  // way and cannot be used to enumerate registered addresses.
  const stored = (user?.password_hash as string | undefined) ??
    "$argon2id$v=19$m=65536,t=2,p=1$aaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const ok = await Bun.password.verify(body.data.password, stored).catch(() => false);

  if (!user || !ok) return c.json({ error: "Invalid email or password" }, 401);

  await issueSession(c, user.id as string);
  return c.json({ ok: true });
});

authRoutes.post("/refresh", async (c) => {
  const presented = getCookie(c, "refresh");
  if (!presented) return c.json({ error: "Not signed in" }, 401);

  const hash = await hashRefreshToken(presented);
  const rows = await sql\`
    SELECT id, user_id FROM refresh_sessions
    WHERE token_hash = \${hash} AND revoked_at IS NULL AND expires_at > now()
    LIMIT 1
  \`;
  const session = rows[0];
  if (!session) return c.json({ error: "Not signed in" }, 401);

  // Rotate: the presented token is spent immediately. If it is ever replayed --
  // because it was stolen -- the second use finds it already revoked.
  await sql\`UPDATE refresh_sessions SET revoked_at = now() WHERE id = \${session.id}\`;

  await issueSession(c, session.user_id as string);
  return c.json({ ok: true, expiresIn: ACCESS_TTL_SECONDS });
});

authRoutes.post("/logout", async (c) => {
  const presented = getCookie(c, "refresh");
  if (presented) {
    await sql\`
      UPDATE refresh_sessions SET revoked_at = now()
      WHERE token_hash = \${await hashRefreshToken(presented)} AND revoked_at IS NULL
    \`;
  }

  deleteCookie(c, "access", accessCookie);
  deleteCookie(c, "refresh", refreshCookie);
  return c.json({ ok: true });
});
`;

/**
 * Deny by default. `requireUser` is applied to a route prefix rather than to
 * individual handlers, so a newly added route under that prefix is protected
 * without anyone remembering to protect it.
 */
const MIDDLEWARE = `import type { MiddlewareHandler } from "hono";
import { getCookie } from "hono/cookie";
import { verifyAccessToken } from "./tokens.ts";

declare module "hono" {
  interface ContextVariableMap {
    userId: string;
  }
}

export const requireUser: MiddlewareHandler = async (c, next) => {
  const token = getCookie(c, "access");
  const userId = token ? await verifyAccessToken(token) : null;

  if (!userId) return c.json({ error: "Not signed in" }, 401);

  c.set("userId", userId);
  await next();
};
`;
