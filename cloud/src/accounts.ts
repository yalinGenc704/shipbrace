import { appJwt } from "@shipbrace/server/github/auth.ts";
import { Hono, type Context } from "hono";
import { randomToken } from "./crypto.ts";
import type { Env } from "./env.ts";
import {
  authorizeUrl,
  currentUser,
  exchangeCode,
  installationRepos,
  parseRepoLink,
  repoAccess,
  repoAccessById,
  userInstallations,
  type OAuthApp,
} from "./github-user.ts";
import { d1History } from "./history-d1.ts";
import { aiAllowedFor } from "./ai-access.ts";
import { nextReset, reviewLimits, usedThisMonth } from "./limits.ts";
import { record } from "./audit.ts";
import { clearedSessionCookie, closeSession, cookieValue, openSession, readSession, sessionCookie, type Session } from "./session.ts";

/**
 * Everything a signed-in person does: sign in and out, accept the notices,
 * paste a repository link, finish setting up the GitHub App, and read kept
 * reviews -- each one only for repositories GitHub says they may see.
 *
 * The rules, in order of importance:
 *  - A review can only be *started* on a repository the person can change.
 *    Otherwise ShipBrace would map the weak spots of other people's sites.
 *  - A kept review can only be *read* by someone GitHub lets see the repository,
 *    asked again (at most five minutes stale) every time.
 *  - Nothing is reviewed, so nothing is sent anywhere, until the person has
 *    accepted the current notices.
 */

/** Bump when the notices change; everyone is asked again. */
export const NOTICE_VERSION = "2026-10-10.2";
const REVIEWS_PER_HOUR = 10;
const GITHUB_TIMEOUT_MS = 15_000;
const STATE_COOKIE = "__Host-shipbrace-state";

type C = Context<{ Bindings: Env; Variables: { session: Session } }>;

const oauthApp = (env: Env): OAuthApp => ({
  clientId: env.GITHUB_CLIENT_ID,
  clientSecret: env.GITHUB_CLIENT_SECRET ?? "",
  redirectUri: `${env.PUBLIC_URL.replace(/\/+$/, "")}/auth/callback`,
});

const configured = (env: Env) => Boolean(env.GITHUB_CLIENT_SECRET && env.SESSION_KEY && env.GITHUB_PRIVATE_KEY);

/** Where to send someone after signing in: a path on this site, never elsewhere. */
const safeReturn = (path: string | undefined) => (path && /^\/(?!\/)[\w\-./?=&%]*$/.test(path) ? path : "/");

/**
 * While ShipBrace is not open to the public, only these GitHub accounts may
 * sign in (ALLOWED_GITHUB_USERS, comma-separated, any case). Empty means open
 * to everyone.
 */
function allowed(env: Env, login: string): boolean {
  const list = (env.ALLOWED_GITHUB_USERS ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return list.length === 0 || list.includes(login.toLowerCase());
}

/** Two strings compared without leaking, through timing, how much matched. */
function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Answers to "what may this person do with repository N", per session, for five minutes. */
const accessCache = new Map<string, { read: boolean; admin: boolean; until: number }>();

async function accessTo(session: Session, githubId: number): Promise<{ read: boolean; admin: boolean }> {
  const key = `${session.idHash}:${githubId}`;
  const cached = accessCache.get(key);
  if (cached && cached.until > Date.now()) return cached;
  const access = await repoAccessById(session.token, githubId);
  const answer = { read: Boolean(access?.read), admin: Boolean(access?.admin) };
  if (accessCache.size > 5_000) accessCache.clear();
  accessCache.set(key, { ...answer, until: Date.now() + 5 * 60_000 });
  return answer;
}

/**
 * A kept review opens for the person who started it and for the repository's
 * admins, and only while GitHub still lets them see the repository: being
 * able to read a repository, even a public one, is not enough on its own.
 */
const mayOpen = (session: Session, access: { read: boolean; admin: boolean }, ranBy: number | null) =>
  access.read && (access.admin || ranBy === session.githubId);

const NOT_YOURS = "Only the person who started this review and the repository's admins can open it.";

/**
 * True when this key is still under its limit (or no limiter is configured).
 * A limiter that fails to answer lets the request through: it is a brake on
 * floods, and the daily and monthly review limits stay exact regardless.
 */
async function underLimit(limiter: RateLimit | undefined, key: string): Promise<boolean> {
  if (!limiter) return true;
  try {
    return (await limiter.limit({ key })).success;
  } catch {
    return true;
  }
}

const TOO_MANY = { error: "Too many requests. Please wait a minute and try again." };

/** The visitor's address as Cloudflare saw it; used only before anyone is signed in. */
const addressOf = (c: { req: { header: (name: string) => string | undefined } }) =>
  c.req.header("cf-connecting-ip") ?? "unknown";

export function accountRoutes() {
  const app = new Hono<{ Bindings: Env; Variables: { session: Session } }>();

  // --- signing in and out --------------------------------------------------------

  app.get("/auth/login", async (c) => {
    if (!configured(c.env)) return c.text("Sign-in is not set up yet.", 503);
    if (!(await underLimit(c.env.ATTEMPT_LIMITER, `sign-in:${addressOf(c)}`))) return c.text(TOO_MANY.error, 429);
    const state = randomToken();
    const back = safeReturn(c.req.query("return"));
    c.header("Set-Cookie", `${STATE_COOKIE}=${state}.${encodeURIComponent(back)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`);
    return c.redirect(authorizeUrl(oauthApp(c.env), state));
  });

  app.get("/auth/callback", async (c) => {
    if (!configured(c.env)) return c.text("Sign-in is not set up yet.", 503);
    if (!(await underLimit(c.env.ATTEMPT_LIMITER, `sign-in:${addressOf(c)}`))) return c.text(TOO_MANY.error, 429);
    const [expected, back] = (cookieValue(c.req.header("cookie"), STATE_COOKIE) ?? "").split(".");
    const state = c.req.query("state") ?? "";
    const code = c.req.query("code");
    // The state ties this callback to the sign-in this browser started; without
    // it, another site could sign a visitor into the attacker's account.
    if (!expected || !code || !sameString(expected, state)) return c.text("Sign-in expired. Please try again.", 400);
    try {
      const tokens = await exchangeCode(oauthApp(c.env), code);
      const user = await currentUser(tokens.accessToken);
      // Not on the invite list: no session, nothing stored about them.
      if (!allowed(c.env, user.login)) return c.redirect("/?invite-only=1");
      const value = await openSession(c.env.DB, c.env.SESSION_KEY!, user, tokens);
      await record(c.env.DB, { actor: user.id, action: "sign-in", target: user.login });
      c.header("Set-Cookie", sessionCookie(value), { append: true });
      c.header("Set-Cookie", `${STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`, { append: true });
      return c.redirect(safeReturn(decodeURIComponent(back ?? "")));
    } catch (error) {
      console.error("sign-in failed:", error instanceof Error ? error.message : "unknown");
      return c.text("Sign-in did not complete. Please try again.", 502);
    }
  });

  // --- everything below needs a session ---------------------------------------------

  app.use("/api/*", async (c, next) => {
    // Changes must come from this site's own pages: same origin, sent as JSON
    // (which another site cannot do without the browser asking first).
    if (c.req.method !== "GET") {
      const origin = c.req.header("origin");
      if (origin !== new URL(c.env.PUBLIC_URL).origin || !c.req.header("content-type")?.startsWith("application/json")) {
        return c.json({ error: "Refused." }, 403);
      }
    }
    if (!configured(c.env)) return c.json({ error: "Sign-in is not set up yet." }, 503);
    const session = await readSession(c.env.DB, c.env.SESSION_KEY!, oauthApp(c.env), c.req.header("cookie"));
    // Someone taken off the invite list loses access at once, not at session expiry.
    const current = session && allowed(c.env, session.login) ? session : null;
    if (!current && c.req.path === "/api/me") return c.json({ signedIn: false, noticeVersion: NOTICE_VERSION });
    if (!current) return c.json({ error: "Please sign in." }, 401);
    if (!(await underLimit(c.env.API_LIMITER, `api:${current.githubId}`))) return c.json(TOO_MANY, 429);
    c.set("session", current);
    c.header("Cache-Control", "no-store");
    c.header("X-Robots-Tag", "noindex");
    await next();
  });

  app.get("/api/me", (c) => {
    const s = c.get("session");
    return c.json({ signedIn: true, login: s.login, noticeVersion: NOTICE_VERSION, noticeAccepted: s.noticeVersion === NOTICE_VERSION });
  });

  app.post("/auth/logout", async (c) => {
    if (c.req.header("origin") !== new URL(c.env.PUBLIC_URL).origin) return c.json({ error: "Refused." }, 403);
    const who = await closeSession(c.env.DB, c.req.header("cookie"));
    if (who !== undefined) await record(c.env.DB, { actor: who, action: "sign-out" });
    c.header("Set-Cookie", clearedSessionCookie());
    return c.json({ ok: true });
  });

  app.post("/api/notice", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { version?: string };
    if (body.version !== NOTICE_VERSION) return c.json({ error: "Please reload and read the current notices." }, 409);
    await c.env.DB.prepare("UPDATE users SET notice_version = ?, notice_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE github_id = ?")
      .bind(NOTICE_VERSION, c.get("session").githubId)
      .run();
    await record(c.env.DB, { actor: c.get("session").githubId, action: "notices-accepted", detail: { version: NOTICE_VERSION } });
    return c.json({ ok: true });
  });

  // --- pasting a link -------------------------------------------------------------------

  app.post("/api/repos", async (c) => (await pasted(c)) as Response);

  async function pasted(c: C) {
    const session = c.get("session");
    if (!(await underLimit(c.env.ATTEMPT_LIMITER, `paste:${session.githubId}`))) return c.json({ status: "limit", ...TOO_MANY }, 429);
    if (session.noticeVersion !== NOTICE_VERSION) return c.json({ status: "notice", error: "Please read the notices first." }, 403);

    const { link } = (await c.req.json().catch(() => ({}))) as { link?: string };
    const parsed = parseRepoLink(String(link ?? ""));
    if (!parsed) return c.json({ status: "invalid", error: "That doesn't look like a GitHub repository link." }, 400);

    const installUrl = `https://github.com/apps/${c.env.GITHUB_APP_SLUG}/installations/new`;
    const repo = await repoAccess(session.token, parsed.owner, parsed.repo);
    if (!repo) {
      return c.json({
        status: "needs-install",
        installUrl,
        message: "ShipBrace can't see this repository yet. If it's private, allow ShipBrace on it on GitHub, then paste the link again.",
      });
    }
    if (!repo.write) {
      return c.json(
        { status: "not-yours", error: "You can only review repositories you can change: your own, or your team's." },
        403,
      );
    }

    // Is the App installed on it? Asked as the App, not as the person.
    const asApp = await fetch(`https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/installation`, {
      headers: {
        authorization: `Bearer ${appJwt(c.env.GITHUB_APP_ID, c.env.GITHUB_PRIVATE_KEY!)}`,
        accept: "application/vnd.github+json",
        "user-agent": "shipbrace",
      },
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
    if (asApp.status === 404) {
      return c.json({ status: "needs-install", installUrl, message: "Allow ShipBrace on this repository on GitHub, then paste the link again." });
    }
    if (!asApp.ok) return c.json({ status: "error", error: "GitHub did not answer. Please try again." }, 502);
    const { id: installationId } = (await asApp.json()) as { id: number };

    const recent = await c.env.DB.prepare(
      "SELECT count(*) AS n FROM review_requests WHERE github_id = ? AND requested_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 hour')",
    )
      .bind(session.githubId)
      .first<{ n: number }>();
    if ((recent?.n ?? 0) >= REVIEWS_PER_HOUR) {
      return c.json({ status: "limit", error: `You can start ${REVIEWS_PER_HOUR} reviews an hour. Please try again later.` }, 429);
    }

    const head = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/commits/${encodeURIComponent(repo.defaultBranch)}`,
      { headers: { authorization: `Bearer ${session.token}`, accept: "application/vnd.github+json", "user-agent": "shipbrace" }, signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS) },
    );
    const sha = head.ok ? ((await head.json()) as { sha?: string }).sha : undefined;
    if (!sha || !/^[0-9a-f]{40}$/.test(sha)) return c.json({ status: "empty", error: "This repository has no commits to review yet." }, 409);

    // Pasting with the notices accepted also sets the installation up -- from
    // now on its pushes are reviewed too -- but only for someone who may manage
    // it. Anyone with write access gets the one review they asked for.
    const setUp = await mayManage(session, installationId);
    const [, inserted] = await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO review_requests (github_id) VALUES (?)").bind(session.githubId),
      ...(setUp
        ? [c.env.DB.prepare("INSERT INTO installations (installation_id, set_up_by) VALUES (?, ?) ON CONFLICT DO NOTHING").bind(installationId, session.githubId)]
        : []),
    ]);
    if (inserted?.meta.changes) {
      await record(c.env.DB, { actor: session.githubId, action: "installation-set-up", target: installationId, detail: { by: "pasted link" } });
    }
    await c.env.REVIEWS.send({ installationId, githubId: repo.githubId, ranBy: session.githubId, owner: repo.owner, repo: repo.name, sha });
    return c.json({ status: "queued", repository: { githubId: repo.githubId, owner: repo.owner, name: repo.name, sha } });
  }

  /** Repositories this person can see through the App, with their latest review. */
  app.get("/api/repos", async (c) => {
    const session = c.get("session");
    const installations = (await userInstallations(session.token)).slice(0, 10);
    const repos = (await Promise.all(installations.map(({ id }) => installationRepos(session.token, id).then((r) => r.map((x) => ({ ...x, installationId: id }))))))
      .flat()
      .filter((r) => r.read)
      .slice(0, 90);
    if (repos.length === 0) return c.json({ repositories: [] });

    // The latest review this person may open: any, where they are an admin;
    // otherwise the latest they started. `?` lists are built from the count only.
    const admin = repos.filter((r) => r.admin).map((r) => r.githubId);
    const { results } = await c.env.DB.prepare(
      `SELECT p.github_id, p.history_id, r.id AS review_id, r.created_at, r.conclusion, r.title
       FROM repositories p
       LEFT JOIN reviews r ON r.id = (
         SELECT id FROM reviews
         WHERE repository_id = p.id AND (p.github_id IN (${admin.map(() => "?").join(",")}) OR ran_by = ?)
         ORDER BY created_at DESC LIMIT 1)
       WHERE p.github_id IN (${repos.map(() => "?").join(",")})`,
    )
      .bind(...admin, session.githubId, ...repos.map((r) => r.githubId))
      .all<{ github_id: number; history_id: string; review_id: string | null; created_at: string | null; conclusion: string | null; title: string | null }>();
    const kept = new Map(results.map((row) => [row.github_id, row]));

    return c.json({
      repositories: repos.map((r) => {
        const row = kept.get(r.githubId);
        return {
          githubId: r.githubId,
          owner: r.owner,
          name: r.name,
          private: r.private,
          canReview: r.write,
          installationId: r.installationId,
          historyId: row?.history_id ?? null,
          latest: row?.review_id ? { id: row.review_id, createdAt: row.created_at, conclusion: row.conclusion, title: row.title } : null,
        };
      }),
    });
  });

  /**
   * Who may set up an installation or change its switches: the person whose
   * own account it is, or an admin of at least one repository it covers.
   * Seeing an installation is not enough -- GitHub lists an organisation's
   * installation to members with read-only access too, and these switches
   * decide what leaves the platform.
   */
  async function mayManage(session: { token: string; githubId: number }, id: number): Promise<boolean> {
    if (!Number.isSafeInteger(id)) return false;
    const installation = (await userInstallations(session.token)).find((i) => i.id === id);
    if (!installation) return false;
    // By GitHub's permanent account number, not the name: a name can be given
    // up and taken by someone else, a number cannot.
    if (installation.accountType === "User" && installation.accountId === session.githubId) return true;
    return (await installationRepos(session.token, id)).some((repo) => repo.admin);
  }

  /** GitHub's "Setup URL" leads to a page whose button posts here, after someone installs the App. */
  app.post("/api/installations/:id/setup", async (c) => {
    const session = c.get("session");
    if (session.noticeVersion !== NOTICE_VERSION) return c.json({ error: "Please read the notices first." }, 403);
    const id = Number(c.req.param("id"));
    // The address can be typed by anyone; GitHub says whether this person may run that installation.
    if (!(await mayManage(session, id))) {
      await refused(c.env.DB, session.githubId, "set up", id);
      return c.json({ error: "Only the account's owner or an admin of its repositories can set this up." }, 403);
    }
    const inserted = await c.env.DB.prepare("INSERT INTO installations (installation_id, set_up_by) VALUES (?, ?) ON CONFLICT DO NOTHING")
      .bind(id, session.githubId)
      .run();
    if (inserted.meta.changes) {
      await record(c.env.DB, { actor: session.githubId, action: "installation-set-up", target: id, detail: { by: "setup page" } });
    }
    return c.json({ ok: true });
  });

  // --- what leaves the platform: per-installation switches -------------------------

  /** The installations this person may manage that are set up, with their switches. */
  app.get("/api/installations", async (c) => {
    const session = c.get("session");
    const all = await userInstallations(session.token);
    const allowed = await Promise.all(all.map((i) => mayManage(session, i.id)));
    const visible = all.filter((_, n) => allowed[n]);
    const aiAvailable = aiAllowedFor(c.env, session.githubId);
    if (visible.length === 0) return c.json({ installations: [], aiAvailable });
    const { results } = await c.env.DB.prepare(
      `SELECT installation_id, package_lookup, ai_review FROM installations WHERE installation_id IN (${visible.map(() => "?").join(",")})`,
    )
      .bind(...visible.map((i) => i.id))
      .all<{ installation_id: number; package_lookup: number; ai_review: number }>();
    const limits = reviewLimits(c.env);
    const used = await Promise.all(results.map((row) => usedThisMonth(c.env.DB, row.installation_id)));
    return c.json({
      aiAvailable,
      installations: results.map((row, n) => ({
        id: row.installation_id,
        account: visible.find((i) => i.id === row.installation_id)?.account ?? "",
        packageLookup: row.package_lookup === 1,
        aiReview: row.ai_review === 1,
        reviews: { used: used[n], limit: limits.monthly, resetsOn: nextReset() },
      })),
    });
  });

  app.post("/api/installations/:id/settings", async (c) => {
    const id = Number(c.req.param("id"));
    if (!(await mayManage(c.get("session"), id))) {
      await refused(c.env.DB, c.get("session").githubId, "change switches", id);
      return c.json({ error: "Only the account's owner or an admin of its repositories can change this." }, 403);
    }
    const body = (await c.req.json().catch(() => ({}))) as { packageLookup?: unknown; aiReview?: unknown };
    if (body.aiReview === true && !aiAllowedFor(c.env, c.get("session").githubId)) {
      return c.json({ error: "The AI step isn't available yet." }, 403);
    }
    const updates: Array<[string, number]> = [];
    if (typeof body.packageLookup === "boolean") updates.push(["package_lookup", body.packageLookup ? 1 : 0]);
    if (typeof body.aiReview === "boolean") updates.push(["ai_review", body.aiReview ? 1 : 0]);
    if (updates.length === 0) return c.json({ error: "Nothing to change." }, 400);
    // Column names come from the fixed list above, never from the request.
    const result = await c.env.DB.prepare(`UPDATE installations SET ${updates.map(([col]) => `${col} = ?`).join(", ")} WHERE installation_id = ?`)
      .bind(...updates.map(([, v]) => v), id)
      .run();
    if (!result.meta.changes) return c.json({ error: "Set this installation up first by reviewing one of its repositories." }, 409);
    await record(c.env.DB, { actor: c.get("session").githubId, action: "switches-changed", target: id, detail: Object.fromEntries(updates) });
    return c.json({ ok: true });
  });

  // --- kept reviews: only for who started them, and the repository's admins ----------

  app.get("/api/reviews/:id", async (c) => {
    const row = await c.env.DB.prepare("SELECT p.github_id, r.ran_by FROM reviews r JOIN repositories p ON p.id = r.repository_id WHERE r.id = ?")
      .bind(c.req.param("id"))
      .first<{ github_id: number; ran_by: number | null }>();
    if (!row) return c.json({ error: "No review at this address." }, 404);
    const session = c.get("session");
    if (!mayOpen(session, await accessTo(session, row.github_id), row.ran_by)) return c.json({ error: NOT_YOURS }, 403);
    return c.json(await d1History(c.env.DB).review(c.req.param("id")));
  });

  /** Admins see every review of the repository; anyone else only the ones they started. */
  app.get("/api/history/:id", async (c) => {
    const row = await c.env.DB.prepare("SELECT github_id FROM repositories WHERE history_id = ?")
      .bind(c.req.param("id"))
      .first<{ github_id: number }>();
    if (!row) return c.json({ error: "No review history at this address." }, 404);
    const session = c.get("session");
    const access = await accessTo(session, row.github_id);
    if (!access.read) return c.json({ error: "You don't have access to this repository on GitHub." }, 403);
    return c.json(await d1History(c.env.DB).repository(c.req.param("id"), access.admin ? undefined : session.githubId));
  });

  return app;
}

/** What the webhook needs: is an installation set up, and deleting what an uninstall removes. */
export const installationIsSetUp = async (db: D1Database, id: number) =>
  Boolean(await db.prepare("SELECT 1 FROM installations WHERE installation_id = ?").bind(id).first());

/** An installation's switches. Unknown installations get nothing sent anywhere. */
export async function installationSwitches(db: D1Database, id: number): Promise<{ packageLookup: boolean; aiReview: boolean }> {
  const row = await db.prepare("SELECT package_lookup, ai_review FROM installations WHERE installation_id = ?").bind(id).first<{ package_lookup: number; ai_review: number }>();
  return { packageLookup: row?.package_lookup === 1, aiReview: row?.ai_review === 1 };
}

/**
 * A refused attempt on an installation: repeated tries at other people's
 * installation numbers are what this record exists to show. Only numbers
 * that are whole and safe are written; anything else is recorded as such.
 */
async function refused(db: D1Database, actor: number, attempt: "set up" | "change switches", id: number): Promise<void> {
  await record(db, { actor, action: "refused", target: Number.isSafeInteger(id) ? id : "not a number", detail: { attempt } });
}

export async function forgetInstallation(db: D1Database, installationId: number, repositoryIds: number[] | "all"): Promise<void> {
  // Told by GitHub (the App was uninstalled, or repositories removed from it).
  await record(db, {
    action: repositoryIds === "all" ? "installation-removed" : "repositories-removed",
    target: installationId,
    ...(repositoryIds === "all" ? {} : { detail: { count: repositoryIds.length, repositories: repositoryIds.slice(0, 50) } }),
  });
  if (repositoryIds === "all") {
    await db.batch([
      db.prepare("DELETE FROM reviews WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id = ?)").bind(installationId),
      db.prepare("DELETE FROM repositories WHERE installation_id = ?").bind(installationId),
      db.prepare("DELETE FROM installations WHERE installation_id = ?").bind(installationId),
    ]);
    return;
  }
  for (const id of repositoryIds.slice(0, 500)) {
    await db.batch([
      db.prepare("DELETE FROM reviews WHERE repository_id IN (SELECT id FROM repositories WHERE github_id = ?)").bind(id),
      db.prepare("DELETE FROM repositories WHERE github_id = ?").bind(id),
    ]);
  }
}
