import { decrypt, encrypt, randomToken, sha256 } from "./crypto.ts";
import { refreshTokens, type OAuthApp, type Tokens } from "./github-user.ts";

/**
 * Signed-in sessions.
 *
 * The browser holds a random value in a cookie it cannot hand to page scripts
 * (`HttpOnly`), sends only over https (`Secure`), only to this site (`__Host-`,
 * `Path=/`), and not on requests other sites start (`SameSite=Lax`). The
 * database holds that value's SHA-256 and the person's GitHub token,
 * encrypted. A session lasts a week; signing out deletes it on the server, not
 * only in the browser.
 */

const SESSION_COOKIE = "__Host-shipbrace";
const SESSION_DAYS = 7;

export interface Session {
  idHash: string;
  githubId: number;
  login: string;
  noticeVersion: string | null;
  /** The GitHub token, decrypted, renewed if it had expired. */
  token: string;
}

export function sessionCookie(value: string, maxAgeSeconds = SESSION_DAYS * 86400): string {
  return `${SESSION_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export const clearedSessionCookie = () => `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;

export function cookieValue(header: string | null | undefined, name: string): string | null {
  for (const part of (header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}

/** Records the person and opens a session. Returns the cookie value. */
export async function openSession(
  db: D1Database,
  key: string,
  user: { id: number; login: string },
  tokens: Tokens,
): Promise<string> {
  const value = randomToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString();
  await db.batch([
    db
      .prepare("INSERT INTO users (github_id, login) VALUES (?, ?) ON CONFLICT (github_id) DO UPDATE SET login = excluded.login")
      .bind(user.id, user.login),
    db
      .prepare(
        "INSERT INTO sessions (id_hash, github_id, token, token_expires_at, refresh_token, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(
        await sha256(value),
        user.id,
        await encrypt(key, tokens.accessToken),
        tokens.accessExpiresAt,
        tokens.refreshToken ? await encrypt(key, tokens.refreshToken) : null,
        expires,
      ),
  ]);
  return value;
}

interface SessionRow {
  id_hash: string;
  github_id: number;
  login: string;
  notice_version: string | null;
  token: string;
  token_expires_at: string | null;
  refresh_token: string | null;
  expires_at: string;
}

/**
 * The session behind a cookie, or null. An expired, unknown or tampered-with
 * cookie is simply not a session; the caller asks the person to sign in.
 */
export async function readSession(
  db: D1Database,
  key: string,
  app: OAuthApp,
  cookieHeader: string | null | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<Session | null> {
  const value = cookieValue(cookieHeader, SESSION_COOKIE);
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const idHash = await sha256(value);
  const row = await db
    .prepare(
      `SELECT s.*, u.login, u.notice_version FROM sessions s JOIN users u ON u.github_id = s.github_id
       WHERE s.id_hash = ? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
    )
    .bind(idHash)
    .first<SessionRow>();
  if (!row) return null;

  let token: string;
  try {
    token = await decrypt(key, row.token);
    // GitHub's tokens last eight hours; renew a few minutes early.
    if (row.token_expires_at && Date.parse(row.token_expires_at) < Date.now() + 5 * 60_000) {
      if (!row.refresh_token) return null;
      const renewed = await refreshTokens(app, await decrypt(key, row.refresh_token), fetchImpl);
      await db
        .prepare("UPDATE sessions SET token = ?, token_expires_at = ?, refresh_token = ? WHERE id_hash = ?")
        .bind(
          await encrypt(key, renewed.accessToken),
          renewed.accessExpiresAt,
          renewed.refreshToken ? await encrypt(key, renewed.refreshToken) : row.refresh_token,
          idHash,
        )
        .run();
      token = renewed.accessToken;
    }
  } catch {
    // Could not decrypt or renew: the session is no use. Remove it.
    await db.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
    return null;
  }
  return { idHash, githubId: row.github_id, login: row.login, noticeVersion: row.notice_version, token };
}

/** Ends the session on the server. Returns whose it was, when there was one. */
export async function closeSession(db: D1Database, cookieHeader: string | null | undefined): Promise<number | undefined> {
  const value = cookieValue(cookieHeader, SESSION_COOKIE);
  if (!value) return undefined;
  const row = await db.prepare("DELETE FROM sessions WHERE id_hash = ? RETURNING github_id").bind(await sha256(value)).first<{ github_id: number }>();
  return row?.github_id;
}
