/**
 * Signing in with GitHub, and asking GitHub what a signed-in person may see.
 *
 * This is the GitHub App's own sign-in, so the token it hands out can only
 * ever reach what both the person and the App can reach. ShipBrace never asks
 * for more: it uses the token to read who someone is and what permission they
 * have on a repository, and nothing else.
 *
 * `fetchImpl` is injectable so tests never reach GitHub.
 */

const API = "https://api.github.com";
// A GitHub call that has not answered by then is treated as failed, never waited on forever.
const TIMEOUT_MS = 15_000;
const HEADERS = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "shipbrace" };

export interface Tokens {
  accessToken: string;
  /** ISO time, or null when the App issues tokens that do not expire. */
  accessExpiresAt: string | null;
  refreshToken: string | null;
}

export interface OAuthApp {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export const authorizeUrl = (app: OAuthApp, state: string) =>
  `https://github.com/login/oauth/authorize?${new URLSearchParams({ client_id: app.clientId, redirect_uri: app.redirectUri, state })}`;

async function tokenRequest(app: OAuthApp, params: Record<string, string>, fetchImpl: typeof fetch): Promise<Tokens> {
  const response = await fetchImpl("https://github.com/login/oauth/access_token", {
    method: "POST",
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: "application/json", "content-type": "application/json", "user-agent": "shipbrace" },
    body: JSON.stringify({ client_id: app.clientId, client_secret: app.clientSecret, ...params }),
  });
  const body = (await response.json().catch(() => ({}))) as {
    access_token?: string;
    expires_in?: number;
    refresh_token?: string;
    error?: string;
  };
  // GitHub reports failures with 200 and an `error` field; neither detail is passed on.
  if (!response.ok || !body.access_token) throw new Error("GitHub did not issue a token");
  return {
    accessToken: body.access_token,
    accessExpiresAt: body.expires_in ? new Date(Date.now() + body.expires_in * 1000).toISOString() : null,
    refreshToken: body.refresh_token ?? null,
  };
}

export const exchangeCode = (app: OAuthApp, code: string, fetchImpl: typeof fetch = fetch) =>
  tokenRequest(app, { code, redirect_uri: app.redirectUri }, fetchImpl);

export const refreshTokens = (app: OAuthApp, refreshToken: string, fetchImpl: typeof fetch = fetch) =>
  tokenRequest(app, { grant_type: "refresh_token", refresh_token: refreshToken }, fetchImpl);

async function get<T>(token: string, path: string, fetchImpl: typeof fetch): Promise<{ status: number; body: T | null }> {
  const response = await fetchImpl(`${API}${path}`, { headers: { ...HEADERS, authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { status: response.status, body: response.ok ? ((await response.json()) as T) : null };
}

export async function currentUser(token: string, fetchImpl: typeof fetch = fetch): Promise<{ id: number; login: string }> {
  const { body } = await get<{ id: number; login: string }>(token, "/user", fetchImpl);
  if (!body || typeof body.id !== "number") throw new Error("GitHub did not say who this is");
  return { id: body.id, login: body.login };
}

export interface RepoAccess {
  githubId: number;
  owner: string;
  ownerId: number;
  name: string;
  private: boolean;
  defaultBranch: string;
  /** Can see it. */
  read: boolean;
  /** Can change it: write, maintain or admin. Required to start a review. */
  write: boolean;
  /** Administers it (organisation owners included). May open every kept review of it. */
  admin: boolean;
}

interface RepoBody {
  id: number;
  name: string;
  private: boolean;
  default_branch: string;
  owner: { login: string; id: number };
  permissions?: { admin?: boolean; maintain?: boolean; push?: boolean; pull?: boolean };
}

const access = (repo: RepoBody): RepoAccess => ({
  githubId: repo.id,
  owner: repo.owner.login,
  ownerId: repo.owner.id,
  name: repo.name,
  private: repo.private,
  defaultBranch: repo.default_branch,
  read: Boolean(repo.permissions?.pull || repo.permissions?.push || repo.permissions?.admin),
  write: Boolean(repo.permissions?.push || repo.permissions?.maintain || repo.permissions?.admin),
  admin: Boolean(repo.permissions?.admin),
});

/**
 * What this person may do with a repository, or null when GitHub will not
 * show it to them -- it does not exist, or it is private and the App has not
 * been allowed on it yet. GitHub deliberately does not say which.
 */
export async function repoAccess(token: string, owner: string, repo: string, fetchImpl: typeof fetch = fetch): Promise<RepoAccess | null> {
  const { body } = await get<RepoBody>(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, fetchImpl);
  return body ? access(body) : null;
}

/** The same, by GitHub's id: still right after a rename or transfer. */
export async function repoAccessById(token: string, githubId: number, fetchImpl: typeof fetch = fetch): Promise<RepoAccess | null> {
  const { body } = await get<RepoBody>(token, `/repositories/${githubId}`, fetchImpl);
  return body ? access(body) : null;
}

/** The App installations this person can see: their own, and their organisations' they belong to. */
export async function userInstallations(token: string, fetchImpl: typeof fetch = fetch): Promise<Array<{ id: number; account: string }>> {
  const { body } = await get<{ installations: Array<{ id: number; account?: { login?: string } }> }>(
    token,
    "/user/installations?per_page=100",
    fetchImpl,
  );
  return body?.installations.map((i) => ({ id: i.id, account: i.account?.login ?? "" })) ?? [];
}

/** Repositories in one installation this person can see, with their permissions. */
export async function installationRepos(token: string, installationId: number, fetchImpl: typeof fetch = fetch): Promise<RepoAccess[]> {
  const { body } = await get<{ repositories: RepoBody[] }>(
    token,
    `/user/installations/${installationId}/repositories?per_page=100`,
    fetchImpl,
  );
  return body?.repositories.map(access) ?? [];
}

/**
 * Turns what someone pasted into owner and repository, or null. Accepts the
 * forms people actually paste: the page address, the clone address, with or
 * without `https://`, `www.`, `.git`, a trailing slash, or a path into the
 * repository. Anything not on github.com is refused.
 */
export function parseRepoLink(input: string): { owner: string; repo: string } | null {
  const text = input.trim();
  if (text.length > 300) return null;
  const match =
    text.match(/^(?:https?:\/\/)?(?:www\.)?github\.com[/:]([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:[/?#].*)?$/) ??
    text.match(/^git@github\.com:([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?$/) ??
    text.match(/^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?$/);
  if (!match) return null;
  const [, owner, repo] = match;
  if (!owner || !repo || repo === "." || repo === "..") return null;
  return { owner, repo };
}
