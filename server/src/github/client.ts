import { appJwt } from "./auth.ts";

/**
 * A deliberately small GitHub REST client: the handful of calls this server
 * makes, over `fetch`, with no SDK. Fewer dependencies is less code from other
 * people running with access to users' repositories.
 *
 * `fetchImpl` is injectable so tests never reach GitHub.
 */

const API = "https://api.github.com";
const HEADERS = {
  accept: "application/vnd.github+json",
  "x-github-api-version": "2022-11-28",
  "user-agent": "shipbrace",
};

export class GitHubError extends Error {
  readonly status: number;

  constructor(status: number, what: string) {
    // The URL and status only. Response bodies can echo request content.
    super(`GitHub answered ${status} for ${what}`);
    this.name = "GitHubError";
    this.status = status;
  }
}

export interface GitHubClient {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body: unknown): Promise<T>;
  patch<T>(path: string, body: unknown): Promise<T>;
}

export function clientWithToken(token: string, fetchImpl: typeof fetch = fetch): GitHubClient {
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await fetchImpl(`${API}${path}`, {
      method,
      headers: {
        ...HEADERS,
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new GitHubError(response.status, `${method} ${path.split("?")[0]}`);
    return (await response.json()) as T;
  };
  return {
    get: (path) => call("GET", path),
    post: (path, body) => call("POST", path, body),
    patch: (path, body) => call("PATCH", path, body),
  };
}

export interface AppCredentials {
  appId: string;
  privateKey: string;
}

/**
 * A client acting as one installation of the App -- that is, with access to
 * exactly the repositories that installation was granted, for one hour.
 * Minted per review rather than cached, so no long-lived token sits in memory.
 */
export async function installationClient(
  credentials: AppCredentials,
  installationId: number,
  fetchImpl: typeof fetch = fetch,
): Promise<GitHubClient> {
  const asApp = clientWithToken(appJwt(credentials.appId, credentials.privateKey), fetchImpl);
  const { token } = await asApp.post<{ token: string }>(
    `/app/installations/${installationId}/access_tokens`,
    {},
  );
  return clientWithToken(token, fetchImpl);
}
