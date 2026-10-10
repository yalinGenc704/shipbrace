/**
 * The signed-in side of the dashboard, talking to cloud/src/accounts.ts.
 *
 * Every change is a same-site JSON POST: the server refuses anything else, so
 * another website cannot act for a signed-in visitor.
 */

export type Me =
  | { signedIn: false; noticeVersion: string }
  | { signedIn: true; login: string; noticeVersion: string; noticeAccepted: boolean };

export interface ConnectedRepo {
  githubId: number;
  owner: string;
  name: string;
  private: boolean;
  canReview: boolean;
  installationId: number;
  historyId: string | null;
  latest: { id: string; createdAt: string; conclusion: "success" | "neutral" | "failure"; title: string } | null;
}

export type PasteResult =
  | { status: "queued"; repository: { githubId: number; owner: string; name: string; sha: string } }
  | { status: "needs-install"; installUrl: string; message: string }
  | { status: "not-yours" | "invalid" | "limit" | "notice" | "empty" | "error"; error: string };

async function send<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await response.json().catch(() => ({ status: "error", error: "Something went wrong. Please try again." }))) as T;
}

export const signInUrl = (returnTo = window.location.pathname) => `/auth/login?return=${encodeURIComponent(returnTo)}`;

export async function loadMe(): Promise<Me> {
  const response = await fetch("/api/me");
  if (!response.ok) throw new Error(`The server answered ${response.status}.`);
  return (await response.json()) as Me;
}

export const acceptNotice = (version: string) => send<{ ok?: boolean; error?: string }>("/api/notice", { version });
export const pasteLink = (link: string) => send<PasteResult>("/api/repos", { link });
export const setUpInstallation = (id: number) => send<{ ok?: boolean; error?: string }>(`/api/installations/${id}/setup`);

export async function signOut(): Promise<void> {
  await fetch("/auth/logout", { method: "POST" });
  window.location.href = "/";
}

export interface InstallationSettings {
  id: number;
  account: string;
  packageLookup: boolean;
  aiReview: boolean;
}

export async function loadInstallations(): Promise<{ installations: InstallationSettings[]; aiAvailable: boolean }> {
  const response = await fetch("/api/installations");
  if (!response.ok) throw new Error(`The server answered ${response.status}.`);
  return (await response.json()) as { installations: InstallationSettings[]; aiAvailable: boolean };
}

export const saveSettings = (id: number, change: { packageLookup?: boolean; aiReview?: boolean }) =>
  send<{ ok?: boolean; error?: string }>(`/api/installations/${id}/settings`, change);

export async function loadRepos(): Promise<ConnectedRepo[]> {
  const response = await fetch("/api/repos");
  if (!response.ok) throw new Error(`The server answered ${response.status}.`);
  return ((await response.json()) as { repositories: ConnectedRepo[] }).repositories;
}

/**
 * The link someone pasted before being sent to GitHub to allow the App, so
 * they come back to it. Browser storage, guarded: losing it only means pasting
 * again.
 */
const PENDING = "shipbrace.pending-link";
export function rememberLink(link: string): void {
  try {
    sessionStorage.setItem(PENDING, link);
  } catch {}
}
export function takeRememberedLink(): string {
  try {
    const link = sessionStorage.getItem(PENDING) ?? "";
    sessionStorage.removeItem(PENDING);
    return link;
  } catch {
    return "";
  }
}
