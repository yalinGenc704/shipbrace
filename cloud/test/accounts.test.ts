import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, test } from "node:test";
import { runSecurityReview, snapshotFromFiles } from "@aegis/guardrails";
import { Hono } from "hono";
import { accountRoutes, forgetInstallation, installationIsSetUp, installationSwitches, NOTICE_VERSION } from "../src/accounts.ts";
import { decrypt, encrypt, randomToken } from "../src/crypto.ts";
import type { Env } from "../src/env.ts";
import { parseRepoLink } from "../src/github-user.ts";
import { d1History } from "../src/history-d1.ts";
import { fakeD1 } from "./fake-d1.ts";

/**
 * Sign-in and paste-a-link, against a stand-in GitHub. Each test is one way
 * someone could try to get more than they should.
 */

const ORIGIN = "https://app.shipbrace.test";
const KEY = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const PEM = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }).toString();

/** Repositories the stand-in GitHub knows, and what our test person may do with each. */
const REPOS: Record<string, { id: number; private: boolean; push: boolean; pull: boolean; installed: number | null }> = {
  "murat/shop": { id: 101, private: true, push: true, pull: true, installed: 7 },
  "murat/fresh": { id: 102, private: false, push: true, pull: true, installed: null },
  "stranger/bank": { id: 201, private: false, push: false, pull: true, installed: 9 },
};

let queued: unknown[];
let env: Env;
let app: Hono<{ Bindings: Env }>;

function fakeGitHub(): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const path = url.pathname;
    if (url.host === "github.com" && path === "/login/oauth/access_token") {
      return Response.json({ access_token: "user-token", expires_in: 28800, refresh_token: "refresh-token" });
    }
    if (path === "/user") return Response.json({ id: 5, login: "murat" });
    if (path === "/user/installations") return Response.json({ installations: [{ id: 7, account: { login: "murat" } }] });
    if (path === "/user/installations/7/repositories") {
      return Response.json({ repositories: [repoBody("murat/shop")] });
    }
    const byName = path.match(/^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/);
    if (byName) {
      const full = `${byName[1]}/${byName[2]}`;
      const repo = REPOS[full];
      if (!repo) return new Response("not found", { status: 404 });
      if (byName[3] === "/installation") {
        return repo.installed ? Response.json({ id: repo.installed }) : new Response("not found", { status: 404 });
      }
      if (byName[3]?.startsWith("/commits/")) return Response.json({ sha: "c".repeat(40) });
      // A private repository the App is not on is invisible, as on GitHub.
      if (repo.private && !repo.installed) return new Response("not found", { status: 404 });
      return Response.json(repoBody(full));
    }
    const byId = path.match(/^\/repositories\/(\d+)$/);
    if (byId) {
      const entry = Object.entries(REPOS).find(([, r]) => r.id === Number(byId[1]));
      return entry && entry[1].pull ? Response.json(repoBody(entry[0])) : new Response("not found", { status: 404 });
    }
    return new Response("unexpected call in test", { status: 500 });
  }) as typeof fetch;
}

function repoBody(full: string) {
  const [owner, name] = full.split("/");
  const r = REPOS[full]!;
  return { id: r.id, name, private: r.private, default_branch: "main", owner: { login: owner, id: 1 }, permissions: { push: r.push, pull: r.pull } };
}

beforeEach(() => {
  globalThis.fetch = fakeGitHub();
  queued = [];
  env = {
    DB: fakeD1(),
    REVIEWS: { send: async (job: unknown) => void queued.push(job) } as never,
    REVIEWER: {} as never,
    ASSETS: {} as never,
    PUBLIC_URL: ORIGIN,
    AI_REVIEW: "off",
    PACKAGE_LOOKUP: "on",
    GITHUB_APP_ID: "12345",
    DAILY_REVIEW_LIMIT: "200",
    GITHUB_CLIENT_ID: "client-id",
    GITHUB_APP_SLUG: "shipbrace-test",
    GITHUB_PRIVATE_KEY: PEM,
    GITHUB_CLIENT_SECRET: "client-secret",
    SESSION_KEY: KEY,
  };
  app = new Hono<{ Bindings: Env }>().route("/", accountRoutes() as never);
});

const call = (path: string, init: RequestInit = {}, cookie = "") =>
  app.request(`${ORIGIN}${path}`, { ...init, headers: { ...(cookie ? { cookie } : {}), ...(init.headers ?? {}) } }, env);

const post = (path: string, body: unknown, cookie: string, origin = ORIGIN) =>
  call(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", origin } }, cookie);

/** Signs the test person in the way a browser would, and returns their cookie. */
async function signIn(acceptNotice = true): Promise<string> {
  const start = await call("/auth/login?return=/reviews/x");
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const back = await call(`/auth/callback?code=abc&state=${state}`, {}, stateCookie);
  assert.equal(back.status, 302);
  assert.equal(back.headers.get("location"), "/reviews/x", "returned where they started");
  const session = back.headers.getSetCookie().find((c) => c.startsWith("__Host-shipbrace="))!.split(";")[0]!;
  if (acceptNotice) assert.equal((await post("/api/notice", { version: NOTICE_VERSION }, session)).status, 200);
  return session;
}

// --- signing in ---------------------------------------------------------------------

test("a sign-in that this browser did not start is refused", async () => {
  const start = await call("/auth/login");
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
  assert.equal((await call(`/auth/callback?code=abc&state=${randomToken()}`, {}, stateCookie)).status, 400, "wrong state");
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  assert.equal((await call(`/auth/callback?code=abc&state=${state}`)).status, 400, "no state cookie");
});

test("the session cookie cannot be read by page scripts or sent by other sites", async () => {
  const start = await call("/auth/login");
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const back = await call(`/auth/callback?code=abc&state=${state}`, {}, stateCookie);
  const cookie = back.headers.getSetCookie().find((c) => c.startsWith("__Host-shipbrace="))!;
  for (const flag of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) assert.ok(cookie.includes(flag), flag);
});

test("after sign-in, nobody is sent anywhere else than this site", async () => {
  const start = await call("/auth/login?return=//evil.example/steal");
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const back = await call(`/auth/callback?code=abc&state=${state}`, {}, stateCookie);
  assert.equal(back.headers.get("location"), "/");
});

test("the stored GitHub token is encrypted, and the cookie itself is not stored", async () => {
  const cookie = await signIn();
  const value = cookie.split("=")[1]!;
  const row = await env.DB.prepare("SELECT * FROM sessions").first<Record<string, string>>();
  assert.ok(row);
  assert.ok(!JSON.stringify(row).includes(value), "cookie value not in the database");
  assert.ok(!JSON.stringify(row).includes("user-token"), "token not stored in the clear");
  assert.equal(await decrypt(KEY, row.token!), "user-token");
});

test("signing out ends the session on the server, not only in the browser", async () => {
  const cookie = await signIn();
  assert.equal((await call("/auth/logout", { method: "POST", headers: { origin: ORIGIN } }, cookie)).status, 200);
  assert.equal((await call("/api/repos", {}, cookie)).status, 401, "the old cookie no longer works");
});

// --- changes only from this site's own pages ------------------------------------------

test("another website cannot make a signed-in visitor start a review", async () => {
  const cookie = await signIn();
  assert.equal((await post("/api/repos", { link: "murat/shop" }, cookie, "https://evil.example")).status, 403);
  const form = await call("/api/repos", { method: "POST", body: "link=murat/shop", headers: { origin: ORIGIN, "content-type": "application/x-www-form-urlencoded" } }, cookie);
  assert.equal(form.status, 403, "a plain form post is refused");
  assert.equal(queued.length, 0);
});

// --- pasting a link ---------------------------------------------------------------------

test("nothing is reviewed before the notices are accepted", async () => {
  const cookie = await signIn(false);
  const response = await post("/api/repos", { link: "https://github.com/murat/shop" }, cookie);
  assert.equal(response.status, 403);
  assert.equal(((await response.json()) as { status: string }).status, "notice");
  assert.equal(queued.length, 0);
});

test("pasting your own repository queues a review of its latest commit and sets the installation up", async () => {
  const cookie = await signIn();
  const response = await post("/api/repos", { link: "https://github.com/murat/shop.git" }, cookie);
  assert.equal(((await response.json()) as { status: string }).status, "queued");
  assert.deepEqual(queued, [{ installationId: 7, githubId: 101, owner: "murat", repo: "shop", sha: "c".repeat(40) }]);
  assert.equal(await installationIsSetUp(env.DB, 7), true, "its later pushes are reviewed too");
});

test("someone else's repository cannot be reviewed, even a public one", async () => {
  const cookie = await signIn();
  const response = await post("/api/repos", { link: "https://github.com/stranger/bank" }, cookie);
  assert.equal(response.status, 403);
  assert.equal(((await response.json()) as { status: string }).status, "not-yours");
  assert.equal(queued.length, 0);
  assert.equal(await installationIsSetUp(env.DB, 9), false);
});

test("a repository the App is not on yet asks for one click on GitHub", async () => {
  const cookie = await signIn();
  const body = (await (await post("/api/repos", { link: "murat/fresh" }, cookie)).json()) as { status: string; installUrl: string };
  assert.equal(body.status, "needs-install");
  assert.equal(body.installUrl, "https://github.com/apps/shipbrace-test/installations/new");
});

test("a link that isn't a GitHub repository is refused plainly", async () => {
  const cookie = await signIn();
  for (const link of ["https://gitlab.com/murat/shop", "not a link", "https://github.com/murat", "https://evil.example/github.com/murat/shop"]) {
    assert.equal((await post("/api/repos", { link }, cookie)).status, 400, link);
  }
});

test("one person can start only so many reviews an hour", async () => {
  const cookie = await signIn();
  for (let i = 0; i < 10; i++) await post("/api/repos", { link: "murat/shop" }, cookie);
  assert.equal((await post("/api/repos", { link: "murat/shop" }, cookie)).status, 429);
  assert.equal(queued.length, 10);
});

test("setting up an installation that isn't yours is refused", async () => {
  const cookie = await signIn();
  assert.equal((await post("/api/installations/9/setup", {}, cookie)).status, 403);
  assert.equal((await post("/api/installations/7/setup", {}, cookie)).status, 200);
  assert.equal(await installationIsSetUp(env.DB, 9), false);
});

// --- reading kept reviews -----------------------------------------------------------------

async function keep(githubId: number, repo: string) {
  const result = await runSecurityReview(snapshotFromFiles([{ path: "a.ts", content: "export const x = 1;" }]));
  return d1History(env.DB).record({
    githubId,
    installationId: 7,
    owner: repo.split("/")[0]!,
    repo: repo.split("/")[1]!,
    commitSha: "d".repeat(40),
    conclusion: "success",
    title: "No proven problems",
    result,
    skipped: { notReadable: 0, tooLarge: 0, overLimit: 0, treeTruncated: false },
  });
}

test("a kept review opens only for someone GitHub lets see the repository", async () => {
  const mine = await keep(101, "murat/shop");
  const cookie = await signIn();
  assert.equal((await call(`/api/reviews/${mine.reviewId}`, {}, cookie)).status, 200);
  assert.equal((await call(`/api/history/${mine.historyId}`, {}, cookie)).status, 200);
  assert.equal((await call(`/api/reviews/${mine.reviewId}`)).status, 401, "the link alone is no longer enough");

  REPOS["murat/shop"]!.pull = false;
  REPOS["murat/shop"]!.push = false;
  const other = await signIn();
  assert.equal((await call(`/api/reviews/${mine.reviewId}`, {}, other)).status, 403, "removed from the repository, removed from its reviews");
  REPOS["murat/shop"]!.pull = true;
  REPOS["murat/shop"]!.push = true;
});

test("uninstalling deletes that installation's reviews and nothing else", async () => {
  const gone = await keep(101, "murat/shop");
  await env.DB.prepare("INSERT INTO installations (installation_id) VALUES (7)").run();
  await forgetInstallation(env.DB, 7, "all");
  assert.equal(await d1History(env.DB).review(gone.reviewId), null);
  assert.equal(await installationIsSetUp(env.DB, 7), false);
});

// --- the small pieces ------------------------------------------------------------------------

test("links are read the way people paste them", () => {
  for (const link of ["https://github.com/murat/shop", "github.com/murat/shop", "https://www.github.com/murat/shop/", "https://github.com/murat/shop.git", "git@github.com:murat/shop.git", "https://github.com/murat/shop/tree/main/src", "murat/shop"]) {
    assert.deepEqual(parseRepoLink(link), { owner: "murat", repo: "shop" }, link);
  }
  assert.equal(parseRepoLink("https://github.com/murat/.."), null);
});

test("an encrypted token cannot be altered or opened with another key", async () => {
  const sealed = await encrypt(KEY, "secret-token");
  assert.equal(await decrypt(KEY, sealed), "secret-token");
  const tampered = sealed.slice(0, -2) + (sealed.endsWith("A") ? "B" : "A") + sealed.slice(-1);
  await assert.rejects(decrypt(KEY, tampered));
  const otherKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  await assert.rejects(decrypt(otherKey, sealed));
});

// --- invite-only ----------------------------------------------------------------------

test("while invite-only, an account not on the list gets no session at all", async () => {
  env.ALLOWED_GITHUB_USERS = "someone-else";
  const start = await call("/auth/login");
  const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const back = await call(`/auth/callback?code=abc&state=${state}`, {}, stateCookie);
  assert.equal(back.headers.get("location"), "/?invite-only=1");
  assert.ok(!back.headers.getSetCookie().some((c) => c.startsWith("__Host-shipbrace=")));
  assert.equal(await env.DB.prepare("SELECT count(*) AS n FROM users").first<{ n: number }>().then((r) => r?.n), 0, "nothing stored about them");
});

test("taking someone off the invite list ends their access immediately", async () => {
  env.ALLOWED_GITHUB_USERS = "Murat";
  const cookie = await signIn();
  assert.equal((await call("/api/repos", {}, cookie)).status, 200, "the list is not case-sensitive");
  env.ALLOWED_GITHUB_USERS = "someone-else";
  assert.equal((await call("/api/repos", {}, cookie)).status, 401);
});

// --- the off switches ----------------------------------------------------------------

test("the package check can be switched off for your installation, and only yours", async () => {
  const cookie = await signIn();
  assert.equal((await post("/api/installations/7/settings", { packageLookup: false }, cookie)).status, 409, "not set up yet");
  await post("/api/repos", { link: "murat/shop" }, cookie);
  assert.deepEqual(await installationSwitches(env.DB, 7), { packageLookup: true, aiReview: false }, "the defaults the notices describe");

  assert.equal((await post("/api/installations/7/settings", { packageLookup: false }, cookie)).status, 200);
  assert.deepEqual(await installationSwitches(env.DB, 7), { packageLookup: false, aiReview: false });
  const listed = (await (await call("/api/installations", {}, cookie)).json()) as { installations: Array<{ id: number; packageLookup: boolean }> };
  assert.deepEqual(listed.installations.map((i) => [i.id, i.packageLookup]), [[7, false]]);

  assert.equal((await post("/api/installations/9/settings", { packageLookup: false }, cookie)).status, 403, "someone else's");
});

test("the AI step cannot be switched on before it is offered", async () => {
  const cookie = await signIn();
  await post("/api/repos", { link: "murat/shop" }, cookie);
  assert.equal((await post("/api/installations/7/settings", { aiReview: true }, cookie)).status, 403);
  assert.deepEqual(await installationSwitches(env.DB, 7), { packageLookup: true, aiReview: false });
});

test("an installation nobody set up sends nothing anywhere", async () => {
  assert.deepEqual(await installationSwitches(env.DB, 12345), { packageLookup: false, aiReview: false });
});
