import assert from "node:assert/strict";
import { test } from "node:test";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

/**
 * General questions go on the user's checklist, apart from "Needs your check"
 * (2026-10-25), and are skipped only when the code clearly shows they cannot
 * apply. Each "doesn't apply" below has a twin where one small sign of the
 * thing keeps the question.
 */

type File = { path: string; content: string };

const HONO_APP: File = {
  path: "server/index.ts",
  content: [
    'import { Hono } from "hono";',
    "const app = new Hono();",
    'app.get("/api/health", (c) => c.json({ ok: true }));',
  ].join("\n"),
};

async function statusOf(files: File[], id: string) {
  const review = await runSecurityReview(snapshotFromFiles(files));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === id);
  assert.ok(item, `no item ${id}`);
  return item;
}
const manifest = (deps: Record<string, string>): File => ({ path: "package.json", content: JSON.stringify({ name: "app", dependencies: deps }) });

// --- Passwords ------------------------------------------------------------------------

test("with no passwords anywhere, the password questions don't apply", async () => {
  for (const id of ["auth/brute-force", "auth/account-recovery", "crypto/no-password-hashes-sent"]) {
    const item = await statusOf([HONO_APP], id);
    assert.equal(item.status, "does-not-apply", id);
    assert.match(item.notApplicable ?? "", /doesn't handle passwords/, id);
  }
});

test("one mention of a password keeps the password questions", async () => {
  const signals: File[][] = [
    [HONO_APP, { path: "server/login.ts", content: "const { email, pass } = await c.req.json();\ntimingSafeEqual(scryptSync(pass, u.salt, 64), u.hash);" }],
    [HONO_APP, { path: "server/de.ts", content: "export const felder = { passwort: z.string() };" }],
    [HONO_APP, { path: "web/form.html", content: '<input type="password" name="p">' }],
    [HONO_APP, { path: "server/users.ts", content: 'await db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").bind(e, h).run();' }],
    [HONO_APP, { path: "db/schema.sql", content: "CREATE TABLE users (id int, password text);" }],
    [HONO_APP, manifest({ bcryptjs: "2.4.3" })],
    [HONO_APP, { path: "web/Login.tsx", content: "export const Login = () => <label>Password</label>;" }],
  ];
  for (const files of signals) {
    for (const id of ["auth/brute-force", "auth/account-recovery"]) {
      assert.equal((await statusOf(files, id)).status, "checklist", `${id} with ${files[1]!.path}`);
    }
  }
});

// --- Sign-in ---------------------------------------------------------------------------

test("with no sign-in at all, the per-person and admin questions don't apply", async () => {
  assert.equal((await statusOf([HONO_APP], "access-control/object-ownership")).status, "does-not-apply");
  assert.equal((await statusOf([HONO_APP], "access-control/admin-only")).status, "does-not-apply");
});

test("API keys or a current user count as accounts", async () => {
  const keyed: File = { path: "server/api.ts", content: 'app.get("/api/x", (c) => c.json(byTenant(c.req.header("x-api-key"))));' };
  assert.equal((await statusOf([HONO_APP, keyed], "access-control/object-ownership")).status, "checklist");
  const clerk: File = { path: "web/Nav.tsx", content: "export const Nav = () => <SignInButton />;" };
  assert.equal((await statusOf([HONO_APP, clerk], "access-control/object-ownership")).status, "checklist");
});

test("with sign-in but no admin pages, the admin question goes on the checklist", async () => {
  const withSession: File = { path: "server/auth.ts", content: 'export const session = getCookie(c, "session");' };
  assert.equal((await statusOf([HONO_APP, withSession], "access-control/object-ownership")).status, "checklist");
  assert.equal((await statusOf([HONO_APP, withSession], "access-control/admin-only")).status, "checklist");
});

// --- Questions that are never skipped ------------------------------------------------

test("the private-network and build-steps questions always stay on the checklist", async () => {
  // No list of ways to send a request is complete, and a hosting service can
  // build a site with no file in the repository saying so.
  const fixed: File = { path: "server/gh.ts", content: 'export const me = () => fetch("https://api.github.com/user");' };
  assert.equal((await statusOf([HONO_APP, fixed], "ssrf/internal-ranges")).status, "checklist");
  assert.equal((await statusOf([HONO_APP], "integrity/ci-permissions")).status, "checklist");
});

// --- Uploads ---------------------------------------------------------------------------------

test("with nothing that receives files, the upload question doesn't apply", async () => {
  assert.equal((await statusOf([HONO_APP], "design/upload-limits")).status, "does-not-apply");
  // An upload tool the check can't read keeps the question with the user.
  assert.equal((await statusOf([HONO_APP, manifest({ formidable: "3.5.0" })], "design/upload-limits")).status, "needs-your-review");
  const form: File = { path: "server/up.ts", content: 'app.post("/api/up", async (c) => { const body = await c.req.parseBody(); return c.json({}); });' };
  assert.equal((await statusOf([HONO_APP, form], "design/upload-limits")).status, "needs-your-review");
  const raw: File = { path: "server/raw.ts", content: 'app.put("/api/avatar", async (c) => { await Bun.write("a.png", await c.req.arrayBuffer()); return c.json({}); });' };
  assert.equal((await statusOf([HONO_APP, raw], "design/upload-limits")).status, "needs-your-review");
});

// --- Code from other websites -----------------------------------------------------------------

test("a script from another website without a lock is a low risk that may be intended", async () => {
  const page: File = { path: "app/index.html", content: '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>' };
  const item = await statusOf([HONO_APP, page], "integrity/third-party-scripts");
  assert.equal(item.status, "action-needed");
  assert.equal(item.risks[0]?.grade, "low");
  assert.equal(item.risks[0]?.mayBeIntended, true);
  assert.match(item.risks[0]?.what ?? "", /cdn\.example\.com/);
});

test("locked scripts, or pages loading only their own code, pass", async () => {
  const locked: File = {
    path: "app/index.html",
    content: '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
  };
  assert.equal((await statusOf([HONO_APP, locked], "integrity/third-party-scripts")).status, "pass");
  const own: File = { path: "app/index.html", content: '<script type="module" src="/src/main.tsx"></script>' };
  // A tag inside an HTML comment does not load.
  const commented: File = { path: "views/head.ejs", content: '<!--[if lt IE 9]>\n<script src="http://html5shim.googlecode.com/html5.js"></script>\n<![endif]-->' };
  assert.equal((await statusOf([HONO_APP, commented], "integrity/third-party-scripts")).status, "pass");
  assert.equal((await statusOf([HONO_APP, own], "integrity/third-party-scripts")).status, "pass");
});

test("pages written as text, or scripts added while running, go back to the user", async () => {
  const asText: File = { path: "server/page.ts", content: 'app.get("/", (c) => c.html(`<html><script src="https://cdn.example.com/x.js"></script></html>`));' };
  assert.equal((await statusOf([HONO_APP, asText, { path: "app/index.html", content: "<html></html>" }], "integrity/third-party-scripts")).status, "needs-your-review");
  const dynamic: File = { path: "web/analytics.ts", content: 'const s = document.createElement("script"); s.src = url; document.head.append(s);' };
  assert.equal((await statusOf([HONO_APP, dynamic, { path: "app/index.html", content: "<html></html>" }], "integrity/third-party-scripts")).status, "needs-your-review");
});

test("an app with no pages at all: the scripts question doesn't apply", async () => {
  assert.equal((await statusOf([HONO_APP], "integrity/third-party-scripts")).status, "does-not-apply");
});

// --- The checklist itself ---------------------------------------------------------------------

test("checklist questions are counted apart, never pass, and don't hold a module back", async () => {
  const review = await runSecurityReview(snapshotFromFiles([HONO_APP, { path: ".github/workflows/ci.yml", content: "on: push" }]));
  const items = review.modules.flatMap((m) => m.items);
  const checklist = items.filter((i) => i.status === "checklist");
  assert.ok(checklist.length > 0);
  assert.equal(review.summary.checklist, checklist.length);
  assert.ok(checklist.every((i) => i.risks.length === 0 && i.unproven.length === 0));
  assert.equal(review.summary.awaitingReview, items.filter((i) => i.status === "needs-your-review").length);
  // A module whose only open items are checklist questions counts as clear.
  const onlyChecklist = review.modules.filter((m) =>
    m.items.some((i) => i.status === "checklist") &&
    m.items.every((i) => i.status === "checklist" || i.status === "pass" || i.status === "does-not-apply")
  );
  assert.ok(onlyChecklist.length > 0);
  assert.ok(review.summary.clear >= onlyChecklist.length);
});

// --- What could not be read --------------------------------------------------------------

test("files ShipBrace could not read keep every question that would otherwise be skipped", async () => {
  const flask = snapshotFromFiles([HONO_APP], undefined, { unread: ["app.py", "templates/index.vue"] });
  const review = await runSecurityReview(flask);
  const status = (id: string) => review.modules.flatMap((m) => m.items).find((i) => i.id === id)?.status;
  for (const id of ["auth/brute-force", "auth/account-recovery", "access-control/object-ownership", "design/upload-limits", "integrity/third-party-scripts", "crypto/no-password-hashes-sent"]) {
    assert.notEqual(status(id), "does-not-apply", id);
  }
  // Pictures and styles hold no code, so they don't count.
  const pictures = await runSecurityReview(snapshotFromFiles([HONO_APP], undefined, { unread: ["public/logo.png", "app/styles.css"] }));
  assert.equal(pictures.modules.flatMap((m) => m.items).find((i) => i.id === "auth/brute-force")?.status, "does-not-apply");
  // A repository too large to list in full is out of sight too.
  const partial = await runSecurityReview(snapshotFromFiles([HONO_APP], undefined, { incomplete: true }));
  assert.notEqual(partial.modules.flatMap((m) => m.items).find((i) => i.id === "auth/brute-force")?.status, "does-not-apply");
});

// --- Scripts: only proven-local or locked addresses pass ------------------------------------

test("addresses filled in later, or loaded outside tags, hand the scripts question back", async () => {
  const pages: Array<[string, string]> = [
    ["web/App.tsx", "export const A = () => <script src={CDN}></script>;"],
    ["web/Analytics.tsx", 'import Script from "next/script";\nexport const G = () => <Script src={`https://www.example.com/gtag.js?id=${id}`} />;'],
    ["views/layout.ejs", '<script src="<%= cdn %>/jquery.min.js"></script>'],
    ["views/layout.hbs", '<script src="{{cdnBase}}/app.js"></script>'],
    ["views/base.njk", '<script src="{{ cdn }}/x.js"></script>'],
    ["app/index.html", '<script type="importmap">{ "imports": { "vue": "https://unpkg.com/vue@3" } }</script>'],
    ["app/index.html", '<script type="module">import x from "https://esm.sh/x@1";</script>'],
    ["web/Head.tsx", 'export const H = () => <Helmet script={[{ src: "https://cdn.example.com/a.js" }]} />;'],
  ];
  for (const [path, content] of pages) {
    assert.equal((await statusOf([HONO_APP, { path, content }], "integrity/third-party-scripts")).status, "needs-your-review", path);
  }
});

test("a lock only counts as the tag's own integrity attribute with a real hash", async () => {
  for (const tag of [
    '<script src="https://cdn.example.com/a.js" integrity=""></script>',
    '<script src="https://cdn.example.com/a.js" data-integrity="sha384-x"></script>',
    "<script src=https://cdn.example.com/a.js></script>",
  ]) {
    assert.equal((await statusOf([HONO_APP, { path: "app/index.html", content: tag }], "integrity/third-party-scripts")).status, "action-needed", tag);
  }
});

test("the report names only the website, never the full address", async () => {
  const page: File = { path: "app/index.html", content: '<script src="https://widgets.example.com/embed.js?key=sk_live_ABCDEFGH12345678"></script>' };
  const item = await statusOf([HONO_APP, page], "integrity/third-party-scripts");
  assert.match(item.risks[0]?.what ?? "", /widgets\.example\.com/);
  assert.doesNotMatch(JSON.stringify(item), /sk_live_/);
});

test("services that ask not to be locked are mentioned, not raised", async () => {
  const page: File = { path: "app/index.html", content: '<link href="https://fonts.googleapis.com/css2?family=VT323" rel="stylesheet"><script src="https://js.stripe.com/v3/"></script>' };
  const item = await statusOf([HONO_APP, page], "integrity/third-party-scripts");
  assert.equal(item.status, "pass");
  assert.match(item.notice ?? "", /js\.stripe\.com/);
});

// --- How statuses are decided ---------------------------------------------------------------

test("a question's skip rule never overrides what a check found", async () => {
  const { runProjectChecks } = await import("../src/review/checks.ts");
  const { buildInventoryFromAst } = await import("../src/analysis/inventory-ast.ts");
  const snapshot = snapshotFromFiles([HONO_APP]);
  const found = {
    id: "test:found",
    itemId: "auth/brute-force",
    run: () => ({ status: "risks" as const, risks: [] }),
  };
  const outcomes = runProjectChecks(snapshot, buildInventoryFromAst(snapshot), [found]);
  assert.equal(outcomes.get("auth/brute-force")?.status, "risks");
});

test("a check that breaks hands its item back; it never becomes a checklist question or a pass", async () => {
  const { runProjectChecks } = await import("../src/review/checks.ts");
  const { buildInventoryFromAst } = await import("../src/analysis/inventory-ast.ts");
  const { buildReview } = await import("../src/review/modules.ts");
  const snapshot = snapshotFromFiles([HONO_APP]);
  const inventory = buildInventoryFromAst(snapshot);
  const broken = { id: "test:broken", itemId: "config/security-headers", run: () => { throw new Error("boom"); } };
  const checks = runProjectChecks(snapshot, inventory, [broken], []);
  const review = buildReview({ findings: [], paths: [], inventory, checks });
  assert.equal(review.modules.flatMap((m) => m.items).find((i) => i.id === "config/security-headers")?.status, "needs-your-review");
});

test("a tool named in a page's words, or in a pattern, is not a tool in use", async () => {
  const prose: File = { path: "views/tutorial.html", content: '<p>Use <a href="https://npmjs.org/package/helmet">Helmet</a> for headers.</p>' };
  assert.equal((await statusOf([HONO_APP, prose], "integrity/third-party-scripts")).status, "pass");
  const checker: File = { path: "src/rules.ts", content: "export const TOOLS = /<Helmet\\b|createElement\\s*\\(\\s*[\"']script/;" };
  assert.equal((await statusOf([HONO_APP, checker, { path: "app/index.html", content: "<html></html>" }], "integrity/third-party-scripts")).status, "pass");
});

test("a session cookie written as a Set-Cookie header counts, and so does its SameSite setting", async () => {
  const route = (cookie: string): File => ({
    path: "server/auth.ts",
    content: `app.post("/api/login", (c) => { c.header("Set-Cookie", \`sid=\${id}; Path=/; HttpOnly${cookie}\`); return c.json({}); });`,
  });
  assert.equal((await statusOf([HONO_APP, route("; SameSite=Lax")], "access-control/csrf")).status, "pass");
  assert.equal((await statusOf([HONO_APP, route("")], "access-control/csrf")).status, "action-needed");
});

test("naming the Set-Cookie header without setting a cookie is not a sign-in cookie", async () => {
  const proxy: File = { path: "server/proxy.ts", content: 'app.post("/api/items", async (c) => { const r = await fetch(u, { method: "POST" }); const h = new Headers(r.headers); h.delete("set-cookie"); return new Response(r.body, { headers: h }); });' };
  assert.notEqual((await statusOf([HONO_APP, proxy], "access-control/csrf")).status, "action-needed");
  const exposed: File = { path: "server/cors.ts", content: 'app.use(cors({ exposeHeaders: ["Set-Cookie"] }));\napp.post("/api/token", (c) => c.json({ token: t }));' };
  assert.notEqual((await statusOf([HONO_APP, exposed], "access-control/csrf")).status, "action-needed");
});

test("Pug pages are read for outside scripts too", async () => {
  const pug: File = { path: "views/layout.pug", content: 'html\n  head\n    script(src="https://cdn.example.com/jquery.js")\n    link(rel="stylesheet", href="/css/site.css")' };
  const item = await statusOf([HONO_APP, pug], "integrity/third-party-scripts");
  assert.equal(item.status, "action-needed");
  assert.equal(item.risks[0]?.location?.line, 3);
});

test("preloaded pictures and fonts are not code, and data-src is not the address", async () => {
  const preloads: File = {
    path: "app/index.html",
    content: '<link rel="preload" as="image" href="https://images.example.com/hero.jpg"><link rel="preload" as="font" href="https://cdn.example.com/inter.woff2" crossorigin>',
  };
  assert.equal((await statusOf([HONO_APP, preloads], "integrity/third-party-scripts")).status, "pass");
  const preloadScript: File = { path: "app/index.html", content: '<link rel="preload" as="script" href="https://cdn.example.com/x.js">' };
  assert.equal((await statusOf([HONO_APP, preloadScript], "integrity/third-party-scripts")).status, "action-needed");
  const dataSrc: File = { path: "app/index.html", content: '<script data-src="/local.js" src="https://cdn.example.com/x.js"></script>' };
  assert.equal((await statusOf([HONO_APP, dataSrc], "integrity/third-party-scripts")).status, "action-needed");
});

test("one report never says both 'no passwords' and 'check your password limits'", async () => {
  const login: File = { path: "server/login.ts", content: "const { email, pass } = await c.req.json();\ntimingSafeEqual(scryptSync(pass, u.salt, 64), u.hash);" };
  const review = await runSecurityReview(snapshotFromFiles([HONO_APP, login]));
  const status = (id: string) => review.modules.flatMap((m) => m.items).find((i) => i.id === id)?.status;
  assert.notEqual(status("crypto/password-storage"), "does-not-apply");
  assert.equal(status("auth/brute-force"), "checklist");
});
