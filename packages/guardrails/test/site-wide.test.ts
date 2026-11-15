import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import { verifyOwnership } from "../src/analysis/verify.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";
import { leakedJargon } from "./plain-words.ts";

/**
 * Steps registered for a whole app or section (`app.use(...)`) and whether
 * they require signing in for the pages after them (setup item 10,
 * `analysis/site-wide.ts`). Three answers: a check, not a check, or "could
 * not tell", which hands the page back and never passes it.
 */

const HEAD = ['const express = require("express");', "const app = express();"];
const ROUTE = 'app.get("/orders", (req, res) => res.json(listOrders(req.session.userId)));';

type Files = Array<{ path: string; content: string }>;
const inv = (files: Files) => buildInventoryFromAst(snapshotFromFiles(files));
const one = (...lines: string[]): Files => [{ path: "server.js", content: [...HEAD, ...lines].join("\n") }];

/** What the open-page check sees for /orders: "check", "open" or "unsure". */
function answer(files: Files, path = "/orders"): string {
  const door = inv(files).doors.find((d) => d.path === path);
  assert.ok(door, `no route ${path}`);
  if (door.guards.length > 0) return "check";
  return door.signInUnclear?.length ? `unsure:${door.signInUnclear[0]!.reason}` : "open";
}

test("a sign-in check written inline, or under a name the checker does not know, protects the pages after it", () => {
  for (const use of [
    'app.use((req, res, next) => { if (!req.session.userId) return res.redirect("/login"); next(); });',
    "app.use(function (req, res, next) { if (!req.user) { return res.status(401).end(); } next(); });",
    'app.use((req, res, next) => (req.session.member ? next() : res.redirect("/login")));',
    'app.use((req, res, next) => { if (req.isAuthenticated()) return next(); res.redirect("/login"); });',
    'app.use((req, res, next) => { if (req.user == null) return res.sendStatus(401); next(); });',
    'app.use((req, res, next) => { if (req.user?.role !== "member") return res.sendStatus(403); next(); });',
    'app.use((req, res, next) => { if (!req.user || !req.user.active) return res.sendStatus(401); next(); });',
  ]) {
    assert.equal(answer(one(use, ROUTE)), "check", use);
  }
  const named = ["function mustBeMember(req, res, next) {", '  if (!req.user) return res.redirect("/login");', "  next();", "}", "app.use(mustBeMember);", ROUTE];
  assert.equal(answer(one(...named)), "check");
  const made = ["const onlyMembers = () => (req, res, next) => { if (!req.user) return res.sendStatus(401); next(); };", "app.use(onlyMembers());", ROUTE];
  assert.equal(answer(one(...made)), "check");
  // Named by what it tests, so the role checks downstream can still read it.
  assert.deepEqual(inv(one('app.use((req, res, next) => { if (!req.session.userId) return res.redirect("/login"); next(); });', ROUTE)).doors[0]?.guards, ["req.session.userId"]);
});

test("a verified sign-in pass counts; a pass only looked for does not", () => {
  const verified = [
    'const jwt = require("jsonwebtoken");',
    "app.use((req, res, next) => { try { req.user = jwt.verify(req.cookies.token, KEY); next(); } catch { res.sendStatus(401); } });",
    ROUTE,
  ];
  assert.equal(answer(one(...verified)), "check");
  const callback = [
    'const jwt = require("jsonwebtoken");',
    "app.use((req, res, next) => { jwt.verify(req.cookies.token, KEY, (err, user) => { if (err) return res.sendStatus(401); req.user = user; next(); }); });",
    ROUTE,
  ];
  assert.equal(answer(one(...callback)), "check");
  const lookedUp = ["app.use(async (req, res, next) => { const user = await sessions.get(req.cookies.sid); if (!user) return res.sendStatus(401); next(); });", ROUTE];
  assert.equal(answer(one(...lookedUp)), "check");
  // `jwt.decode` reads a pass without checking it is genuine.
  const decoded = ['const jwt = require("jsonwebtoken");', "app.use((req, res, next) => { const user = jwt.decode(req.cookies.token); if (!user) return res.sendStatus(401); next(); });", ROUTE];
  assert.equal(answer(one(...decoded)), "unsure:credential-only");
  assert.equal(answer(one("app.use((req, res, next) => { if (!req.headers.authorization) return res.sendStatus(401); next(); });", ROUTE)), "unsure:credential-only");
});

test("library checks count when bound to their import, unless set to let everyone through", () => {
  assert.equal(answer(one('const { expressjwt } = require("express-jwt");', 'app.use(expressjwt({ secret: KEY, algorithms: ["HS256"] }));', ROUTE)), "check");
  assert.equal(answer(one('const { expressjwt } = require("express-jwt");', "app.use(expressjwt({ secret: KEY, credentialsRequired: false }));", ROUTE)), "unsure:optional");
  assert.equal(answer(one('const passport = require("passport");', 'app.use(passport.authenticate("jwt", { session: false }));', ROUTE)), "check");
  // The session strategy restores who is signed in but refuses nobody.
  assert.equal(answer(one('const passport = require("passport");', 'app.use(passport.authenticate("session"));', ROUTE)), "unsure:optional");
  assert.equal(answer(one('const { requiresAuth } = require("express-openid-connect");', "app.use(requiresAuth());", ROUTE)), "check");
  assert.equal(answer(one('const { ensureLoggedOut } = require("connect-ensure-login");', "app.use(ensureLoggedOut());", ROUTE)), "open");
  // A package with no sign-in word in its name or export prepares the request.
  assert.equal(answer(one('const i18n = require("i18n");', "app.use(i18n.init);", ROUTE)), "open");
  assert.equal(answer(one('const requestId = require("express-request-id");', "app.use(requestId());", ROUTE)), "open");
});

test("steps that do not require signing in never count, whatever their name", () => {
  for (const lines of [
    ["app.use((req, res, next) => { console.log(req.method, req.url); next(); });"],
    ['app.use((req, res, next) => { res.setHeader("X-Frame-Options", "DENY"); next(); });'],
    ["app.use(async (req, res, next) => { req.user = await findUser(req.cookies.sid); next(); });"],
    ['app.use((req, res, next) => { if (busy()) return res.status(503).send("Back soon"); next(); });'],
    ['app.use((req, res, next) => { if (!req.session) return next(new Error("No session")); next(); });'],
    ["function requireLogin(req, res, next) { req.wantsLogin = true; next(); }", "app.use(requireLogin);"],
    ['app.use(function authErrors(err, req, res, next) { res.status(401).send("Sign in"); });'],
    ['const session = require("express-session");', "app.use(session({ secret: KEY }));", "app.use(express.json());"],
  ]) {
    assert.equal(answer(one(...lines, ROUTE)), "open", lines.join(" "));
  }
});

test("a step that lets anonymous visitors through somewhere is not a check", () => {
  // Turning away only banned users lets everyone who is not signed in through.
  assert.equal(answer(one("app.use((req, res, next) => { if (req.user?.banned) return res.sendStatus(403); next(); });", ROUTE)), "unsure:unclear-body");
  assert.equal(answer(one('app.use((req, res, next) => { if (!req.user && req.path !== "/welcome") return res.redirect("/login"); next(); });', ROUTE)), "unsure:unclear-body");
  assert.equal(answer(one('app.use((req, res, next) => { if (req.path === "/welcome") return next(); if (!req.user) return res.redirect("/login"); next(); });', ROUTE)), "unsure:exempt");
  // Only signed-out visitors get on.
  assert.equal(answer(one('app.use((req, res, next) => { if (req.user) return res.redirect("/home"); next(); });', ROUTE)), "unsure:unclear-body");
});

test("what the checker cannot read goes back to the user, never a pass", () => {
  assert.equal(answer(one("app.use(checkpoint);", ROUTE)), "unsure:unreadable");
  assert.equal(answer(one('if (process.env.LOCKED) app.use((req, res, next) => (req.user ? next() : res.sendStatus(401)));', ROUTE)), "unsure:conditional");
  assert.equal(answer(one('app.use((req, res, next) => { if (req.get("x-api-key") !== KEY) return res.sendStatus(401); next(); });', ROUTE)), "unsure:key-or-address");
  assert.equal(answer(one("function setup(app, guard) {", "  app.use(guard);", '  app.get("/orders", (req, res) => res.json(listOrders(req.user.id)));', "}")), "unsure:parameter");
  assert.equal(answer(one('app.use((req, res, next) => { if (!isMember(req)) return res.sendStatus(403); next(); });', ROUTE)), "unsure:unclear-body");
  // A clear name keeps counting when its code is out of sight (Murat's decision, 2026-11-15).
  assert.equal(answer(one("app.use(requireLogin);", ROUTE)), "check");
});

test("the conventions reviewer's false passes stay closed (2026-11-15)", () => {
  const check = "function requireAuth(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }";
  // 1. An address that cannot be read is not "every address".
  assert.equal(answer(one(check, 'const { API_PREFIX } = require("./config");', "app.use(API_PREFIX, requireAuth);", ROUTE)), "unsure:some-addresses");
  assert.equal(answer(one(check, "app.use(config.adminPath, requireAuth);", ROUTE)), "unsure:some-addresses");
  // 2. A step chosen by a condition.
  assert.equal(answer(one(check, "app.use(process.env.AUTH ? requireAuth : noop);", ROUTE)), "unsure:conditional");
  assert.equal(answer(one(check, "app.use(enabled && requireAuth);", ROUTE)), "unsure:conditional");
  // 3. A verify that may fail quietly: an optional sign-in, an ignored answer.
  const jwt = 'const jwt = require("jsonwebtoken");';
  assert.equal(answer(one(jwt, "app.use((req, res, next) => { try { req.user = jwt.verify(req.cookies.token, K); } catch (e) { req.user = null; } next(); });", ROUTE)), "open");
  assert.equal(answer(one("app.use((req, res, next) => { verifyToken(req.cookies.token); next(); });", ROUTE)), "open");
  assert.equal(answer(one('app.use((req, res, next) => { const ok = verifyToken(req.cookies.token); if (!ok) { console.log("bad"); } next(); });', ROUTE)), "open");
  // ...while a library verify on its own line still guards what follows.
  assert.equal(answer(one(jwt, "app.use((req, res, next) => { req.user = jwt.verify(req.cookies.token, K); next(); });", ROUTE)), "check");
  // 4. Anti-forgery and share tokens are not sign-in passes.
  assert.equal(answer(one('app.use((req, res, next) => { if (!validateCsrf(req.headers["x-csrf-token"])) return res.sendStatus(403); next(); });', ROUTE)), "open");
  assert.equal(answer(one("app.use((req, res, next) => { if (!tokens.get(req.query.token)) return res.sendStatus(403); next(); });", ROUTE)), "open");
  assert.equal(answer(one("app.use((req, res, next) => { if (!cache.get(req.cookies.sidebar)) return res.sendStatus(403); next(); });", ROUTE)), "open");
  // 5. A router out of sight is not a check, whatever its name.
  assert.equal(answer(one('import adminRouter from "@/routes/admin";', "app.use(adminRouter);", ROUTE)), "unsure:unreadable");
  // 6. Steps and routes added inside functions run whenever, and if, the function is called.
  assert.equal(answer(one(check, "function addAuth() { app.use(requireAuth); }", "if (process.env.PROD) addAuth();", ROUTE)), "unsure:order");
  assert.equal(answer(one(check, "setup();", "app.use(requireAuth);", 'function setup() { app.get("/orders", (req, res) => res.json(listOrders(req.user.id))); }')), "unsure:order");
  // Smaller ones: a record picked by the address, a user that is always something,
  // a session key that is not a person, a comparison the visitor can make true.
  assert.equal(answer(one("app.use(async (req, res, next) => { const id = req.query.id; const user = await getUser(id); if (!user) return res.sendStatus(404); next(); });", ROUTE)), "open");
  assert.equal(answer(one("app.use((req, res, next) => { const user = req.user || {}; if (!user) return res.sendStatus(401); next(); });", ROUTE)), "unsure:unclear-body");
  assert.equal(answer(one("app.use((req, res, next) => { if (!req.session.userAgent) return res.sendStatus(401); next(); });", ROUTE)), "unsure:unclear-body");
  assert.equal(answer(one("app.use((req, res, next) => { if (req.user?.id === req.query.x) return next(); res.sendStatus(403); });", ROUTE)), "unsure:unclear-body");
});

test("the second review's false passes stay closed (2026-11-15)", () => {
  const check = "function requireLogin(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }";
  const app = (...lines: string[]) => ({ path: "app.js", content: [...HEAD, check, ...lines].join("\n") });
  const two = {
    path: "routes.js",
    content: [
      'const express = require("express");',
      "const router = express.Router();",
      "const adminRoutes = express.Router();",
      'router.get("/home", (req, res) => res.json(home()));',
      'adminRoutes.get("/orders", (req, res) => res.json(listOrders(req.user.id)));',
      "module.exports = { pub: router, admin: adminRoutes };",
    ].join("\n"),
  };
  // 1. The router mounted before the check is the one picked, not any router in the file.
  assert.equal(answer([app('const { admin } = require("./routes");', 'app.use("/admin", admin);', "app.use(requireLogin);", 'app.use("/pub", require("./routes").pub);'), two]), "open");
  assert.equal(answer([app('const { admin } = require("./routes");', "app.use(requireLogin);", 'app.use("/admin", admin);'), two]), "check");
  assert.equal(answer([app('const routes = require("./routes");', 'app.use("/admin", routes.admin);', "app.use(requireLogin);"), two]), "open");
  // A file whose router cannot be told apart: it may be mounted before the check.
  const unexported = { path: "routes.js", content: ['const express = require("express");', "const router = express.Router();", "const adminRoutes = express.Router();", 'adminRoutes.get("/orders", (req, res) => res.json(listOrders(req.user.id)));', "module.exports = router;"].join("\n") };
  assert.notEqual(answer([app("app.use(requireLogin);", 'app.use("/x", require("./routes"));'), unexported]), "check");
  // 2. An address made by a call.
  assert.equal(answer(one(check, "app.use(base(), requireLogin);", ROUTE)), "unsure:some-addresses");
  assert.equal(answer(one(check, 'app.use(config.get("prefix"), requireLogin);', ROUTE)), "unsure:some-addresses");
  assert.equal(answer(one(check, 'const cors = require("cors");', "app.use(cors(), requireLogin);", ROUTE)), "check");
  // 3. A user that is always something.
  assert.equal(answer(one("app.use((req, res, next) => { const user = req.user ? req.user : {}; if (!user) return res.sendStatus(401); next(); });", ROUTE)), "unsure:unclear-body");
  // 4. A comparison with a value the visitor sends, held in a name.
  assert.equal(answer(one("app.use((req, res, next) => { const want = req.query.u; if (req.user?.id === want) return next(); res.sendStatus(401); });", ROUTE)), "unsure:unclear-body");
  assert.equal(answer(one("app.use((req, res, next) => { const { u } = req.query; if (req.user?.id === u) return next(); res.sendStatus(401); });", ROUTE)), "unsure:unclear-body");
  // Final pass: a "user" that is always something, by shape.
  for (const user of [
    "let user = req.user; if (!user) user = {};",
    "const user = { ...req.user };",
    "const user = Object.assign({}, req.user);",
    "const user = `${req.user}`;",
    "const user = [req.user];",
    "const user = String(req.user);",
  ]) {
    assert.notEqual(answer(one(`app.use((req, res, next) => { ${user} if (!user) return res.sendStatus(401); next(); });`, ROUTE)), "check", user);
  }
  // ...while the user itself, or a part of it, still counts.
  assert.equal(answer(one("app.use(async (req, res, next) => { const user = await getUser(req); if (!user) return res.sendStatus(401); next(); });", ROUTE)), "check");
  assert.equal(answer(one("app.use((req, res, next) => { const id = req.user?.id; if (!id) return res.sendStatus(401); next(); });", ROUTE)), "check");
  // A routes file handed the app under a condition may never be handed it.
  const gate = { path: "middleware/gate.js", content: "module.exports = function (req, res, next) { if (!req.user) return res.sendStatus(401); next(); };" };
  const handed = { path: "routes/index.js", content: ["module.exports = (app) => {", '  app.get("/statements", (req, res) => res.json(list(req.user.id)));', "};"].join("\n") };
  assert.equal(answer([app('app.use(require("./middleware/gate"));', 'if (process.env.FULL) require("./routes")(app);'), gate, handed], "/statements"), "unsure:conditional");
  // A role word alone is not a sign-in name; next to a check word it is.
  assert.equal(answer(one('import adminLogger from "@/h";', "app.use(adminLogger);", ROUTE)), "unsure:unreadable");
  assert.equal(answer(one("app.use(isAdmin);", ROUTE)), "check");
});

test("the fresh review's false passes stay closed (2026-11-15)", async () => {
  const passport = 'const passport = require("passport");';
  // 1. Passport's list of strategies, or a strategy held in a name, may include "anonymous".
  assert.equal(answer(one(passport, 'app.use(passport.authenticate(["jwt", "anonymous"], { session: false }));', ROUTE)), "unsure:optional");
  assert.equal(answer(one(passport, 'const m = "anonymous";', "app.use(passport.authenticate(m));", ROUTE)), "unsure:optional");
  // 2. Library settings held in a name or spread in.
  const ejwt = 'const { expressjwt } = require("express-jwt");';
  assert.equal(answer(one(ejwt, "const o = { secret: K, credentialsRequired: false };", "app.use(expressjwt(o));", ROUTE)), "unsure:optional");
  assert.equal(answer(one(ejwt, "app.use(expressjwt({ ...opts }));", ROUTE)), "unsure:optional");
  assert.equal(answer(one('const { auth } = require("express-openid-connect");', "const c = { authRequired: false };", "app.use(auth(c));", ROUTE)), "unsure:optional");
  // 3. Addresses exempted with .unless(...).
  assert.equal(answer(one(ejwt, 'app.use(expressjwt({ secret: K, algorithms: ["HS256"] }).unless({ path: ["/orders"] }));', ROUTE)), "unsure:exempt");
  assert.equal(answer(one('app.use(requireLogin.unless({ path: ["/orders"] }));', ROUTE)), "unsure:exempt");
  // 4. The step writes who is signed in itself, then reads it back.
  for (const write of ["req.user = req.query.u;", "req.session.userId = req.query.u;", "req.user = req.user || {};", "req.user = { id: 1 };", "req = { user: {} };"]) {
    const test = write.startsWith("req.session") ? "req.session.userId" : "req.user";
    assert.notEqual(answer(one(`app.use((req, res, next) => { ${write} if (!${test}) return res.sendStatus(401); next(); });`, ROUTE)), "check", write);
  }
  // ...while a verified pass written there still counts.
  assert.equal(answer(one("app.use(async (req, res, next) => { req.user = await sessions.get(req.cookies.sid); if (!req.user) return res.sendStatus(401); next(); });", ROUTE)), "check");
  // 5. Names that say they let visitors through, or only prepare something.
  for (const name of ["optionalAuth", "authOptional", "noAuth", "allowAnonymousAuth", "authLogger", "setAuthUser", "attachAuthUser", "guestGuard", "requireLoginExceptPublic"]) {
    assert.equal(answer(one(`app.use(${name});`, ROUTE)), "unsure:unreadable", name);
  }
  // 6. A sign-in check that reads a role is still not a role check for the admin pages.
  const admin = one("app.use((req, res, next) => { if (!req.user || !req.user.role) return res.sendStatus(401); next(); });", 'app.get("/admin/users", (req, res) => res.json(User.findAll()));');
  assert.deepEqual(inv(admin).doors[0]?.guards, ["req.user"]);
  // 7. A helper the step defines for itself is not the app's sign-in lookup.
  assert.notEqual(answer(one("app.use(async (req, res, next) => { const getUser = () => ({}); const u = getUser(req); if (!u) return res.sendStatus(401); next(); });", ROUTE)), "check");
  // A check added by a helper the app is handed counts where the helper is called.
  const check = "function requireLogin(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }";
  assert.equal(answer(one(check, "function applyMiddleware(app) { app.use(requireLogin); }", "applyMiddleware(app);", ROUTE)), "check");
  assert.equal(answer(one(check, "function applyMiddleware(app) { app.use(requireLogin); }", ROUTE, "applyMiddleware(app);")), "open");
  const mw = { path: "mw.js", content: [check, "module.exports = (app) => { app.use(requireLogin); };"].join("\n") };
  assert.equal(answer([{ path: "app.js", content: [...HEAD, 'require("./mw")(app);', ROUTE].join("\n") }, mw]), "check");
  assert.equal(answer(one(check, "function applyMiddleware(app) { setTimeout(() => app.use(requireLogin)); }", "applyMiddleware(app);", ROUTE)), "unsure:order");
});

test("the last review's findings stay closed (2026-11-15)", () => {
  // Clerk outside @clerk/express only records who is signed in.
  assert.equal(answer(one('const { clerkMiddleware } = require("@hono/clerk-auth");', "app.use(clerkMiddleware());", ROUTE)), "open");
  assert.equal(answer(one('const { clerkMiddleware } = require("@clerk/nextjs/server");', "app.use(clerkMiddleware());", ROUTE)), "open");
  assert.equal(answer(one('const { ClerkExpressWithAuth } = require("@clerk/clerk-sdk-node");', "app.use(ClerkExpressWithAuth());", ROUTE)), "open");
  assert.equal(answer(one('const { ClerkExpressRequireAuth } = require("@clerk/clerk-sdk-node");', "app.use(ClerkExpressRequireAuth());", ROUTE)), "check");
  // The sign-in pages, mounted everywhere, refuse nobody.
  assert.equal(answer(one('const { toNodeHandler } = require("better-auth/node");', "app.use(toNodeHandler(auth));", ROUTE)), "open");
  assert.equal(answer(one('const { ExpressAuth } = require("@auth/express");', "app.use(ExpressAuth({ providers }));", ROUTE)), "open");
  // Names that mean "maybe", or only decode.
  for (const name of ["maybeAuth", "softAuth", "tryAuth", "authIfPresent", "jwtDecode"]) assert.equal(answer(one(`app.use(${name});`, ROUTE)), "unsure:unreadable", name);
  // `next(null)` and `next("route")` carry on: a catch ending in one lets everyone through.
  const jwt = 'const jwt = require("jsonwebtoken");';
  assert.notEqual(answer(one(jwt, "app.use((req, res, next) => { try { req.user = jwt.verify(req.cookies.token, K); next(); } catch { next(null); } });", ROUTE)), "check");
  // A captcha or webhook signature is not a sign-in pass.
  assert.notEqual(answer(one("app.use((req, res, next) => { if (!verifyToken(req.body.captcha)) return res.sendStatus(401); next(); });", ROUTE)), "check");
  assert.notEqual(answer(one('app.use((req, res, next) => { if (!verifyToken(req.headers["x-signature"])) return res.sendStatus(401); next(); });', ROUTE)), "check");
  // Names that want visitors signed out, or do another job, are not trusted by name.
  for (const name of ["checkNotAuthenticated", "isNotLoggedIn", "requireLoggedOut", "forwardAuthenticated", "onlyUnauthenticated", "loginLimiter", "authCors", "protectFromCsrf", "jwtParser", "requireHttps"]) {
    assert.equal(answer(one(`app.use(${name});`, ROUTE)), "unsure:unreadable", name);
  }
  // `next(false)` and `next("router")` carry on too.
  assert.notEqual(answer(one('app.use((req, res, next) => { if (!req.user) return next(false); next(); });', ROUTE)), "check");
  assert.notEqual(answer(one('app.use((req, res, next) => { if (!req.user) return next("router"); next(); });', ROUTE)), "check");
  // ...while a sign-in pass still is.
  assert.equal(answer(one("app.use((req, res, next) => { const user = verifyToken(req.cookies.token); if (!user) return res.sendStatus(401); next(); });", ROUTE)), "check");
});

test("a step covers only pages after it, under its own address", () => {
  const check = "function requireMember(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }";
  assert.equal(answer(one(check, ROUTE, "app.use(requireMember);")), "open");
  assert.equal(answer(one(check, 'app.use("/api", requireMember);', 'app.get("/apiary", (req, res) => res.json(hives()));'), "/apiary"), "open");
  assert.equal(answer(one(check, 'app.use("/api", requireMember);', 'app.get("/api/orders", (req, res) => res.json(listOrders(req.user.id)));'), "/api/orders"), "check");
  assert.equal(answer(one(check, 'app.use(["/a", "/api"], requireMember);', 'app.get("/api/orders", (req, res) => res.json(listOrders(req.user.id)));'), "/api/orders"), "check");
  // The same check on another router in the same file does not count.
  assert.equal(answer(one(check, "const router = express.Router();", "router.use(requireMember);", ROUTE)), "open");
});

test("checks are followed into routers mounted after them and files handed the app", () => {
  const check = { path: "middleware/gate.js", content: "module.exports = function (req, res, next) { if (!req.user) return res.sendStatus(401); next(); };" };
  const router = { path: "routes/shop.js", content: ['const router = require("express").Router();', 'router.get("/cart", (req, res) => res.json(cartOf(req.user.id)));', "module.exports = router;"].join("\n") };
  const app = (...lines: string[]) => ({ path: "app.js", content: [...HEAD, ...lines].join("\n") });

  assert.equal(answer([app('app.use(require("./middleware/gate"));', 'app.use("/shop", require("./routes/shop"));'), check, router], "/cart"), "check");
  assert.equal(answer([app('const shop = require("./routes/shop");', 'app.use("/shop", shop);', 'app.use(require("./middleware/gate"));'), check, router], "/cart"), "open");
  // Mounted twice, once behind the check and once not.
  assert.equal(
    answer([app('const shop = require("./routes/shop");', 'app.use("/open", shop);', 'app.use(require("./middleware/gate"));', 'app.use("/shop", shop);'), check, router], "/cart"),
    "unsure:mounted-twice",
  );
  // The app handed to a routes file after the check.
  const handed = { path: "routes/index.js", content: ["module.exports = (app) => {", '  app.get("/statements", (req, res) => res.json(list(req.user.id)));', "};"].join("\n") };
  assert.equal(answer([app('app.use(require("./middleware/gate"));', 'require("./routes")(app);'), check, handed], "/statements"), "check");
  assert.equal(answer([app('require("./routes")(app);', 'app.use(require("./middleware/gate"));'), check, handed], "/statements"), "open");
  // A check whose router could not be followed: handed back, not reported open.
  assert.equal(answer([app('app.use(require("./middleware/gate"));', "for (const r of routers) app.use(r);"), check, router], "/cart"), "unsure:mount");
  // ...but only within the same package.
  assert.equal(
    answer([app('app.use(require("./middleware/gate"));'), check, { ...router, path: "other/routes/shop.js" }, { path: "other/package.json", content: "{}" }], "/cart"),
    "open",
  );
});

test("Hono: inline checks, and sub-apps mounted with app.route", () => {
  const hono = (...lines: string[]) => [{ path: "server/src/index.ts", content: ['import { Hono } from "hono";', "const app = new Hono();", ...lines].join("\n") }];
  assert.equal(answer(hono('app.use("/api/*", async (c, next) => { if (!c.get("user")) return c.json({ error: "Sign in" }, 401); await next(); });', 'app.get("/api/me", (c) => c.json(me(c.get("user"))));'), "/api/me"), "check");
  assert.equal(answer(hono('app.use("*", async (c, next) => { c.header("X-Frame-Options", "DENY"); await next(); });', 'app.get("/api/me", (c) => c.json(me(c.get("user"))));'), "/api/me"), "open");
  const sub = [
    "const apiRoutes = new Hono();",
    'apiRoutes.get("/me", (c) => c.json(me(c.get("user"))));',
    'app.use("/api/*", async (c, next) => { if (!c.get("user")) return c.json({ error: "Sign in" }, 401); await next(); });',
    'app.route("/api", apiRoutes);',
  ];
  assert.equal(answer(hono(...sub), "/me"), "check");
  const { jwt } = { jwt: 'import { jwt } from "hono/jwt";' };
  assert.equal(answer(hono(jwt, 'app.use("/api/*", jwt({ secret: KEY }));', 'app.get("/api/me", (c) => c.json(me(c.get("jwtPayload"))));'), "/api/me"), "check");
});

test("an unclear step is one 'needs your check' naming its pages, never a risk", async () => {
  const files = one(
    "app.use(checkpoint);",
    ROUTE,
    'app.get("/invoices", (req, res) => res.json(invoicesOf(req.session.userId)));',
    'app.post("/invoices", (req, res) => res.json(saveInvoice(req.session.userId)));',
  );
  const review = await runSecurityReview(snapshotFromFiles(files));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "access-control/unguarded-routes")!;
  assert.deepEqual(item.risks, []);
  assert.equal(item.status, "needs-your-review");
  const leads = item.unproven.filter((l) => l.id.startsWith("access-control/sign-in-unclear"));
  assert.equal(leads.length, 1);
  assert.match(leads[0]!.what, /`checkpoint` requires signing in before the page \/orders, the page \/invoices and the action \/invoices/);
  assert.match(leads[0]!.checkDetail ?? "", /GET \/orders, GET \/invoices, POST \/invoices/);
  for (const text of [leads[0]!.what, leads[0]!.why, leads[0]!.check]) assert.deepEqual(leakedJargon(text), [], text);
});

test("whose records an unclear page reaches is undecidable, not 'open to all'", () => {
  const inventory = inv(one("app.use(checkpoint);", 'app.get("/orders/:id", (req, res) => db.query("SELECT * FROM orders WHERE id = ?", [req.params.id]));'));
  assert.equal(verifyOwnership({ door: "/orders/:id", parameter: "id" }, inventory).verdict, "undecidable");
});
