import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import { analyseTaint } from "../src/analysis/oracle.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const MODELS = {
  path: "server/models.js",
  content: 'const userSchema = new mongoose.Schema({ name: String, email: String, role: String });\nconst User = mongoose.model("User", userSchema);',
};
const operations = (handler: string) =>
  buildInventoryFromAst(snapshotFromFiles([MODELS, { path: "server/routes.js", content: `app.post("/signup", async (req, res) => {\n${handler}\n});` }]));
const flagged = (handler: string) => operations(handler).sinks.filter((s) => s.kind === "mass-assignment").length > 0;

test("the whole request saved as-is, directly or through plain copies, is mass assignment", () => {
  assert.ok(flagged("await User.create(req.body);"));
  assert.ok(flagged("const form = req.body; const data = form; await User.create(data);"));
  assert.ok(flagged("const form = req.body; await User.create({ ...form, name: 'x' });"));
  const paths = analyseTaint(operations("const data = req.body; await User.create(data);"));
  assert.ok(paths.some((p) => p.sink.kind === "mass-assignment" && p.verdict === "exploitable"));
});

test("anything that may have dropped fields on the way is not", () => {
  assert.ok(!flagged("const { name } = req.body; const data = { name }; await User.create(data);"));
  assert.ok(!flagged("const data = Signup.parse(req.body); await User.create(data);"));
  assert.ok(!flagged("const data = _.pick(req.body, ['name', 'email']); await User.create(data);"));
  assert.ok(!flagged("const { value } = Joi.validate(req.body, schema, { stripUnknown: true }); await User.create(value);"));
  assert.ok(!flagged("const form = req.body; await User.create({ ...form, role: 'member' });"));
  assert.ok(!flagged("const name = req.body.name; await User.create(name);"));
});

test("a field the app sets after spreading the request is not visitor text when read back", () => {
  const inventory = buildInventoryFromAst(snapshotFromFiles([MODELS, {
    path: "server/routes.js",
    content: [
      'app.post("/signup", async (req, res) => { const f = req.body; await User.create({ ...f, role: "member" }); res.end(); });',
      'app.get("/me", async (req, res) => { const u = await User.findOne(); res.redirect(u.role); });',
    ].join("\n"),
  }]));
  assert.deepEqual(inventory.sources.filter((s) => s.kind === "stored-data"), []);
});

test("a whole request checked first, trimmed, or saved by an admin is left alone", () => {
  assert.ok(!flagged("const r = Signup.strict().safeParse(req.body); if (!r.success) return res.sendStatus(400); await User.create(req.body);"));
  assert.ok(!flagged("const { error } = schema.validate(req.body); if (error) return res.sendStatus(400); await User.create(req.body);"));
  assert.ok(!flagged("const data = req.body; delete data.role; await User.create(data);"));
  const admin = buildInventoryFromAst(snapshotFromFiles([MODELS, {
    path: "server/routes.js",
    content: 'app.post("/admin/users", requireAdmin, async (req, res) => { await User.create(req.body); res.end(); });',
  }]));
  assert.deepEqual(admin.sinks.filter((s) => s.kind === "mass-assignment"), []);
  const middleware = buildInventoryFromAst(snapshotFromFiles([MODELS, {
    path: "server/routes.js",
    content: [
      "const check = (s) => (req, res, next) => { req.body = s.parse(req.body); next(); };",
      'app.post("/signup", check(Signup), async (req, res) => { await User.create(req.body); res.end(); });',
    ].join("\n"),
  }]));
  assert.deepEqual(middleware.sinks.filter((s) => s.kind === "mass-assignment"), []);
});

test("with no table definitions the checklist item says it could not judge", async () => {
  const { runSecurityReview } = await import("../src/review/pipeline.ts");
  const review = await runSecurityReview(snapshotFromFiles([
    { path: "server/routes.js", content: 'app.post("/signup", async (req, res) => { await User.create(req.body); res.end(); });' },
  ]));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "access-control/mass-assignment")!;
  assert.equal(item.status, "needs-your-review");
  assert.match(item.notApplicable ?? "", /No table definitions/);
});

test("a whole request saved into a table with a role field is reported", async () => {
  const { runSecurityReview } = await import("../src/review/pipeline.ts");
  const review = await runSecurityReview(snapshotFromFiles([
    MODELS,
    { path: "server/routes.js", content: 'app.post("/signup", async (req, res) => { await User.create(req.body); res.end(); });' },
  ]));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "access-control/mass-assignment")!;
  assert.equal(item.risks.length, 1);
});
