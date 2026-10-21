import assert from "node:assert/strict";
import { test } from "node:test";
import { modelFields } from "../src/analysis/schemas.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const fields = (path: string, content: string) => modelFields(snapshotFromFiles([{ path, content }]));

test("reads fields from Prisma, SQL, Mongoose, Sequelize and Drizzle", () => {
  assert.deepEqual(fields("prisma/schema.prisma", "model Post {\n  id Int @id\n  title String\n  authorId Int\n}\n").get("post")?.sensitive, ["authorid"]);
  assert.deepEqual(
    fields("db/001.sql", "CREATE TABLE IF NOT EXISTS users (\n  id SERIAL PRIMARY KEY,\n  name VARCHAR(255),\n  role TEXT,\n  PRIMARY KEY (id)\n);").get("user")?.fields,
    ["id", "name", "role"],
  );
  assert.deepEqual(fields("m.js", 'const s = new Schema({ text: String }); mongoose.model("Note", s);').get("note")?.fields, ["text"]);
  assert.deepEqual(fields("m.js", 'sequelize.define("Account", { balance: DataTypes.INTEGER });').get("account")?.sensitive, ["balance"]);
  assert.deepEqual(fields("m.ts", "class Team extends Model {}\nTeam.init({ plan: DataTypes.STRING }, { sequelize });").get("team")?.sensitive, ["plan"]);
  assert.deepEqual(fields("m.ts", 'export const orders = pgTable("orders", { id: serial("id"), userId: integer("user_id") });').get("order")?.sensitive, ["userid"]);
});

test("a table with no sensitive field has none, and unknown tables are absent", () => {
  const found = fields("prisma/schema.prisma", "model Feedback {\n  id Int @id\n  message String\n}\n");
  assert.deepEqual(found.get("feedback")?.sensitive, []);
  assert.equal(found.get("user"), undefined);
});
