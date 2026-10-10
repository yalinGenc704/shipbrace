// A deliberately flawed sample, used only to test the hosted setup end to end.
import { Hono } from "hono";
const app = new Hono();
app.get("/api/reports/:id", async (c) => {
  const id = c.req.param("id");
  return c.json(await db.query(`SELECT * FROM reports WHERE id = ${id}`));
});
