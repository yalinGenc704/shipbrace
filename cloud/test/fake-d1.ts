import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

/**
 * Just enough of Cloudflare's D1 for tests, on Node's built-in SQLite (D1 is
 * SQLite too), with this project's real migrations applied.
 */
export function fakeD1(): D1Database {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  const dir = new URL("../migrations/", import.meta.url);
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    sqlite.exec(readFileSync(new URL(file, dir), "utf8"));
  }

  const statement = (sql: string, params: unknown[] = []) => ({
    bind: (...values: unknown[]) => statement(sql, values),
    first: async <T>() => (sqlite.prepare(sql).get(...(params as never[])) ?? null) as T | null,
    all: async <T>() => ({ results: sqlite.prepare(sql).all(...(params as never[])) as T[] }),
    run: async () => {
      const info = sqlite.prepare(sql).run(...(params as never[]));
      return { meta: { changes: info.changes } };
    },
  });

  return {
    prepare: (sql: string) => statement(sql),
    batch: async (statements: Array<{ run: () => Promise<unknown> }>) => {
      sqlite.exec("BEGIN");
      try {
        const out = [];
        for (const s of statements) out.push(await s.run());
        sqlite.exec("COMMIT");
        return out;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    },
  } as unknown as D1Database;
}
