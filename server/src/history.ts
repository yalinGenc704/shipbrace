import { LINK_ID, newLinkId } from "./links.ts";
import type { ReviewResult } from "@shipbrace/guardrails";
import postgres from "postgres";
import type { Conclusion } from "./github/report.ts";

/**
 * Past reviews of each repository, kept in PostgreSQL.
 *
 * A review stays the record of one commit: it is written once, when the review
 * finishes, and never updated. So an old result can never be mistaken for a
 * current one -- every entry says which commit it describes and when.
 *
 * There is no sign-in yet, so the pages are reached by unguessable links
 * instead: each review and each repository's history has a random 144-bit
 * address. The GitHub check links to them, so the people who can see the
 * check -- those with access to the repository -- are the ones who get the
 * link. This is a stopgap until accounts exist, not a substitute for them.
 */

export interface Skipped {
  notReadable: number;
  tooLarge: number;
  overLimit: number;
  treeTruncated: boolean;
}

export interface NewReview {
  /** GitHub's repository id. Unlike the name, it survives renames and transfers. */
  githubId: number;
  /** The App installation it came through, so an uninstall can delete it. */
  installationId?: number;
  /** GitHub id of the person who started it: who pushed, or who pasted the link. */
  ranBy?: number;
  owner: string;
  repo: string;
  commitSha: string;
  conclusion: Conclusion;
  title: string;
  result: ReviewResult;
  skipped: Skipped;
}

export interface ReviewEntry {
  id: string;
  commitSha: string;
  createdAt: string;
  conclusion: Conclusion;
  title: string;
  counts: { high: number; medium: number; low: number; awaitingReview: number; unproven: number };
}

export interface StoredReview extends ReviewEntry {
  repository: { owner: string; name: string; historyId: string };
  result: ReviewResult;
  skipped: Skipped;
}

export interface RepositoryHistory {
  owner: string;
  name: string;
  reviews: ReviewEntry[];
}

export interface ReviewHistory {
  record(review: NewReview): Promise<{ reviewId: string; historyId: string }>;
  review(id: string): Promise<StoredReview | null>;
  repository(historyId: string): Promise<RepositoryHistory | null>;
  close(): Promise<void>;
}

export { LINK_ID, newLinkId } from "./links.ts";

/** The newest reviews shown on a repository's page. */
const HISTORY_LIMIT = 100;

/**
 * Schema changes, applied in order and never edited once released: a new
 * change is a new entry. Each runs once, inside a transaction, recorded in
 * `schema_migrations`.
 */
const MIGRATIONS: string[] = [
  `CREATE TABLE repositories (
     id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
     github_id     bigint NOT NULL UNIQUE,
     owner         text NOT NULL,
     name          text NOT NULL,
     history_id    text NOT NULL UNIQUE,
     created_at    timestamptz NOT NULL DEFAULT now()
   );

   CREATE TABLE reviews (
     id             text PRIMARY KEY,
     repository_id  bigint NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
     commit_sha     text NOT NULL,
     conclusion     text NOT NULL CHECK (conclusion IN ('success', 'neutral', 'failure')),
     title          text NOT NULL,
     high           integer NOT NULL,
     medium         integer NOT NULL,
     low            integer NOT NULL,
     awaiting       integer NOT NULL,
     unproven       integer NOT NULL,
     result         jsonb NOT NULL,
     skipped        jsonb NOT NULL,
     created_at     timestamptz NOT NULL DEFAULT now()
   );

   CREATE INDEX reviews_repository_newest_idx ON reviews (repository_id, created_at DESC);`,
];

/**
 * Inside a transaction the connection is still called `sql`, not `tx`: the
 * review's query check recognises a parameterised query by that name, and this
 * file should pass the checks it applies to everyone else.
 */
type Sql = postgres.Sql;

/**
 * Brings the database up to date. Safe to run on every start, and from two
 * servers at once: the advisory lock makes the second wait for the first.
 */
export async function migrate(sql: Sql): Promise<void> {
  await sql.begin(async (sql) => {
    await sql`SELECT pg_advisory_xact_lock(hashtext('shipbrace.migrate'))`;
    await sql`CREATE TABLE IF NOT EXISTS schema_migrations (
      version    integer PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`;
    const [row] = await sql<{ version: number | null }[]>`SELECT max(version) AS version FROM schema_migrations`;
    const current = row?.version ?? 0;
    for (let version = current + 1; version <= MIGRATIONS.length; version++) {
      await sql.unsafe(MIGRATIONS[version - 1]!);
      await sql`INSERT INTO schema_migrations (version) VALUES (${version})`;
    }
  });
}

/**
 * The connection is opened here and nowhere else. Values interpolated into
 * sql`...` are always sent as parameters, never spliced into the query text;
 * the one `unsafe` call above runs this file's own fixed migrations.
 */
export function connect(databaseUrl: string): Sql {
  return postgres(databaseUrl, { max: 5, idle_timeout: 20, onnotice: () => {} });
}

interface ReviewRow {
  id: string;
  commit_sha: string;
  created_at: Date;
  conclusion: Conclusion;
  title: string;
  high: number;
  medium: number;
  low: number;
  awaiting: number;
  unproven: number;
}

const entry = (row: ReviewRow): ReviewEntry => ({
  id: row.id,
  commitSha: row.commit_sha,
  createdAt: row.created_at.toISOString(),
  conclusion: row.conclusion,
  title: row.title,
  counts: {
    high: row.high,
    medium: row.medium,
    low: row.low,
    awaitingReview: row.awaiting,
    unproven: row.unproven,
  },
});

export function postgresHistory(sql: Sql): ReviewHistory {
  return {
    async record(review) {
      const { high, medium, low, awaitingReview, unproven } = review.result.summary;
      return sql.begin(async (sql) => {
        // The name is refreshed on every push, so a renamed repository shows
        // its current name while keeping its history and its link.
        const [repository] = await sql<{ id: string; history_id: string }[]>`
          INSERT INTO repositories (github_id, owner, name, history_id)
          VALUES (${review.githubId}, ${review.owner}, ${review.repo}, ${newLinkId()})
          ON CONFLICT (github_id) DO UPDATE SET owner = EXCLUDED.owner, name = EXCLUDED.name
          RETURNING id, history_id`;
        const reviewId = newLinkId();
        await sql`
          INSERT INTO reviews (id, repository_id, commit_sha, conclusion, title,
                               high, medium, low, awaiting, unproven, result, skipped)
          VALUES (${reviewId}, ${repository!.id}, ${review.commitSha}, ${review.conclusion}, ${review.title},
                  ${high}, ${medium}, ${low}, ${awaitingReview}, ${unproven},
                  ${sql.json(review.result as never)}, ${sql.json(review.skipped as never)})`;
        return { reviewId, historyId: repository!.history_id };
      });
    },

    async review(id) {
      if (!LINK_ID.test(id)) return null;
      const [row] = await sql<(ReviewRow & { result: ReviewResult; skipped: Skipped; owner: string; name: string; history_id: string })[]>`
        SELECT r.*, p.owner, p.name, p.history_id
        FROM reviews r JOIN repositories p ON p.id = r.repository_id
        WHERE r.id = ${id}`;
      if (!row) return null;
      return {
        ...entry(row),
        repository: { owner: row.owner, name: row.name, historyId: row.history_id },
        result: row.result,
        skipped: row.skipped,
      };
    },

    async repository(historyId) {
      if (!LINK_ID.test(historyId)) return null;
      const [repository] = await sql<{ id: string; owner: string; name: string }[]>`
        SELECT id, owner, name FROM repositories WHERE history_id = ${historyId}`;
      if (!repository) return null;
      const rows = await sql<ReviewRow[]>`
        SELECT id, commit_sha, created_at, conclusion, title, high, medium, low, awaiting, unproven
        FROM reviews WHERE repository_id = ${repository.id}
        ORDER BY created_at DESC, id
        LIMIT ${HISTORY_LIMIT}`;
      return { owner: repository.owner, name: repository.name, reviews: rows.map(entry) };
    },

    close: () => sql.end({ timeout: 5 }),
  };
}
