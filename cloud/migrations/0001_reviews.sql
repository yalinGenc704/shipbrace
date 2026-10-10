-- Review history on Cloudflare D1 (SQLite). Same shape as the PostgreSQL
-- schema in server/src/history.ts; see that file for why it looks like this.

CREATE TABLE repositories (
  id          INTEGER PRIMARY KEY,
  github_id   INTEGER NOT NULL UNIQUE,
  owner       TEXT NOT NULL,
  name        TEXT NOT NULL,
  history_id  TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE reviews (
  id             TEXT PRIMARY KEY,
  repository_id  INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  commit_sha     TEXT NOT NULL,
  conclusion     TEXT NOT NULL CHECK (conclusion IN ('success', 'neutral', 'failure')),
  title          TEXT NOT NULL,
  high           INTEGER NOT NULL,
  medium         INTEGER NOT NULL,
  low            INTEGER NOT NULL,
  awaiting       INTEGER NOT NULL,
  unproven       INTEGER NOT NULL,
  -- JSON text. D1 caps a row at 2 MB; history-d1.ts refuses anything larger.
  result         TEXT NOT NULL,
  skipped        TEXT NOT NULL,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX reviews_repository_newest_idx ON reviews (repository_id, created_at DESC);
