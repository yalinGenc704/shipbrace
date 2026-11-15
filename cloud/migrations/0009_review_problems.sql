-- Reviews that stopped without a report: refused (a limit, too many files)
-- or failed. The GitHub check says why; this lets the dashboard say it too,
-- instead of waiting for a report that will never come. Only fixed text is
-- kept (no code, no file names). Kept for a week, and deleted with the
-- repository's history, the person's account, or the installation.
CREATE TABLE review_problems (
  id               INTEGER PRIMARY KEY,
  github_id        INTEGER NOT NULL,   -- the repository's GitHub id
  installation_id  INTEGER NOT NULL,
  ran_by           INTEGER,            -- who pushed or pasted, when known
  commit_sha       TEXT NOT NULL,
  title            TEXT NOT NULL,
  message          TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX review_problems_repo_idx ON review_problems (github_id, created_at);
CREATE INDEX review_problems_time_idx ON review_problems (created_at);
