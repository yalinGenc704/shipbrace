-- Per-repository choices. review_pushes: 1 reviews every push automatically
-- (the default, also when there is no row), 0 ignores pushes; a pasted link
-- still reviews on demand.
CREATE TABLE repo_settings (
  github_id      INTEGER PRIMARY KEY,
  review_pushes  INTEGER NOT NULL DEFAULT 1,
  changed_by     INTEGER,
  changed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
