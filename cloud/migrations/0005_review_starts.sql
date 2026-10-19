-- Every review started in a reviewer container, whether it finishes or not,
-- for the daily limits. `reviews` only holds the ones that finished and fit.
CREATE TABLE review_starts (
  installation_id  INTEGER NOT NULL,
  started_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX review_starts_time_idx ON review_starts (started_at);
CREATE INDEX review_starts_installation_idx ON review_starts (installation_id, started_at);
