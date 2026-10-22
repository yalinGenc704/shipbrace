-- Who did what, and when, for actions that change who can do what or what
-- leaves the platform. Nothing in the app reads or edits it; it is for the
-- operator, through the Cloudflare dashboard. Kept a year (nightly job).
-- No foreign keys: a record outlives the person or installation it names.
CREATE TABLE audit_log (
  id      INTEGER PRIMARY KEY,
  at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor   INTEGER,
  action  TEXT NOT NULL,
  target  TEXT,
  detail  TEXT
);
CREATE INDEX audit_log_time_idx ON audit_log (at);
