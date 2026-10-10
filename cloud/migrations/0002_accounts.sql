-- Sign-in with GitHub, the notices people accept before anything is sent
-- anywhere, and which App installations have been set up.

CREATE TABLE users (
  github_id        INTEGER PRIMARY KEY,
  login            TEXT NOT NULL,
  -- Which version of the notices this person accepted, and when. Null until
  -- they do; nothing is reviewed on their behalf before that.
  notice_version   TEXT,
  notice_at        TEXT,
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE sessions (
  -- SHA-256 of the cookie's value. The cookie itself is never stored, so a
  -- copy of this table does not let anyone sign in.
  id_hash           TEXT PRIMARY KEY,
  github_id         INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
  -- The person's GitHub token, encrypted with SESSION_KEY (AES-GCM). Used only
  -- to ask GitHub what this person may see.
  token             TEXT NOT NULL,
  token_expires_at  TEXT,
  refresh_token     TEXT,
  expires_at        TEXT NOT NULL,
  created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX sessions_user_idx ON sessions (github_id);

-- Pushes are reviewed only for installations someone has set up: signed in,
-- accepted the notices. Before that, nothing leaves the platform.
CREATE TABLE installations (
  installation_id  INTEGER PRIMARY KEY,
  set_up_by        INTEGER REFERENCES users(github_id) ON DELETE SET NULL,
  set_up_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Reviews started by pasting a link, for the per-person hourly limit.
CREATE TABLE review_requests (
  github_id     INTEGER NOT NULL,
  requested_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX review_requests_user_idx ON review_requests (github_id, requested_at);

-- So an uninstall can delete exactly that installation's reviews.
ALTER TABLE repositories ADD COLUMN installation_id INTEGER;
