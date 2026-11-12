-- Each message GitHub sends has its own id (the X-GitHub-Delivery header),
-- and a repeated delivery of the same message carries the same id. Kept for a
-- week, so a push that arrives twice is reviewed, and counted, once.
CREATE TABLE webhook_deliveries (
  id           TEXT PRIMARY KEY,
  received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX webhook_deliveries_time_idx ON webhook_deliveries (received_at);
