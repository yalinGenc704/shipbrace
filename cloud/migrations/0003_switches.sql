-- Per-installation switches for what leaves the platform during a review.
-- The package check is on by default (the notices say so); the AI step is off
-- by default and can only be switched on once it is offered (AI_REVIEW=on).
ALTER TABLE installations ADD COLUMN package_lookup INTEGER NOT NULL DEFAULT 1;
ALTER TABLE installations ADD COLUMN ai_review INTEGER NOT NULL DEFAULT 0;
