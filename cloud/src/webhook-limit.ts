import { bodyLimit } from "hono/body-limit";

/** GitHub's own limit for a webhook delivery is 25 MB; pushes are far smaller. */
export const MAX_WEBHOOK_BYTES = 5 * 1024 * 1024;

/**
 * Counts the bytes actually received, not the size the sender claims. A body
 * sent in chunks has no Content-Length at all, so trusting that header let
 * any amount through before the signature was even checked.
 */
export const webhookBodyLimit = bodyLimit({
  maxSize: MAX_WEBHOOK_BYTES,
  onError: (c) => c.json({ error: "Too large." }, 413),
});
