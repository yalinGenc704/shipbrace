import { Hono } from "hono";
import type { ReviewHistory } from "./history.ts";

/**
 * Reading past reviews back: one review, and one repository's list.
 *
 * The addresses are the only key (see history.ts), so every response is kept
 * out of caches and search engines, and an unknown address gets the same
 * answer as a malformed one -- nothing tells a guesser they were close.
 */
export function historyRoutes(history: ReviewHistory | null, log = console.error) {
  const routes = new Hono();

  routes.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
    c.header("X-Robots-Tag", "noindex");
  });

  routes.get("/reviews/:id", async (c) => {
    if (!history) return c.json({ error: "Review history is not configured." }, 503);
    try {
      const review = await history.review(c.req.param("id"));
      return review ? c.json(review) : c.json({ error: "No review at this address." }, 404);
    } catch (error) {
      log("could not read a stored review:", error);
      return c.json({ error: "The review could not be loaded." }, 500);
    }
  });

  routes.get("/history/:id", async (c) => {
    if (!history) return c.json({ error: "Review history is not configured." }, 503);
    try {
      const repository = await history.repository(c.req.param("id"));
      return repository ? c.json(repository) : c.json({ error: "No review history at this address." }, 404);
    } catch (error) {
      log("could not read a review history:", error);
      return c.json({ error: "The review history could not be loaded." }, 500);
    }
  });

  return routes;
}
