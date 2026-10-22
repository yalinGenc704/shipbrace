import assert from "node:assert/strict";
import { test } from "node:test";
import { Hono } from "hono";
import { MAX_WEBHOOK_BYTES, webhookBodyLimit } from "../src/webhook-limit.ts";

const app = new Hono().post("/hook", webhookBodyLimit, async (c) => c.text(String((await c.req.text()).length)));

/** A body sent in pieces, with no Content-Length header at all. */
function chunked(bytes: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent >= bytes) return controller.close();
      const piece = Math.min(64 * 1024, bytes - sent);
      sent += piece;
      controller.enqueue(new Uint8Array(piece));
    },
  });
}

const send = (body: ReadableStream<Uint8Array> | string) =>
  app.request("/hook", { method: "POST", body, ...(typeof body === "string" ? {} : { duplex: "half" }) } as RequestInit);

test("a webhook body is limited by the bytes received, even with no Content-Length", async () => {
  assert.equal((await send(chunked(MAX_WEBHOOK_BYTES + 1))).status, 413);
  assert.equal((await send(chunked(1024))).status, 200);
  assert.equal((await send("{}")).status, 200);
});
