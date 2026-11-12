import assert from "node:assert/strict";
import { test } from "node:test";
import { alertLine, record, refusedLastDay, REFUSED_ALERT_AT } from "../src/audit.ts";
import { firstDelivery, forgetOldDeliveries, queueOnce } from "../src/deliveries.ts";
import { fakeD1 } from "./fake-d1.ts";

const ID = "8c1f6a52-9d3e-4b7a-a1c2-0f9e8d7c6b5a";

test("a message GitHub delivers twice starts one review, not two", async () => {
  const db = fakeD1();
  assert.equal(await firstDelivery(db, ID), true);
  assert.equal(await firstDelivery(db, ID), false, "the repeat");
  assert.equal(await firstDelivery(db, ID.toUpperCase()), false, "the same id in capitals");
  assert.equal(await firstDelivery(db, "0c1f6a52-9d3e-4b7a-a1c2-0f9e8d7c6b5a"), true, "another push");
});

test("a message with no usable id is still reviewed, and nothing odd is remembered", async () => {
  const db = fakeD1();
  for (const id of [undefined, "", "not-an-id", `${ID}'; DROP TABLE reviews; --`, "x".repeat(5000)]) {
    assert.equal(await firstDelivery(db, id), true);
    assert.equal(await firstDelivery(db, id), true);
  }
  const kept = await db.prepare("SELECT count(*) AS n FROM webhook_deliveries").first<{ n: number }>();
  assert.equal(kept?.n, 0);
});

test("delivery ids are forgotten after a week", async () => {
  const db = fakeD1();
  await firstDelivery(db, ID);
  await db.prepare("UPDATE webhook_deliveries SET received_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-8 days')").run();
  await forgetOldDeliveries(db).run();
  assert.equal(await firstDelivery(db, ID), true, "seen as new again");
});

test("a few refusals are normal; many in a day write one alert line", async () => {
  const db = fakeD1();
  for (let i = 0; i < REFUSED_ALERT_AT - 1; i++) await record(db, { action: "refused", detail: { attempt: "sign in" } });
  assert.equal(alertLine(await refusedLastDay(db)), null);

  await record(db, { actor: 5, action: "refused", target: 7, detail: { attempt: "change switches" } });
  await record(db, { actor: 5, action: "refused", target: 7, detail: { attempt: "clear history" } });
  // Not refusals, and an old one: none of these count.
  await record(db, { actor: 5, action: "sign-in", target: "ada" });
  await record(db, { action: "refused", detail: { attempt: "sign in" } });
  await db.prepare("UPDATE audit_log SET at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 days') WHERE id = (SELECT max(id) FROM audit_log)").run();

  const line = alertLine(await refusedLastDay(db));
  assert.equal(line, `SHIPBRACE-ALERT ${REFUSED_ALERT_AT + 1} refused attempts in the last 24 hours (4 x sign in, 1 x change switches, 1 x clear history). See the audit_log table for who and when.`);
});

test("the alert line holds counts and fixed words only", async () => {
  const db = fakeD1();
  for (let i = 0; i < REFUSED_ALERT_AT; i++) {
    await db.prepare("INSERT INTO audit_log (action, detail) VALUES ('refused', ?)").bind(i === 0 ? "not json" : JSON.stringify({ attempt: "<script>alert(1)</script> https://evil.example" })).run();
  }
  assert.equal(alertLine(await refusedLastDay(db)), `SHIPBRACE-ALERT ${REFUSED_ALERT_AT} refused attempts in the last 24 hours (${REFUSED_ALERT_AT} x other). See the audit_log table for who and when.`);
});

test("a push whose queueing failed can be delivered again", async () => {
  const db = fakeD1();
  let sent = 0;
  await assert.rejects(queueOnce(db, ID, () => Promise.reject(new Error("queue down"))));
  assert.equal(await queueOnce(db, ID, async () => void sent++), true, "Redeliver starts the review");
  assert.equal(await queueOnce(db, ID, async () => void sent++), false, "and a further repeat does not");
  assert.equal(sent, 1);
});

test("if the ids cannot be checked at all, the push is reviewed rather than dropped", async () => {
  const broken = { prepare: () => ({ bind: () => ({ run: () => Promise.reject(new Error("no such table")) }) }) } as unknown as D1Database;
  let sent = 0;
  assert.equal(await queueOnce(broken, ID, async () => void sent++), true);
  assert.equal(sent, 1);
});
