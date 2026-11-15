import assert from "node:assert/strict";
import { test } from "node:test";
import { ALERT_SENDER, emailAlert } from "../src/alerts.ts";
import { alertLine } from "../src/audit.ts";

/** Records what would be sent. */
function fakeEmail() {
  const sent: Array<Record<string, any>> = [];
  return { binding: { send: async (m: Record<string, any>) => (sent.push(m), { messageId: "m1" }) } as unknown as SendEmail, sent };
}

test("the alert is emailed to the owner, from the one allowed sender, with counts only", async () => {
  const line = alertLine(new Map([["sign in", 6], ["clear history", 1]]))!;
  const { binding, sent } = fakeEmail();
  assert.equal(await emailAlert(binding, " owner@example.com ", line), "sent");
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.to, "owner@example.com");
  assert.equal(sent[0]!.from.email, ALERT_SENDER);
  assert.match(sent[0]!.text, /^SHIPBRACE-ALERT 7 refused attempts/);
  assert.match(sent[0]!.text, /6 x sign in, 1 x clear history/);
});

test("without the email service or an address, nothing is sent and nothing fails", async () => {
  const { binding, sent } = fakeEmail();
  assert.equal(await emailAlert(undefined, "owner@example.com", "x"), "not set up");
  assert.equal(await emailAlert(binding, undefined, "x"), "not set up");
  assert.equal(await emailAlert(binding, "  ", "x"), "not set up");
  assert.equal(sent.length, 0);
});

test("a quiet day sends nothing: under 5 refusals there is no alert line", () => {
  assert.equal(alertLine(new Map([["sign in", 4]])), null);
});

test("an email service that never answers is given up on, so the clean-up is not held up", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const hanging = { send: () => new Promise(() => {}) } as unknown as SendEmail;
  const attempt = emailAlert(hanging, "owner@example.com", "x");
  t.mock.timers.tick(15_000);
  await assert.rejects(attempt, /did not answer in time/);
});
