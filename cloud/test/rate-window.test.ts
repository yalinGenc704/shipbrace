import assert from "node:assert/strict";
import { test } from "node:test";
import { allowHit } from "../src/rate-window.ts";

test("at most the limit in any window, exactly, and refused tries do not extend the wait", () => {
  const times: number[] = [];
  for (let t = 0; t < 10; t++) assert.equal(allowHit(times, t * 100, 10, 60_000), true);
  assert.equal(allowHit(times, 1_000, 10, 60_000), false, "the eleventh within a minute is refused");
  assert.equal(allowHit(times, 59_999, 10, 60_000), false, "still within the minute of the first");
  assert.equal(allowHit(times, 60_000, 10, 60_000), true, "the first has left the window");
  assert.equal(times.length, 10);
});
