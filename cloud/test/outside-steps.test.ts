import assert from "node:assert/strict";
import { test } from "node:test";
import { mayAsk } from "../src/outside-steps.ts";

test("a review may use only the outside steps it was allowed, each once", () => {
  assert.equal(mayAsk(["lookup"], false, "lookup"), true);
  assert.equal(mayAsk(["lookup"], true, "lookup"), false, "asked twice");
  assert.equal(mayAsk(["lookup"], false, "propose"), false, "AI switched off for this installation");
  assert.equal(mayAsk([], false, "lookup"), false, "both switched off");
  assert.equal(mayAsk(undefined, false, "propose"), false, "nothing recorded means nothing allowed");
});
