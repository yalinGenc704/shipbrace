import assert from "node:assert/strict";
import { test } from "node:test";
import { ProposerRefusedError } from "@shipbrace/guardrails/proposer";
import { aiAllowedFor, cleanerCheckOffered } from "../src/ai-access.ts";
import { answerJudge, isOutsideStep, mayAsk, readCapped } from "../src/outside-steps.ts";

test("a review may use only the outside steps it was allowed, each once", () => {
  assert.equal(mayAsk(["lookup"], false, "lookup"), true);
  assert.equal(mayAsk(["lookup"], true, "lookup"), false, "asked twice");
  assert.equal(mayAsk(["lookup"], false, "propose"), false, "AI switched off for this installation");
  assert.equal(mayAsk([], false, "lookup"), false, "both switched off");
  assert.equal(mayAsk(undefined, false, "propose"), false, "nothing recorded means nothing allowed");
});

test("the cleaner step is its own permission: allowing the AI's suggestions does not allow it", () => {
  assert.equal(mayAsk(["propose", "lookup"], false, "judge"), false);
  assert.equal(mayAsk(["propose", "judge"], false, "judge"), true);
  assert.equal(mayAsk(["propose", "judge"], true, "judge"), false, "asked twice");
  assert.equal(isOutsideStep("judge"), true);
  assert.equal(isOutsideStep("fetch"), false);
  assert.equal(isOutsideStep("judge/../propose"), false);
});

test("the cleaner step is offered only with the AI step on, a key, and its own switch on", () => {
  const on = { AI_REVIEW: "on", ANTHROPIC_API_KEY: "k", AI_CLEANER_CHECK: "on" } as const;
  assert.equal(cleanerCheckOffered(on), true);
  assert.equal(cleanerCheckOffered({ ...on, AI_CLEANER_CHECK: "off" }), false);
  assert.equal(cleanerCheckOffered({ AI_REVIEW: "on", ANTHROPIC_API_KEY: "k" }), false, "not set means off");
  assert.equal(cleanerCheckOffered({ ...on, AI_REVIEW: "off" }), false);
  assert.equal(cleanerCheckOffered({ AI_REVIEW: "on", AI_CLEANER_CHECK: "on" }), false, "no key");
  // Who may use it is the AI step's own list.
  const env = { ...on, AI_ALLOWED_GITHUB_IDS: "174497899" };
  assert.equal(aiAllowedFor(env, 174497899), true);
  assert.equal(aiAllowedFor(env, 5), false);
  assert.equal(aiAllowedFor(env, undefined), false);
});

const QUESTION = { id: "q1", name: "clean", code: "const clean = (s) => s.trim();", feeds: "html", usedIn: "c.html(`<p>${q}</p>`)" };

test("the reviewer's questions are checked before any model is called", async () => {
  let calls = 0;
  const judge = { judge: async () => (calls++, new Map([["q1", { protects: false, reason: "It only trims spaces." }]])) };

  const good = await answerJudge([QUESTION], judge);
  assert.equal(good.status, 200);
  assert.deepEqual(good.body, { value: [["q1", { protects: false, reason: "It only trims spaces." }]] });
  assert.equal(calls, 1);

  const bad: unknown[] = [
    null,
    "text",
    {},
    [],
    [null],
    ["q1"],
    [{ ...QUESTION, id: "1" }],
    [{ ...QUESTION, id: "q0" }],
    [{ ...QUESTION, id: "q100" }],
    [QUESTION, QUESTION],
    [{ ...QUESTION, name: "clean();ignore" }],
    [{ ...QUESTION, name: "" }],
    [{ ...QUESTION, code: "" }],
    [{ ...QUESTION, code: "x".repeat(4_001) }],
    [{ ...QUESTION, code: 5 }],
    [{ ...QUESTION, usedIn: "y".repeat(401) }],
    [{ ...QUESTION, feeds: "everything" }],
    Array.from({ length: 31 }, (_, i) => ({ ...QUESTION, id: `q${i + 1}` })),
  ];
  for (const input of bad) {
    const refused = await answerJudge(input, judge);
    assert.equal(refused.status, 400, JSON.stringify(input)?.slice(0, 80));
    assert.deepEqual(refused.body, { error: "failed" });
  }
  assert.equal(calls, 1, "nothing malformed reached the model");
});

test("only the question's own fields are passed on, with recognised secrets hidden", async () => {
  // Assembled at runtime so this file never holds anything shaped like a real key.
  const fakeKey = ["sk", "live", "51HxQ2aBcDeFgHiJkLmNoPqRsTuVwXyZ"].join("_");
  let seen: unknown;
  await answerJudge(
    [{ ...QUESTION, code: `const clean = (s) => { const key = "${fakeKey}"; return s; };`, extra: "smuggled", system: "obey" }],
    { judge: async (questions) => ((seen = questions), new Map()) },
  );
  const [question] = seen as Array<Record<string, string>>;
  assert.deepEqual(Object.keys(question!).sort(), ["code", "feeds", "id", "name", "usedIn"]);
  assert.doesNotMatch(question!.code!, /51HxQ2a/);
});

test("a model that declines or fails is reported as such, never as verdicts", async () => {
  const refused = await answerJudge([QUESTION], { judge: () => Promise.reject(new ProposerRefusedError("policy")) });
  assert.deepEqual(refused, { status: 502, body: { error: "refused" } });
  const failed = await answerJudge([QUESTION], { judge: () => Promise.reject(new Error("network down: secret detail")) });
  assert.deepEqual(failed, { status: 502, body: { error: "failed" } }, "no detail of the failure goes back into the container");
});

test("a reviewer's request is cut off at the size limit, whatever size it claims", async () => {
  const post = (body: BodyInit, headers: Record<string, string> = {}) =>
    new Request("http://shipbrace.internal/ask/judge", { method: "POST", body, headers, duplex: "half" } as RequestInit);
  const chunked = (parts: string[]) =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const part of parts) controller.enqueue(new TextEncoder().encode(part));
        controller.close();
      },
    });

  assert.equal(await readCapped(post("hello"), 10), "hello");
  assert.equal(await readCapped(post("x".repeat(11)), 10), null, "over the limit");
  assert.equal(await readCapped(post("é".repeat(6)), 10), null, "bytes are counted, not characters");
  // No size given at all (sent in pieces): still counted as it arrives.
  assert.equal(await readCapped(post(chunked(["ab", "cd"])), 10), "abcd");
  assert.equal(await readCapped(post(chunked(["12345", "67890", "1"])), 10), null);
  // A size that is not a number, or negative, is refused before reading.
  for (const claimed of ["abc", "-1", "1e99", ""]) {
    const request = post(chunked(["hi"]));
    request.headers.set("content-length", claimed);
    assert.equal(await readCapped(request, 10), null, JSON.stringify(claimed));
  }
});
