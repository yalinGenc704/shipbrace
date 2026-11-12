import Anthropic from "@anthropic-ai/sdk";
import { CLEANER_MODEL, createClaudeCleanerJudge } from "@shipbrace/guardrails/cleaner-judge";
import { createClaudeProposer, ProposerRefusedError } from "@shipbrace/guardrails/proposer";
import { createOsvSource } from "@shipbrace/guardrails/vulnerabilities";
import { Container, type OutboundHandlerContext } from "@cloudflare/containers";
import { cleanerCheckOffered } from "./ai-access.ts";
import type { Env } from "./env.ts";
import { answerJudge, isOutsideStep, mayAsk, readCapped, type OutsideStep } from "./outside-steps.ts";

/**
 * The review container: one per review, started for it and destroyed after.
 *
 * `enableInternet = false` leaves it no way out. The single exception is the
 * made-up host `shipbrace.internal`, whose requests Cloudflare hands to
 * `answer` below rather than to any network. That is how the reviewer asks for
 * the AI's suggestions, the AI's reading of the app's own cleaning functions,
 * and the package lookup -- and `answer` treats every
 * request as coming from code that might have been taken over: each step at
 * most once per review, only if switched on (on this deployment and for this
 * installation, recorded by `allow` before the review starts), with a size
 * limit.
 */
export class Reviewer extends Container<Env> {
  override defaultPort = 8080;
  override sleepAfter = "2m";
  override enableInternet = false;

  /**
   * The outside steps this review may use, set by the Worker from the
   * installation's switches before the review starts. Called over RPC; never
   * remove it or `claim`.
   */
  async allow(steps: OutsideStep[]): Promise<void> {
    await this.ctx.storage.put("allowed", steps);
  }

  /** True the first time a review asks for an allowed `step`; false otherwise and ever after. */
  async claim(step: string): Promise<boolean> {
    const key = `asked:${step}`;
    const allowed = await this.ctx.storage.get<OutsideStep[]>("allowed");
    if (!mayAsk(allowed, Boolean(await this.ctx.storage.get(key)), step)) return false;
    await this.ctx.storage.put(key, true);
    return true;
  }
}

const MAX_ASK_BYTES = 4 * 1024 * 1024;
const JUDGE_TIMEOUT_MS = 120_000;
const PROPOSE_TIMEOUT_MS = 5 * 60_000;
const reply = (body: unknown, status = 200) => Response.json(body, { status });

async function answer(request: Request, env: Env, ctx: OutboundHandlerContext): Promise<Response> {
  const step = new URL(request.url).pathname.replace(/^\/ask\//, "");
  if (request.method !== "POST" || !isOutsideStep(step)) return reply({ error: "failed" }, 404);

  const reviewer = env.REVIEWER.get(env.REVIEWER.idFromString(ctx.containerId));
  if (!(await reviewer.claim(step))) {
    console.error("reviewer asked for", step, "when not allowed or twice - refused");
    return reply({ error: "failed" }, 403);
  }

  // Counted as it arrives, after the step is claimed: an oversized ask has
  // used the review's one chance at this step.
  const raw = await readCapped(request, MAX_ASK_BYTES);
  if (raw === null) return reply({ error: "failed" }, 413);
  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    return reply({ error: "failed" }, 400);
  }

  if (step === "propose") {
    if (env.AI_REVIEW !== "on" || !env.ANTHROPIC_API_KEY) return reply({ error: "failed" }, 403);
    try {
      // A larger request to a larger model than the judge's, still bounded:
      // one retry, and no single try outlasts the review's own time limit.
      const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY, timeout: PROPOSE_TIMEOUT_MS, maxRetries: 1 });
      const proposer = createClaudeProposer(client as never);
      return reply({ value: await proposer.propose(input as never) });
    } catch (error) {
      return reply({ error: error instanceof ProposerRefusedError ? "refused" : "failed" }, 502);
    }
  }

  if (step === "judge") {
    if (!cleanerCheckOffered(env)) return reply({ error: "failed" }, 403);
    // Numbers only, for measuring what the step costs; never the code.
    let asked = 0;
    const counted = { input: 0, output: 0 };
    // A small request to a small model: answered in seconds or not at all.
    const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY, timeout: JUDGE_TIMEOUT_MS, maxRetries: 1 });
    const judge = createClaudeCleanerJudge(client as never, {
      model: CLEANER_MODEL,
      onUsage: (usage) => {
        counted.input += usage.input_tokens;
        counted.output += usage.output_tokens;
      },
    });
    const answered = await answerJudge(input, {
      judge: (questions) => {
        asked = questions.length;
        return judge.judge(questions);
      },
    });
    console.log(
      `cleaner check (${CLEANER_MODEL}): ${asked} functions asked, status ${answered.status}, ` +
        `${counted.input} input and ${counted.output} output tokens`,
    );
    return reply(answered.body, answered.status);
  }

  if (env.PACKAGE_LOOKUP !== "on") return reply({ error: "failed" }, 403);
  try {
    const found = await createOsvSource().lookup(input as never);
    return reply({ value: [...found.entries()] });
  } catch {
    return reply({ error: "failed" }, 502);
  }
}

Reviewer.outboundByHost = { "shipbrace.internal": answer as never };
