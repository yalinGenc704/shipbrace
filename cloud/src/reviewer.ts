import Anthropic from "@anthropic-ai/sdk";
import { createClaudeProposer, ProposerRefusedError } from "@aegis/guardrails/proposer";
import { createOsvSource } from "@aegis/guardrails/vulnerabilities";
import { Container, type OutboundHandlerContext } from "@cloudflare/containers";
import type { Env } from "./env.ts";

/**
 * The review container: one per review, started for it and destroyed after.
 *
 * `enableInternet = false` leaves it no way out. The single exception is the
 * made-up host `shipbrace.internal`, whose requests Cloudflare hands to
 * `answer` below rather than to any network. That is how the reviewer asks for
 * the AI's suggestions and the package lookup -- and `answer` treats every
 * request as coming from code that might have been taken over: each step at
 * most once per review, only if switched on, with a size limit.
 */
export class Reviewer extends Container<Env> {
  override defaultPort = 8080;
  override sleepAfter = "2m";
  override enableInternet = false;

  /** True the first time a review asks for `step`; false ever after. */
  async claim(step: string): Promise<boolean> {
    const key = `asked:${step}`;
    if (await this.ctx.storage.get(key)) return false;
    await this.ctx.storage.put(key, true);
    return true;
  }
}

const MAX_ASK_BYTES = 4 * 1024 * 1024;
const reply = (body: unknown, status = 200) => Response.json(body, { status });

async function answer(request: Request, env: Env, ctx: OutboundHandlerContext): Promise<Response> {
  const step = new URL(request.url).pathname.replace(/^\/ask\//, "");
  if (request.method !== "POST" || (step !== "propose" && step !== "lookup")) return reply({ error: "failed" }, 404);
  if (Number(request.headers.get("content-length") ?? MAX_ASK_BYTES + 1) > MAX_ASK_BYTES) return reply({ error: "failed" }, 413);

  const reviewer = env.REVIEWER.get(env.REVIEWER.idFromString(ctx.containerId));
  if (!(await reviewer.claim(step))) {
    console.error("reviewer asked twice for", step, "- refused");
    return reply({ error: "failed" }, 403);
  }

  let input: unknown;
  try {
    input = await request.json();
  } catch {
    return reply({ error: "failed" }, 400);
  }

  if (step === "propose") {
    if (env.AI_REVIEW !== "on" || !env.ANTHROPIC_API_KEY) return reply({ error: "failed" }, 403);
    try {
      const proposer = createClaudeProposer(new Anthropic({ apiKey: env.ANTHROPIC_API_KEY }) as never);
      return reply({ value: await proposer.propose(input as never) });
    } catch (error) {
      return reply({ error: error instanceof ProposerRefusedError ? "refused" : "failed" }, 502);
    }
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
