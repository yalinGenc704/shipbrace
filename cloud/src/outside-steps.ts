import { parseQuestions } from "@shipbrace/guardrails/cleaner-judge";
import { ProposerRefusedError } from "@shipbrace/guardrails/proposer";

/**
 * The steps a review may take outside its container: the AI's suggestions,
 * the AI's reading of the app's own cleaning functions, and the package lookup.
 */
export type OutsideStep = "propose" | "lookup" | "judge";

const STEPS: ReadonlySet<string> = new Set<OutsideStep>(["propose", "lookup", "judge"]);
export const isOutsideStep = (step: string): step is OutsideStep => STEPS.has(step);

/**
 * Whether a review may use an outside step now: only one it was allowed
 * before it started, and only once. No list recorded means nothing allowed.
 */
export function mayAsk(allowed: readonly string[] | undefined, alreadyAsked: boolean, step: string): boolean {
  return !alreadyAsked && (allowed ?? []).includes(step);
}

/** What the Worker sends back to the reviewer for one outside step. */
export interface StepAnswer {
  status: number;
  body: { value?: unknown; error?: "refused" | "failed" };
}

/** The part of a cleaner judge this needs; the real one talks to the model. */
interface Judge {
  judge(questions: NonNullable<ReturnType<typeof parseQuestions>>): Promise<Map<string, { protects: boolean; reason: string }>>;
}

/**
 * The `judge` step: the reviewer's questions about an app's own cleaning
 * functions, answered by a model.
 *
 * The questions come from the container that reads the repository, so they
 * are checked before anything is sent anywhere: the right shape, at most 30,
 * each capped in size (`parseQuestions`). Anything else is refused and no
 * model is called. A Map does not survive JSON, so the verdicts go back as
 * entries.
 */
export async function answerJudge(input: unknown, judge: Judge): Promise<StepAnswer> {
  const questions = parseQuestions(input);
  if (!questions) return { status: 400, body: { error: "failed" } };
  try {
    const verdicts = await judge.judge(questions);
    return { status: 200, body: { value: [...verdicts.entries()] } };
  } catch (error) {
    return { status: 502, body: { error: error instanceof ProposerRefusedError ? "refused" : "failed" } };
  }
}

/**
 * The body of a reviewer's request as text, or null when it is larger than
 * `maxBytes`. The bytes actually received are counted: the size the sender
 * claims is only used to refuse early, never trusted to let a body through.
 */
export async function readCapped(request: Request, maxBytes: number): Promise<string | null> {
  const claimed = request.headers.get("content-length");
  if (claimed !== null && !(/^\d{1,15}$/.test(claimed) && Number(claimed) <= maxBytes)) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.byteLength;
  }
  return new TextDecoder().decode(all);
}
