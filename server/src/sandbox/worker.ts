import {
  ProposerRefusedError,
  runSecurityReview,
  type AttackProposer,
  type RepoSnapshot,
  type VulnerabilitySource,
} from "@aegis/guardrails";

/**
 * The sealed side of a review: runs in its own process, started by
 * `sandboxedReview`, with no secrets, no network, no files beyond Aegis's own
 * code, and a time and memory limit (see sandbox.ts).
 *
 * Everything that reads the repository runs here. The two steps that need the
 * outside world -- the AI's suggestions and the package lookup -- are asked of
 * the parent over the process channel, so the key and the network stay there.
 */

export type ToWorker =
  | {
      type: "review";
      snapshot: RepoSnapshot;
      /** Present when the parent will answer for that step. */
      proposer?: { name: string };
      vulnerabilities?: { notice: string };
    }
  | { type: "answer"; id: number; value?: unknown; error?: "refused" | "failed" };

export type FromWorker =
  | { type: "ask"; id: number; step: "propose" | "lookup"; input: unknown }
  | { type: "done"; result: Awaited<ReturnType<typeof runSecurityReview>> }
  | { type: "failed" };

const send = (message: FromWorker) => process.send!(message);

let nextId = 0;
const waiting = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();

function ask(step: "propose" | "lookup", input: unknown): Promise<unknown> {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject });
    send({ type: "ask", id, step, input });
  });
}

process.on("message", async (message: ToWorker) => {
  if (message.type === "answer") {
    const pending = waiting.get(message.id);
    waiting.delete(message.id);
    if (!pending) return;
    if (message.error === "refused") pending.reject(new ProposerRefusedError("The model declined."));
    else if (message.error) pending.reject(new Error("The parent could not complete this step."));
    else pending.resolve(message.value);
    return;
  }

  const proposer: AttackProposer | undefined = message.proposer && {
    name: message.proposer.name,
    propose: (context) => ask("propose", context) as ReturnType<AttackProposer["propose"]>,
  };
  const vulnerabilities: VulnerabilitySource | undefined = message.vulnerabilities && {
    notice: message.vulnerabilities.notice,
    lookup: (dependencies) => ask("lookup", dependencies) as ReturnType<VulnerabilitySource["lookup"]>,
  };

  try {
    const result = await runSecurityReview(message.snapshot, {
      ...(proposer ? { proposer } : {}),
      ...(vulnerabilities ? { vulnerabilities } : {}),
    });
    send({ type: "done", result });
  } catch {
    // The detail could quote the repository; the parent only needs to know.
    send({ type: "failed" });
  }
});
