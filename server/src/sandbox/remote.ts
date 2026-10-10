import { connect } from "node:net";
import type { ReviewResult } from "@aegis/guardrails";
import { MAX_FROM_REVIEWER, receive, send } from "./channel.ts";
import { ReviewStoppedError, type Review } from "./sandbox.ts";

/**
 * The server's side of the review container (see reviewer.ts).
 *
 * The container is the side that reads hostile code, so everything it sends
 * is treated as untrusted: replies are size-capped JSON, the AI step and the
 * package lookup are each answered at most once per review, a stop reason
 * must be one this server knows, and the whole exchange has a time limit
 * whatever the container claims.
 */

const STOP_REASONS = new Set(["time", "memory", "crash", "busy", "unavailable"]);
const MAX_WALL_MS = 20 * 60_000;

type FromReviewer =
  | { type: "ask"; id: number; step: "propose" | "lookup"; input: unknown }
  | { type: "done"; result: ReviewResult }
  | { type: "stopped"; reason: string }
  | { type: "failed" };

export function createRemoteReviewer(socketPath: string, log: (message: string) => void = console.error): Review {
  return (snapshot, options = {}) =>
    new Promise<ReviewResult>((resolve, reject) => {
      const socket = connect(socketPath);
      const asked = new Set<string>();
      let settled = false;

      const finish = (outcome: { result: ReviewResult } | { error: Error }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if ("result" in outcome) resolve(outcome.result);
        else reject(outcome.error);
      };
      const timer = setTimeout(() => finish({ error: new ReviewStoppedError("time") }), MAX_WALL_MS);

      socket.on("connect", () =>
        send(
          socket,
          {
            type: "review",
            snapshot,
            ...(options.proposer ? { proposer: { name: options.proposer.name } } : {}),
            ...(options.vulnerabilities ? { vulnerabilities: { notice: options.vulnerabilities.notice } } : {}),
          },
          "v8",
        ),
      );

      receive(
        socket,
        "json",
        MAX_FROM_REVIEWER,
        (raw) => {
          const message = raw as FromReviewer;
          if (message?.type === "done" && isReviewResult(message.result)) return finish({ result: message.result });
          if (message?.type === "stopped" && STOP_REASONS.has(message.reason)) {
            return finish({ error: new ReviewStoppedError(message.reason as never) });
          }
          if (message?.type === "failed") return finish({ error: new Error("the review failed inside the review service") });

          const step =
            message?.type === "ask" && !asked.has(message.step)
              ? message.step === "propose"
                ? options.proposer && (() => options.proposer!.propose(message.input as never))
                : message.step === "lookup"
                ? options.vulnerabilities && (() => options.vulnerabilities!.lookup(message.input as never))
                : undefined
              : undefined;
          if (!step || message.type !== "ask") {
            log("reviewer: unexpected message; stopping the review");
            return finish({ error: new ReviewStoppedError("crash") });
          }
          asked.add(message.step);
          const id = message.id;
          step().then(
            (value) => !settled && send(socket, { type: "answer", id, value }, "v8"),
            (error: unknown) =>
              !settled &&
              send(
                socket,
                { type: "answer", id, error: error instanceof Error && error.name === "ProposerRefusedError" ? "refused" : "failed" },
                "v8",
              ),
          );
        },
        (why) => {
          log(`reviewer: ${why}; stopping the review`);
          finish({ error: new ReviewStoppedError("crash") });
        },
      );

      socket.on("error", (error: NodeJS.ErrnoException) => {
        const down = error.code === "ENOENT" || error.code === "ECONNREFUSED";
        if (down) log(`reviewer: not reachable at ${socketPath}`);
        finish({ error: new ReviewStoppedError(down ? "unavailable" : "crash") });
      });
      socket.on("close", () => finish({ error: new ReviewStoppedError("crash") }));
    });
}

function isReviewResult(value: unknown): value is ReviewResult {
  const r = value as ReviewResult;
  return typeof r === "object" && r !== null && Array.isArray(r.modules) && typeof r.summary === "object" && typeof r.stats === "object";
}
