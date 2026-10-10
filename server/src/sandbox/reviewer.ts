import { chmodSync, rmSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import {
  ProposerRefusedError,
  type AttackProposer,
  type RepoSnapshot,
  type ReviewOptions,
  type VulnerabilitySource,
} from "@aegis/guardrails";
import { MAX_TO_REVIEWER, receive, send } from "./channel.ts";
import { createSandbox, ReviewStoppedError, type Review } from "./sandbox.ts";

/**
 * The review container's program (hosting only; see compose.yaml).
 *
 * It runs where there is no network at all, a read-only disk and a memory
 * cap, and listens on a Unix socket shared with the server. Each connection
 * is one review, run by the same sandbox as on a laptop -- a fresh process
 * per review, with Node's permission model inside the container's walls. The
 * AI step and the package lookup are asked of the server over the same
 * connection, so the key and the network stay on the other side.
 */

type FromServer =
  | { type: "review"; snapshot: RepoSnapshot; proposer?: { name: string }; vulnerabilities?: { notice: string } }
  | { type: "answer"; id: number; value?: unknown; error?: "refused" | "failed" };

export function serveReviews(socketPath: string, review: Review = createSandbox()) {
  const server = createServer((socket) => handle(socket, review));
  rmSync(socketPath, { force: true });
  server.listen(socketPath, () => {
    // The server's container shares the socket's group; nobody else may connect.
    chmodSync(socketPath, 0o660);
  });
  return server;
}

function handle(socket: Socket, review: Review): void {
  let nextId = 0;
  const waiting = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  let started = false;

  const ask = (step: "propose" | "lookup", input: unknown) =>
    new Promise<unknown>((resolve, reject) => {
      const id = nextId++;
      waiting.set(id, { resolve, reject });
      send(socket, { type: "ask", id, step, input }, "json");
    });

  receive(socket, "v8", MAX_TO_REVIEWER, async (raw) => {
    const message = raw as FromServer;
    if (message.type === "answer") {
      const pending = waiting.get(message.id);
      waiting.delete(message.id);
      if (!pending) return;
      if (message.error === "refused") pending.reject(new ProposerRefusedError("The model declined."));
      else if (message.error) pending.reject(new Error("The server could not complete this step."));
      else pending.resolve(message.value);
      return;
    }
    if (message.type !== "review" || started) return socket.destroy();
    started = true;

    const options: ReviewOptions = {};
    if (message.proposer) {
      options.proposer = {
        name: message.proposer.name,
        propose: (context) => ask("propose", context) as ReturnType<AttackProposer["propose"]>,
      };
    }
    if (message.vulnerabilities) {
      options.vulnerabilities = {
        notice: message.vulnerabilities.notice,
        lookup: (dependencies) => ask("lookup", dependencies) as ReturnType<VulnerabilitySource["lookup"]>,
      };
    }

    try {
      const result = await review(message.snapshot, options);
      send(socket, { type: "done", result }, "json");
    } catch (error) {
      send(socket, error instanceof ReviewStoppedError ? { type: "stopped", reason: error.reason } : { type: "failed" }, "json");
    }
    socket.end();
  }, () => socket.destroy());

  socket.on("error", () => {});
}

if (import.meta.main) {
  const path = process.env.REVIEWER_SOCKET ?? "/run/aegis/reviewer.sock";
  serveReviews(path);
  console.log(`reviewer listening on ${path}`);
}
