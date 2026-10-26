import { createServer, type IncomingMessage } from "node:http";
import {
  ProposerRefusedError,
  snapshotFromFiles,
  type AttackProposer,
  type ReviewOptions,
  type VulnerabilitySource,
} from "@shipbrace/guardrails";
import { createSandbox, ReviewStoppedError, type Review } from "./sandbox.ts";

/**
 * The reviewer as Cloudflare runs it: one container per review, with internet
 * access switched off (cloud/src/reviewer.ts). It answers one request --
 * "review these files" -- using the same sandbox as everywhere else, so inside
 * the container each review still runs in its own sealed process.
 *
 * The AI step and the package lookup are asked of `http://shipbrace.internal`.
 * That address is not on the internet: Cloudflare hands every request to it to
 * the Worker, which decides whether to answer (at most once per step, per
 * review). Every other address simply has no way out.
 */

export interface ReviewRequest {
  files: Array<{ path: string; content: string }>;
  tracked: string[];
  /** Files that exist but were not read; see `RepoSnapshot.unread`. */
  unread?: string[];
  incomplete?: boolean;
  proposer?: { name: string };
  vulnerabilities?: { notice: string };
}

export type ReviewReply =
  | { type: "done"; result: Awaited<ReturnType<Review>> }
  | { type: "stopped"; reason: string }
  | { type: "failed" };

const ASK = "http://shipbrace.internal/ask";
/** Matches the largest snapshot a review reads (32 MB), with room for JSON. */
const MAX_REQUEST_BYTES = 96 * 1024 * 1024;

async function ask(step: "propose" | "lookup", input: unknown): Promise<unknown> {
  const response = await fetch(`${ASK}/${step}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  const body = (await response.json()) as { value?: unknown; error?: "refused" | "failed" };
  if (body.error === "refused") throw new ProposerRefusedError("The model declined.");
  if (!response.ok || body.error) throw new Error("The Worker could not complete this step.");
  return body.value;
}

export async function handleReview(request: ReviewRequest, review: Review): Promise<ReviewReply> {
  const options: ReviewOptions = {};
  if (request.proposer) {
    options.proposer = {
      name: request.proposer.name,
      propose: (context) => ask("propose", context) as ReturnType<AttackProposer["propose"]>,
    };
  }
  if (request.vulnerabilities) {
    options.vulnerabilities = {
      notice: request.vulnerabilities.notice,
      // A Map does not survive JSON, so it travels as its entries.
      lookup: async (dependencies) => new Map((await ask("lookup", dependencies)) as Array<[string, never]>),
    } satisfies VulnerabilitySource;
  }
  try {
    const sight = {
      ...(Array.isArray(request.unread) ? { unread: request.unread.filter((p): p is string => typeof p === "string") } : {}),
      ...(request.incomplete === true ? { incomplete: true } : {}),
    };
    const result = await review(snapshotFromFiles(request.files, request.tracked, sight), options);
    return { type: "done", result };
  } catch (error) {
    return error instanceof ReviewStoppedError ? { type: "stopped", reason: error.reason } : { type: "failed" };
  }
}

async function readBody(request: IncomingMessage): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > MAX_REQUEST_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

if (import.meta.main) {
  const review = createSandbox();
  const port = Number(process.env.PORT ?? 8080);

  createServer(async (req, res) => {
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method === "GET" && req.url === "/health") return reply(200, { ok: true });
    if (req.method !== "POST" || req.url !== "/review") return reply(404, { error: "Not found." });

    const raw = await readBody(req);
    if (raw === null) return reply(413, { error: "Too large." });
    let request: ReviewRequest;
    try {
      request = JSON.parse(raw) as ReviewRequest;
      if (!Array.isArray(request.files) || !Array.isArray(request.tracked)) throw new Error("shape");
    } catch {
      return reply(400, { error: "Invalid request." });
    }
    reply(200, await handleReview(request, review));
  }).listen(port, () => console.log(`reviewer listening on ${port}`));
}
