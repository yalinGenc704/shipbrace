import { fork } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { redact, type RepoSnapshot, type ReviewOptions, type ReviewResult } from "@shipbrace/guardrails";
import { ReviewStoppedError } from "./stopped.ts";
import type { FromWorker, ToWorker } from "./worker.ts";

export { ReviewStoppedError };

/**
 * Reviews run sealed off, one process each.
 *
 * The parser that reads a repository is native code fed someone else's files,
 * and a bug in it is a real possibility (docs/architecture.md, "Open item").
 * A separate process -- not a worker thread, which shares the server's memory
 * and dies with it -- means a crash, a hang, or a runaway allocation costs one
 * review, never the server. Inside it:
 *
 *   - no secrets: the environment is empty, so there is no API key, GitHub key
 *     or database address to steal;
 *   - Node's permission model: files may be read only from ShipBrace's own code
 *     (not .env, not the App's key), and no network, no writing, no starting
 *     other programs, no worker threads;
 *   - a time limit on the work itself (time spent waiting for the AI is not
 *     counted), and a memory limit; going over either kills the process.
 *
 * Honest limit: the permission model is enforced by Node's JavaScript layer.
 * Native code that has been taken over could bypass it. The complete seal is
 * the operating system's -- a container with no network, a read-only disk and
 * a memory cap -- which comes with hosting (step 2). This is the layer that
 * works everywhere, including on the laptop, and it already contains crashes,
 * hangs and memory blow-ups, which are the likely failures.
 */

export interface SandboxLimits {
  /** Time the sealed process may spend working, excluding waits for the AI and the package lookup. */
  workMs: number;
  /** Ceiling on its JavaScript memory. */
  memoryMb: number;
  /** Reviews running at once; the rest wait their turn. */
  concurrency: number;
  /** Reviews allowed to wait. Beyond this they are refused, so a flood of pushes cannot exhaust memory. */
  maxWaiting: number;
}

export const DEFAULT_SANDBOX_LIMITS: SandboxLimits = { workMs: 60_000, memoryMb: 1_024, concurrency: 2, maxWaiting: 50 };

/** Waiting on the outside steps is not counted as work, but is not unlimited either. */
const MAX_WALL_MS = 15 * 60_000;

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const WORKER = fileURLToPath(new URL("./worker.ts", import.meta.url));

/**
 * What the sealed process may read: the code it runs and the packages it
 * imports. Nothing else in the project -- in particular not `.env` or
 * `github-app.pem` at its root.
 */
function readable(entry: string): string[] {
  return [
    `${ROOT}node_modules/*`,
    `${ROOT}packages/*`,
    `${dirname(entry)}/*`,
    `${ROOT}package.json`,
    `${ROOT}server/package.json`,
  ];
}

export type Review = (snapshot: RepoSnapshot, options?: ReviewOptions) => Promise<ReviewResult>;

/**
 * `entry` is the program run inside; tests replace it with deliberately
 * misbehaving ones to prove the walls hold.
 */
/**
 * The one line of a crash worth logging: the error's own line ("TypeError:
 * ..."), secrets blanked, any quoted text removed (a parse error quotes the
 * input it choked on, which is someone's repository), and kept short.
 */
function errorLine(stderr: string): string {
  const line = /^\s*(?:\w*Error|RangeError|FATAL ERROR)\b.*$/m.exec(stderr)?.[0]?.trim();
  if (!line) return "";
  return `: ${redact(line).replace(/(["'`])(?:(?!\1).){0,400}\1/g, "$1…$1").slice(0, 200)}`;
}

export function createSandbox(
  limits: SandboxLimits = DEFAULT_SANDBOX_LIMITS,
  entry: string = WORKER,
  log: (message: string) => void = console.error,
): Review {
  let running = 0;
  const queue: Array<() => void> = [];

  return async (snapshot, options = {}) => {
    if (running >= limits.concurrency) {
      if (queue.length >= limits.maxWaiting) throw new ReviewStoppedError("busy");
      await new Promise<void>((resolve) => queue.push(resolve));
    }
    running++;
    try {
      return await reviewOnce(snapshot, options, limits, entry, log);
    } finally {
      running--;
      queue.shift()?.();
    }
  };
}

function reviewOnce(
  snapshot: RepoSnapshot,
  options: ReviewOptions,
  limits: SandboxLimits,
  entry: string,
  log: (message: string) => void,
): Promise<ReviewResult> {
  return new Promise((resolve, reject) => {
    const child = fork(entry, [], {
      execArgv: [
        "--experimental-strip-types",
        "--permission",
        ...readable(entry).map((path) => `--allow-fs-read=${path}`),
        // The parser is a native addon. Allowing addons is what makes the
        // permission model a JavaScript-level wall only; see the note above.
        "--allow-addons",
        `--max-old-space-size=${limits.memoryMb}`,
      ],
      env: {},
      serialization: "advanced",
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    });

    // The operator's log gets the start of anything the process printed when
    // it failed; kept short, since a crash report could quote the code.
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < 2_000) stderr += chunk.toString("utf8");
    });

    let settled = false;
    let stoppedFor: "time" | null = null;
    const finish = (outcome: { result: ReviewResult } | { error: Error }) => {
      if (settled) return;
      settled = true;
      clearTimeout(workTimer);
      clearTimeout(wallTimer);
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      if ("result" in outcome) resolve(outcome.result);
      else reject(outcome.error);
    };

    const stop = () => {
      stoppedFor = "time";
      child.kill("SIGKILL");
    };

    // The work clock runs only while the process is working, not while it
    // waits for the parent to answer.
    let remaining = limits.workMs;
    let since = Date.now();
    let workTimer = setTimeout(stop, remaining);
    let outstanding = 0;
    const wallTimer = setTimeout(stop, MAX_WALL_MS);

    const pauseClock = () => {
      if (outstanding++ > 0) return;
      clearTimeout(workTimer);
      remaining -= Date.now() - since;
    };
    const resumeClock = () => {
      if (--outstanding > 0 || settled) return;
      since = Date.now();
      workTimer = setTimeout(stop, Math.max(remaining, 0));
    };

    // The pipeline asks each outside step at most once. Anything else means
    // the process is not running the code it was given.
    const asked = new Set<string>();

    child.on("message", (message: FromWorker) => {
      if (message.type === "done") return finish({ result: message.result });
      if (message.type === "failed") return finish({ error: new Error("the review failed inside the sandbox") });
      if (message.type !== "ask" || asked.has(message.step)) {
        log("sandbox: unexpected message; stopping the review");
        return finish({ error: new ReviewStoppedError("crash") });
      }
      asked.add(message.step);

      const step =
        message.step === "propose" ? options.proposer && (() => options.proposer!.propose(message.input as never))
        : options.vulnerabilities && (() => options.vulnerabilities!.lookup(message.input as never));
      if (!step) return finish({ error: new ReviewStoppedError("crash") });

      pauseClock();
      step().then(
        (value) => answer({ type: "answer", id: message.id, value }),
        (error: unknown) =>
          answer({
            type: "answer",
            id: message.id,
            error: error instanceof Error && error.name === "ProposerRefusedError" ? "refused" : "failed",
          }),
      );
    });

    const answer = (message: ToWorker) => {
      resumeClock();
      if (!settled && child.connected) child.send(message);
    };

    child.on("error", (error) => {
      log(`sandbox: could not run the review process: ${error.message}`);
      finish({ error: new ReviewStoppedError("crash") });
    });

    child.on("exit", (code, signal) => {
      if (settled) return;
      const reason =
        stoppedFor ?? (/heap out of memory|allocation failed/i.test(stderr) ? "memory" : "crash");
      log(`sandbox: review process ended early (${reason}; code ${code}, signal ${signal})${errorLine(stderr)}`);
      finish({ error: new ReviewStoppedError(reason) });
    });

    const request: ToWorker = {
      type: "review",
      snapshot,
      ...(options.proposer ? { proposer: { name: options.proposer.name } } : {}),
      ...(options.vulnerabilities ? { vulnerabilities: { notice: options.vulnerabilities.notice } } : {}),
    };
    child.send(request);
  });
}
