import { spawnSync } from "node:child_process";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { snapshotFromFiles, type RepoSnapshot } from "@aegis/guardrails";

/**
 * Turns a folder on disk into a snapshot the review engine can analyse.
 *
 * This is the only part of the server that touches the filesystem, and it is
 * therefore where the server's own security lives. Two rules drive the design:
 *
 *  1. A caller names which folder to review, so the path is untrusted input.
 *     Everything is resolved and then confined under a configured root --
 *     including after following symlinks, because a link inside the root can
 *     point outside it.
 *
 *  2. A repository is arbitrary data. Reading it must be bounded in files,
 *     bytes, and time, or one large or hostile directory stalls the server for
 *     everyone.
 */

export interface IngestLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
  /**
   * Lockfiles are routinely larger than source files, and the dependency
   * checks are blind without them. Still capped: they are data, not trusted.
   */
  maxLockfileBytes?: number;
}

export const DEFAULT_LIMITS: IngestLimits = {
  maxFiles: 5_000,
  maxTotalBytes: 32 * 1024 * 1024,
  maxFileBytes: 512 * 1024,
  maxLockfileBytes: 8 * 1024 * 1024,
};

export const LOCKFILE = /^(?:package-lock\.json|bun\.lock|pnpm-lock\.yaml|yarn\.lock)$/;

/** Directories never worth reading, and large enough to dominate a walk. */
export const SKIP_DIR =
  /^(node_modules|\.git|dist|build|coverage|\.next|\.turbo|\.cache|vendor|__pycache__)$/;

/** Only text formats the rules and the oracle can actually reason about. */
const READABLE = /\.(?:[cm]?[jt]sx?|json|ya?ml|toml|md|sql|sh|env[\w.]*|dockerfile|txt|ejs|hbs|handlebars|pug|njk|swig|html)$/i;
const NAMED = /^(?:Dockerfile|docker-compose\.ya?ml|\.env[\w.]*|\.gitignore|.*\.lock|bun\.lockb?)$/i;

export class PathOutsideRootError extends Error {
  constructor(target: string) {
    super(`Refused to read ${target}: it is outside the configured review root.`);
    this.name = "PathOutsideRootError";
  }
}

export interface IngestResult {
  snapshot: RepoSnapshot;
  /** What was left out and why, so a thin review is never mistaken for a clean one. */
  skipped: { binaryOrUnknown: number; tooLarge: number; overLimit: number };
  root: string;
  fileCount: number;
  isGitRepository: boolean;
}

/**
 * Confine `target` to `root`.
 *
 * `realpath` is applied to both sides before comparing, so a symlink inside the
 * root that points elsewhere cannot be used to escape it. The separator is
 * appended before the prefix check: without it, "/srv/repos-secret" would pass
 * a check against the root "/srv/repos".
 */
export async function confine(root: string, target: string): Promise<string> {
  const realRoot = await realpath(resolve(root));
  const resolved = resolve(realRoot, target);

  let realTarget: string;
  try {
    realTarget = await realpath(resolved);
  } catch {
    // Does not exist: still refuse anything that resolves outside the root,
    // so a caller cannot probe for files by reading the error message.
    realTarget = resolved;
  }

  if (realTarget !== realRoot && !realTarget.startsWith(realRoot + sep)) {
    throw new PathOutsideRootError(target);
  }
  return realTarget;
}

/**
 * Files git knows about, used by the rule that flags a committed `.env`.
 *
 * Arguments are passed as an array and never interpolated into a shell string
 * -- the same discipline the product's own guardrails demand of generated apps.
 * A folder that is not a repository yields an empty set, which is correct:
 * nothing there is committed anywhere.
 *
 * The folder's own `.git/config` is someone else's too, and git obeys it: a
 * `core.fsmonitor` setting there makes even `git ls-files` run a program of
 * the folder's choosing (tested; it does). So every setting that can start a
 * program is overridden on the command line, which wins over the folder's
 * config, and git gets a bare environment instead of the server's.
 */
const GIT_OVERRIDES = [
  "-c", "core.fsmonitor=false",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.pager=cat",
  "-c", "core.sshCommand=false",
  "-c", "protocol.allow=never",
];

function trackedFiles(directory: string): { tracked: Set<string>; isRepository: boolean } {
  const result = spawnSync("git", [...GIT_OVERRIDES, "ls-files", "-z"], {
    cwd: directory,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" },
  });

  if (result.status !== 0 || typeof result.stdout !== "string") {
    return { tracked: new Set(), isRepository: false };
  }
  return {
    tracked: new Set(result.stdout.split("\0").filter(Boolean)),
    isRepository: true,
  };
}

export const looksBinary = (buffer: Buffer): boolean => buffer.subarray(0, 8192).includes(0);

export const wanted = (name: string): boolean => READABLE.test(name) || NAMED.test(name);

export async function ingest(
  root: string,
  target = ".",
  limits: IngestLimits = DEFAULT_LIMITS,
): Promise<IngestResult> {
  const directory = await confine(root, target);

  const info = await stat(directory);
  if (!info.isDirectory()) throw new Error(`${target} is not a directory.`);

  const files: Array<{ path: string; content: string }> = [];
  const skipped = { binaryOrUnknown: 0, tooLarge: 0, overLimit: 0 };
  let totalBytes = 0;

  async function walk(current: string): Promise<void> {
    const entries = await readdir(current, { withFileTypes: true });

    for (const entry of entries) {
      if (files.length >= limits.maxFiles || totalBytes >= limits.maxTotalBytes) {
        skipped.overLimit++;
        continue;
      }

      const absolute = join(current, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIR.test(entry.name)) await walk(absolute);
        continue;
      }
      // Symlinked files are not followed. Resolving each one is a per-file
      // escape risk for no benefit, since the target is almost always already
      // in the tree.
      if (!entry.isFile()) continue;

      if (!wanted(entry.name)) {
        skipped.binaryOrUnknown++;
        continue;
      }

      const size = (await stat(absolute)).size;
      const cap = LOCKFILE.test(entry.name)
        ? Math.max(limits.maxFileBytes, limits.maxLockfileBytes ?? 0)
        : limits.maxFileBytes;
      if (size > cap) {
        skipped.tooLarge++;
        continue;
      }

      const buffer = await readFile(absolute);
      if (looksBinary(buffer)) {
        skipped.binaryOrUnknown++;
        continue;
      }

      files.push({
        path: relative(directory, absolute).split(sep).join("/"),
        content: buffer.toString("utf8"),
      });
      totalBytes += size;
    }
  }

  await walk(directory);

  const { tracked, isRepository } = trackedFiles(directory);

  return {
    snapshot: snapshotFromFiles(files, tracked),
    skipped,
    root: directory,
    fileCount: files.length,
    isGitRepository: isRepository,
  };
}
