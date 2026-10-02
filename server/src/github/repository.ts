import { snapshotFromFiles, type RepoSnapshot } from "@aegis/guardrails";
import { DEFAULT_LIMITS, LOCKFILE, looksBinary, SKIP_DIR, wanted, type IngestLimits } from "../ingest.ts";
import type { GitHubClient } from "./client.ts";

/**
 * Read one commit of a repository straight from GitHub's object store.
 *
 * The repository is someone else's and must be treated as hostile, so it is
 * read file by file through the API rather than downloaded as an archive and
 * unpacked. Unpacking an archive is a classic way to write files outside the
 * intended folder; reading blobs into memory has no folder to escape from.
 * Nothing is written to disk and nothing is executed.
 *
 * The same filters and limits as a local review apply: which files are worth
 * reading, which folders are skipped, and how much is read in total.
 */

interface TreeEntry {
  path: string;
  type: "blob" | "tree" | "commit";
  sha: string;
  size?: number;
}

export interface FetchResult {
  snapshot: RepoSnapshot;
  fileCount: number;
  /** What was left out and why, so a thin review is never mistaken for a clean one. */
  skipped: { notReadable: number; tooLarge: number; overLimit: number; treeTruncated: boolean };
}

const CONCURRENCY = 8;

export async function fetchRepository(
  client: GitHubClient,
  owner: string,
  repo: string,
  commitSha: string,
  limits: IngestLimits = DEFAULT_LIMITS,
): Promise<FetchResult> {
  const where = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const tree = await client.get<{ tree: TreeEntry[]; truncated: boolean }>(
    `${where}/git/trees/${encodeURIComponent(commitSha)}?recursive=1`,
  );

  const skipped = { notReadable: 0, tooLarge: 0, overLimit: 0, treeTruncated: tree.truncated };
  const chosen: TreeEntry[] = [];
  let plannedBytes = 0;

  for (const entry of tree.tree) {
    if (entry.type !== "blob") continue;
    const parts = entry.path.split("/");
    const name = parts.at(-1) ?? "";
    if (parts.slice(0, -1).some((dir) => SKIP_DIR.test(dir))) continue;
    if (!wanted(name)) {
      skipped.notReadable++;
      continue;
    }
    const size = entry.size ?? 0;
    const cap = LOCKFILE.test(name)
      ? Math.max(limits.maxFileBytes, limits.maxLockfileBytes ?? 0)
      : limits.maxFileBytes;
    if (size > cap) {
      skipped.tooLarge++;
      continue;
    }
    if (chosen.length >= limits.maxFiles || plannedBytes + size > limits.maxTotalBytes) {
      skipped.overLimit++;
      continue;
    }
    chosen.push(entry);
    plannedBytes += size;
  }

  const files: Array<{ path: string; content: string }> = [];
  for (let i = 0; i < chosen.length; i += CONCURRENCY) {
    const batch = await Promise.all(
      chosen.slice(i, i + CONCURRENCY).map(async (entry) => {
        const blob = await client.get<{ content: string; encoding: string }>(
          `${where}/git/blobs/${encodeURIComponent(entry.sha)}`,
        );
        const buffer = Buffer.from(blob.content, blob.encoding === "base64" ? "base64" : "utf8");
        return looksBinary(buffer) ? null : { path: entry.path, content: buffer.toString("utf8") };
      }),
    );
    for (const file of batch) {
      if (file) files.push(file);
      else skipped.notReadable++;
    }
  }

  // Everything here came from the commit, so all of it is tracked by git.
  return { snapshot: snapshotFromFiles(files), fileCount: files.length, skipped };
}
