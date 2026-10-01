import type { RepoSnapshot, SourceFile } from "./types.ts";

/** Never worth scanning, and large enough to dominate runtime if included. */
const IGNORED = /(^|\/)(node_modules|dist|build|\.git|\.next|coverage|\.turbo)(\/|$)/;

/**
 * Build a snapshot from already-read files. Reading from disk or from a git
 * object store is the caller's job -- keeping IO out of this package is what
 * lets the same engine run in the server, in a worker, and in tests.
 */
export function snapshotFromFiles(
  files: SourceFile[],
  tracked: Iterable<string> = files.map((f) => f.path),
): RepoSnapshot {
  const kept = files.filter((f) => !IGNORED.test(f.path));
  const manifests = new Map<string, Record<string, unknown>>();

  for (const file of kept) {
    if (!/(^|\/)package\.json$/.test(file.path)) continue;
    try {
      const parsed: unknown = JSON.parse(file.content);
      // A malformed manifest is a finding for another rule, not a crash here.
      if (parsed && typeof parsed === "object") {
        manifests.set(file.path, parsed as Record<string, unknown>);
      }
    } catch {
      // Ignore: unparseable manifests are surfaced by the dependency rules.
    }
  }

  return { files: kept, manifests, tracked: new Set(tracked) };
}
