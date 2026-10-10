import type { CodeLocation, SourceFile } from "./types.ts";

/** Lines that are pure comments -- most false positives live here. */
const COMMENT = /^\s*(\/\/|\/\*|\*|#)/;

export interface LineHit {
  line: number;
  text: string;
  match: RegExpExecArray;
}

/**
 * Scan a file line by line, skipping comments unless `includeComments`.
 * Regexes are reset per line so callers can pass /g patterns without the
 * lastIndex footgun.
 */
export function scanLines(
  file: SourceFile,
  pattern: RegExp,
  opts: { includeComments?: boolean } = {},
): LineHit[] {
  const hits: LineHit[] = [];
  const lines = file.content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i]!;
    if (!opts.includeComments && COMMENT.test(text)) continue;

    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    if (match) hits.push({ line: i + 1, text, match });
  }
  return hits;
}

/**
 * Replace anything that looks like a live credential with a placeholder.
 *
 * Findings travel into logs, the dashboard, and PR comments, so an excerpt that
 * still contains the secret would leak it into three new places while reporting
 * that it leaked. Redact at the boundary, always.
 */
export function redact(text: string): string {
  return text
    // Quoted values on a key that names a credential.
    .replace(
      /((?:secret|token|password|passwd|api[-_]?key|private[-_]?key|credential)\w*\s*[:=]\s*)(['"`])([^'"`]{4,})\2/gi,
      (_m, head: string, q: string) => `${head}${q}[redacted]${q}`,
    )
    // Bare provider-shaped tokens anywhere on the line.
    .replace(/\b(sk-|ghp_|github_pat_|xox[baprs]-|AKIA)[A-Za-z0-9_-]{8,}/g, "$1[redacted]")
    // JWTs.
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g, "[redacted-jwt]");
}

export function locate(file: SourceFile, hit: LineHit): CodeLocation {
  return {
    path: file.path,
    line: hit.line,
    column: hit.match.index + 1,
    excerpt: redact(hit.text.trim()).slice(0, 300),
  };
}

const TEST_PATH = /(^|\/)(tests?|__tests__|__mocks__|e2e|fixtures?)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/;
export const isTestPath = (p: string): boolean => TEST_PATH.test(p);

const EXAMPLE_ENV = /(^|\/)\.env\.(example|sample|template)$/;
export const isExampleEnv = (p: string): boolean => EXAMPLE_ENV.test(p);

const TS_JS = /\.[cm]?[jt]sx?$/;
export const isSource = (p: string): boolean => TS_JS.test(p) && !p.includes("node_modules/");
