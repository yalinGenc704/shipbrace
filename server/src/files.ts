/**
 * Which files a review reads, and how much -- shared by the folder review
 * (ingest.ts) and the GitHub review (github/repository.ts). Kept free of any
 * filesystem or process code so it also runs on Cloudflare Workers.
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
const READABLE = /\.(?:[cm]?[jt]sx?|json|ya?ml|toml|md|sql|sh|env[\w.]*|dockerfile|txt|ejs|hbs|handlebars|pug|njk|swig|html|prisma)$/i;
const NAMED = /^(?:Dockerfile|docker-compose\.ya?ml|\.env[\w.]*|\.gitignore|.*\.lock|bun\.lockb?)$/i;

export const looksBinary = (buffer: Buffer): boolean => buffer.subarray(0, 8192).includes(0);

export const wanted = (name: string): boolean => READABLE.test(name) || NAMED.test(name);
