/**
 * Core vocabulary of the guardrail engine.
 *
 * A Rule inspects a RepoSnapshot and emits Findings. Everything downstream --
 * the auto-fix pipeline, the dashboard, the PR comment writer -- consumes
 * Findings and nothing else. Rules never perform IO and never mutate the repo;
 * that keeps them trivially testable and safe to run on untrusted user code.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "secrets"
  | "auth"
  | "injection"
  | "transport"
  | "dependency"
  | "architecture"
  | "deploy"
  | "data-loss";

/** How much we trust the match. Only `certain` findings are eligible for silent auto-fix. */
export type Confidence = "certain" | "likely" | "possible";

export interface SourceFile {
  /** Repo-relative, forward-slashed. */
  path: string;
  content: string;
}

export interface RepoSnapshot {
  files: SourceFile[];
  /** Parsed package.json manifests, keyed by repo-relative path. */
  manifests: Map<string, Record<string, unknown>>;
  /** Set of repo-relative paths tracked by git, for .gitignore-awareness. */
  tracked: ReadonlySet<string>;
  /**
   * Files that exist but were not read: a type the reader does not read
   * (Python, Vue, a Jenkinsfile), or too large. What they hold is out of
   * sight, so nothing may be called absent on the strength of not finding it.
   */
  unread?: readonly string[];
  /** Some files were never even listed: the repository was over a limit. */
  incomplete?: boolean;
}

export interface CodeLocation {
  path: string;
  /** 1-indexed. */
  line: number;
  column?: number;
  /** The offending line, verbatim, for supervise mode. Secrets are redacted before this is set. */
  excerpt?: string;
}

/**
 * A proposed edit. `kind: "replace"` swaps an exact substring on one line so the
 * patch stays reviewable; anything structural is left to a human or the LLM.
 */
export interface Fix {
  /** The next step in plain words, for someone who does not read code. */
  description: string;
  /**
   * The same step as an exact, code-level instruction, shown as "Exact fix
   * (paste into your AI assistant)". Kept apart so the plain part stays plain.
   */
  detail?: string;
  kind: "replace" | "insert-file" | "manual";
  path?: string;
  find?: string;
  replace?: string;
  /** Full contents, for kind: "insert-file". */
  contents?: string;
}

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** One line, imperative, no jargon -- this is what a non-technical user reads. */
  title: string;
  /** Plain-language consequence. Answers "why should I care?" without shaming. */
  why: string;
  location?: CodeLocation;
  fix?: Fix;
  /** Link to a longer explainer in the dashboard. */
  learnMore?: string;
}

export interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  /** Files this rule wants, as a predicate on repo-relative path. */
  appliesTo: (path: string) => boolean;
  check: (file: SourceFile, snapshot: RepoSnapshot) => Finding[];
}
