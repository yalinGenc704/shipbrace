/**
 * The scaffold is composed, not templated.
 *
 * A single template with every feature baked in forces product decisions --
 * "do generated apps have logins?" -- to be answered once, globally, and
 * changed only by rewriting. Instead each capability is a Module that
 * contributes files, dependencies, and environment variables, and `compose`
 * merges the selected set. The decision becomes a value in a ScaffoldSpec,
 * so it can be made per-app and changed at any time.
 */

export type FeatureId = "auth" | "charts" | "spreadsheets";

export type DatabaseKind = "postgres" | "mysql" | "none";

export interface ScaffoldSpec {
  /** kebab-case; used as the directory name, Docker project name, and DB name. */
  name: string;
  features: FeatureId[];
  database: DatabaseKind;
}

export interface GeneratedFile {
  /** Repo-relative, forward-slashed. */
  path: string;
  contents: string;
}

/**
 * A variable the generated app needs at runtime.
 *
 * `secret: true` means the value must never reach the browser bundle and never
 * be written into .env.example with a usable default -- the placeholder has to
 * be obviously fake so a copied file fails loudly instead of running insecurely.
 */
export interface EnvVar {
  name: string;
  description: string;
  secret: boolean;
  /** Placeholder for .env.example. Required for non-secrets, ignored for secrets. */
  example?: string;
}

export interface Module {
  id: string;
  /** Only included when every listed feature is present in the spec. */
  when?: (spec: ScaffoldSpec) => boolean;
  files: (spec: ScaffoldSpec) => GeneratedFile[];
  /** name -> exact version. Pinned, never ranged: a scaffold that drifts is not reproducible. */
  appDeps?: Record<string, string>;
  serverDeps?: Record<string, string>;
  env?: EnvVar[];
}

export interface ComposeResult {
  files: GeneratedFile[];
  /** Non-fatal problems worth surfacing, e.g. a module overwriting another's file. */
  warnings: string[];
}
