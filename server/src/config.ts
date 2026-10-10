import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";

/**
 * Validated once at startup, exactly as the generated apps do it.
 *
 * REVIEW_ROOT is the boundary the ingest step confines every request to. It
 * defaults to the current working directory rather than the filesystem root:
 * a default that could read anything on the machine would be a vulnerability
 * shipped as a convenience.
 */
const schema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  REVIEW_ROOT: z.string().default(process.cwd()),
  ALLOWED_ORIGINS: z
    .string()
    .default("http://localhost:5173")
    .refine((value) => !value.includes("*"), {
      message: "ALLOWED_ORIGINS must list real origins; * would let any site call this API",
    }),
  /**
   * Whether package names and versions may be sent to OSV.dev to look up
   * known flaws. On by default; "off" keeps every review fully offline.
   */
  PACKAGE_LOOKUP: z.enum(["on", "off"]).default("on"),
  /**
   * Whether reviews also ask an AI model where to look. Off by default: it
   * costs money per review and sends code excerpts to the model provider (see
   * docs/legal/third-party-services.md). Needs ANTHROPIC_API_KEY.
   */
  AI_REVIEW: z.enum(["on", "off"]).default("off"),
  ANTHROPIC_API_KEY: z.string().optional(),
  /**
   * The GitHub App. All three or none: with none, the webhook route answers
   * "not configured" and everything else works as before. The private key is
   * read from a file (GitHub hands it out as one) rather than pasted into the
   * environment, where line breaks get mangled.
   */
  GITHUB_APP_ID: z.string().regex(/^\d+$/, "GITHUB_APP_ID is the number shown on the App's page").optional(),
  GITHUB_PRIVATE_KEY_PATH: z.string().optional(),
  GITHUB_WEBHOOK_SECRET: z.string().min(20, "GITHUB_WEBHOOK_SECRET should be long and random").optional(),
  /**
   * Where past reviews are kept. Without it nothing is stored: GitHub checks
   * still work, they just have no link to a report.
   */
  DATABASE_URL: z.string().regex(/^postgres(ql)?:\/\//, "DATABASE_URL must start with postgres://").optional(),
  /**
   * The address people reach this server at (the tunnel, later the domain),
   * used for the links in GitHub checks. https, except on this machine.
   */
  /**
   * The "review this folder" page (`/api/review` and the dashboard's front
   * page). Useful on a laptop; on a hosted server it would let anyone start
   * reviews of the server's own files, so hosting turns it off.
   */
  LOCAL_REVIEW: z.enum(["on", "off"]).default("on"),
  /**
   * Where the review container listens (hosting). Without it, reviews run in
   * a sealed process on this machine instead (sandbox/sandbox.ts).
   */
  REVIEWER_SOCKET: z.string().startsWith("/", "REVIEWER_SOCKET must be an absolute path").optional(),
  PUBLIC_URL: z
    .url()
    .refine((value) => value.startsWith('https://') || /^http:\/\/localhost(:\d+)?\/?$/.test(value), {
      message: "PUBLIC_URL must be an https address (or http://localhost)",
    })
    .optional(),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(`  ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

export const config = {
  port: parsed.data.PORT,
  reviewRoot: resolve(parsed.data.REVIEW_ROOT),
  allowedOrigins: parsed.data.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim()),
  packageLookup: parsed.data.PACKAGE_LOOKUP === "on",
  aiReview: aiReviewEnabled(parsed.data),
  github: githubConfig(parsed.data),
  localReview: parsed.data.LOCAL_REVIEW === "on",
  reviewerSocket: parsed.data.REVIEWER_SOCKET ?? null,
  databaseUrl: parsed.data.DATABASE_URL ?? null,
  publicUrl: publicUrl(parsed.data),
};

function publicUrl(env: z.infer<typeof schema>): string | null {
  if (!env.PUBLIC_URL) return null;
  if (!env.DATABASE_URL) {
    console.error("PUBLIC_URL is only used for links to stored reviews, which need DATABASE_URL.");
    process.exit(1);
  }
  return env.PUBLIC_URL.replace(/\/+$/, "");
}

function aiReviewEnabled(env: z.infer<typeof schema>): boolean {
  if (env.AI_REVIEW !== "on") return false;
  if (!env.ANTHROPIC_API_KEY) {
    console.error("AI_REVIEW=on needs ANTHROPIC_API_KEY.");
    process.exit(1);
  }
  return true;
}

function githubConfig(env: z.infer<typeof schema>) {
  const set = [env.GITHUB_APP_ID, env.GITHUB_PRIVATE_KEY_PATH, env.GITHUB_WEBHOOK_SECRET].filter(Boolean);
  if (set.length === 0) return null;
  if (set.length < 3) {
    console.error("GitHub App settings are incomplete: set GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH and GITHUB_WEBHOOK_SECRET together.");
    process.exit(1);
  }
  let privateKey: string;
  try {
    privateKey = readFileSync(resolve(env.GITHUB_PRIVATE_KEY_PATH!), "utf8");
  } catch {
    // The path, not the error: the error could quote file contents.
    console.error(`Could not read the GitHub App private key at ${env.GITHUB_PRIVATE_KEY_PATH}.`);
    process.exit(1);
  }
  return { appId: env.GITHUB_APP_ID!, privateKey, webhookSecret: env.GITHUB_WEBHOOK_SECRET! };
}
