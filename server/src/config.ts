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
   * The GitHub App. All three or none: with none, the webhook route answers
   * "not configured" and everything else works as before. The private key is
   * read from a file (GitHub hands it out as one) rather than pasted into the
   * environment, where line breaks get mangled.
   */
  GITHUB_APP_ID: z.string().regex(/^\d+$/, "GITHUB_APP_ID is the number shown on the App's page").optional(),
  GITHUB_PRIVATE_KEY_PATH: z.string().optional(),
  GITHUB_WEBHOOK_SECRET: z.string().min(20, "GITHUB_WEBHOOK_SECRET should be long and random").optional(),
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
  github: githubConfig(parsed.data),
};

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
