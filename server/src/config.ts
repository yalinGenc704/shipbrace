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
};
