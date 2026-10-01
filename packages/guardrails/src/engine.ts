import { authRules } from "./rules/auth.ts";
import { injectionRules } from "./rules/injection.ts";
import { secretsRules } from "./rules/secrets.ts";
import type { Finding, RepoSnapshot, Rule, Severity } from "./types.ts";

export const allRules: Rule[] = [...secretsRules, ...injectionRules, ...authRules];

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface ScanResult {
  findings: Finding[];
  /** Rules that threw, so one bad rule degrades coverage instead of failing the scan. */
  errors: Array<{ ruleId: string; path: string; message: string }>;
  filesScanned: number;
  durationMs: number;
}

/**
 * Run every applicable rule over the snapshot.
 *
 * Rules are untrusted-adjacent (they run regexes over arbitrary user code, where
 * a pathological input can throw or backtrack), so each invocation is isolated:
 * a rule that fails on one file is recorded and the scan continues.
 */
export function scan(snapshot: RepoSnapshot, rules: Rule[] = allRules): ScanResult {
  const started = performance.now();
  const findings: Finding[] = [];
  const errors: ScanResult["errors"] = [];

  for (const file of snapshot.files) {
    for (const rule of rules) {
      if (!rule.appliesTo(file.path)) continue;
      try {
        findings.push(...rule.check(file, snapshot));
      } catch (error) {
        errors.push({
          ruleId: rule.id,
          path: file.path,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  return {
    findings: sortFindings(dedupe(findings)),
    errors,
    filesScanned: snapshot.files.length,
    durationMs: performance.now() - started,
  };
}

/**
 * Two rules can legitimately flag the same line -- a hardcoded key inside a SQL
 * string, say. Reporting it twice makes the user think there are two problems.
 */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.location?.path ?? ""}:${finding.location?.line ?? 0}`;
    const existing = seen.get(key);
    if (!existing || SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]) {
      seen.set(key, finding);
    }
  }
  return [...seen.values()];
}

/** Most severe first; ties broken by path then line so output is stable across runs. */
function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;

    const byPath = (a.location?.path ?? "").localeCompare(b.location?.path ?? "");
    if (byPath !== 0) return byPath;

    return (a.location?.line ?? 0) - (b.location?.line ?? 0);
  });
}

/**
 * The deploy gate. Critical findings block regardless of confidence, because the
 * cost of shipping a leaked key dwarfs the cost of a false positive the user can
 * dismiss. High findings block only when we are reasonably sure.
 */
export function blocksDeploy(findings: Finding[]): Finding[] {
  return findings.filter(
    (f) =>
      f.severity === "critical" ||
      (f.severity === "high" && f.confidence !== "possible"),
  );
}
