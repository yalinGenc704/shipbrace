import { blocksDeploy } from "./engine.ts";
import type { Finding } from "./types.ts";

/**
 * The product has one finding stream and two audiences for it.
 *
 * `auto` is for the user who chose to stay in the design surface: it says what
 * was handled and what still needs a decision, and never shows code. `supervise`
 * is for the user who opted in to following along: same findings, but with the
 * offending line, the rule that caught it, and the reasoning, so they can learn
 * the pattern rather than just trust the tool.
 *
 * Deliberately not two rule sets -- if supervise mode could surface something
 * auto mode hides, the safe-by-default promise would be a lie.
 */

export interface AutoReport {
  ok: boolean;
  headline: string;
  /** Plain-language items needing a human decision. No file paths, no code. */
  needsYou: Array<{ title: string; why: string; whatToDo: string }>;
  handledCount: number;
}

export function renderAuto(findings: Finding[]): AutoReport {
  const blocking = blocksDeploy(findings);
  const handled = findings.length - blocking.length;

  return {
    ok: blocking.length === 0,
    headline: blocking.length === 0
      ? "No security problems are blocking your site from going live."
      : `${blocking.length} problem${blocking.length === 1 ? "" : "s"} need${
        blocking.length === 1 ? "s" : ""
      } your decision before this can go live.`,
    needsYou: blocking.map((f) => ({
      title: f.title,
      why: f.why,
      whatToDo: f.fix?.description ?? "Open supervise mode to see the affected code.",
    })),
    handledCount: handled,
  };
}

export interface SuperviseReport {
  ok: boolean;
  summary: { critical: number; high: number; medium: number; low: number; info: number };
  items: Array<{
    ruleId: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    title: string;
    why: string;
    /** Already redacted upstream in `locate`; safe to render. */
    location?: { path: string; line: number; excerpt?: string };
    suggestedFix?: string;
    blocking: boolean;
    learnMore?: string;
  }>;
}

export function renderSupervise(findings: Finding[]): SuperviseReport {
  const blocking = new Set(blocksDeploy(findings));
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  return {
    ok: blocking.size === 0,
    summary,
    // Optional fields are spread in only when present. Assigning `undefined`
    // to an optional property is a different thing from omitting it, and the
    // wire format should carry absent fields as absent.
    items: findings.map((f) => ({
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence,
      title: f.title,
      why: f.why,
      ...(f.location
        ? {
          location: {
            path: f.location.path,
            line: f.location.line,
            ...(f.location.excerpt ? { excerpt: f.location.excerpt } : {}),
          },
        }
        : {}),
      ...(f.fix?.description ? { suggestedFix: f.fix.description } : {}),
      blocking: blocking.has(f),
      ...(f.learnMore ? { learnMore: f.learnMore } : {}),
    })),
  };
}
