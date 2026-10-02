import type { ReviewResult } from "@aegis/guardrails";

/**
 * A review, as a GitHub check on the commit: a mark next to the change, a
 * plain-language summary, and notes pinned to the exact lines.
 *
 * The mark (product decision, 2026-10-01):
 *   failure  - at least one proven high risk
 *   neutral  - proven risks, none high
 *   success  - no proven risks
 * The title always says what is still left for the user, so a green tick
 * never reads as "this app is secure" -- no scanner can promise that, and the
 * checklist always holds items only a person can judge.
 */

export type Conclusion = "success" | "neutral" | "failure";

export interface Annotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
}

export interface CheckOutput {
  conclusion: Conclusion;
  title: string;
  summary: string;
  annotations: Annotation[];
}

const LEVEL = { high: "failure", medium: "warning", low: "notice" } as const;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function checkOutput(review: ReviewResult, skipped?: { overLimit: number; tooLarge: number; treeTruncated: boolean }): CheckOutput {
  const { high, medium, low, awaitingReview, unproven } = review.summary;
  const proven = high + medium + low;

  const conclusion: Conclusion = high > 0 ? "failure" : proven > 0 ? "neutral" : "success";
  const left = plural(awaitingReview, "item") + " for you to check";
  const title = high > 0
    ? `${plural(high, "high-risk problem")} to fix · ${left}`
    : proven > 0
    ? `${plural(proven, "problem")} to fix, none high-risk · ${left}`
    : `No proven problems · ${left}`;

  const lines: string[] = [];
  lines.push(
    `**${plural(proven, "proven problem")}**` +
      (proven > 0 ? ` (${high} high, ${medium} medium, ${low} low)` : "") +
      ` · **${plural(unproven, "place")} worth a look**, not proven · **${left}**`,
    "",
  );

  for (const module of review.modules) {
    const risks = module.items.flatMap((item) => item.risks);
    if (risks.length === 0) continue;
    lines.push(`### ${module.owasp} · ${module.title}`, "");
    for (const risk of risks) {
      lines.push(
        `**${risk.grade.toUpperCase()} RISK.** ${risk.what}`,
        "",
        `*Why this matters:* ${risk.impact}`,
        "",
        `*What to do:* ${risk.fix}`,
        "",
      );
    }
  }

  const notices = [...new Set(review.modules.flatMap((m) => m.items.flatMap((i) => (i.notice ? [i.notice] : []))))];
  if (skipped && (skipped.overLimit > 0 || skipped.tooLarge > 0 || skipped.treeTruncated)) {
    lines.push(
      "> **Not everything was read.** This repository is larger than one review covers, so some files were left out. Problems in them would not appear here.",
      "",
    );
  }
  lines.push(
    "---",
    "This review reports what it was able to check. It is not a guarantee that the application is secure.",
    ...notices.map((n) => `\n${n}`),
  );

  const annotations: Annotation[] = [];
  for (const module of review.modules) {
    for (const item of module.items) {
      for (const risk of item.risks) {
        if (!risk.location) continue;
        annotations.push({
          path: risk.location.path,
          start_line: risk.location.line,
          end_line: risk.location.line,
          annotation_level: LEVEL[risk.grade],
          title: `${risk.grade.toUpperCase()} RISK · ${item.title}`,
          message: `${risk.what}\n\nWhy this matters: ${risk.impact}\n\nWhat to do: ${risk.fix}`,
        });
      }
      for (const lead of item.unproven) {
        if (!lead.location) continue;
        annotations.push({
          path: lead.location.path,
          start_line: lead.location.line,
          end_line: lead.location.line,
          annotation_level: "notice",
          title: "Worth a look, not proven",
          message: `${lead.what}\n\nIf a visitor's input does reach it: ${lead.why}\n\nWhat to check: ${lead.check}`,
        });
      }
    }
  }

  // GitHub caps the summary at 65,535 characters.
  const summary = lines.join("\n");
  return {
    conclusion,
    title,
    summary: summary.length > 60_000 ? `${summary.slice(0, 60_000)}\n\n…(cut short; open the dashboard for the rest)` : summary,
    annotations,
  };
}
