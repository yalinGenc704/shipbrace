import type { ReviewResult } from "@shipbrace/guardrails";

/**
 * A review, as a GitHub check on the commit: a mark next to the change, a
 * plain-language summary, and notes pinned to the exact lines.
 *
 * The mark (product decision, 2026-10-01):
 *   failure  - at least one proven high risk
 *   neutral  - proven risks, none high; or no proven risks, but an AI's
 *              opinion alone moved a traced finding to "worth a look" (the
 *              optional cleaner step; Murat's decision, 2026-11-10). A model
 *              saying "this is fine" never produces a green tick.
 *   success  - no proven risks, and nothing softened by an AI
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
/** The grade as shown, from a fixed list: never the review's own text. */
const GRADE_WORD: Record<string, string> = { high: "HIGH RISK", medium: "MEDIUM RISK", low: "LOW RISK" };

/**
 * Review text quotes the reviewed repository (file paths, page addresses),
 * which anyone who can push there controls, and comes from the container
 * that read it. In the markdown summary it must not open links or images,
 * carry HTML, or end a code span early.
 *
 * - A run of backticks becomes one: GitHub pairs runs of equal length, so
 *   three in a row would otherwise open a span this function never sees.
 * - Outside code spans, markup characters are escaped, and a bare web
 *   address is broken (`https\://`, `www\.`) so GitHub does not turn it
 *   into a link on its own.
 */
const inline = (text: string): string =>
  String(text)
    .replace(/[\r\n]+/g, " ")
    .replace(/`+/g, "`")
    // Only outside code spans: inside one, a backslash would show literally.
    .split(/(`[^`]*`)/)
    .map((part, i) =>
      i % 2 === 1
        ? part
        : part
          .replace(/([\\[\]!<>`@#|*_~])/g, "\\$1")
          .replace(/:\/\//g, "\\://")
          .replace(/\bwww\./gi, "www\\."),
    )
    .join("");
const codeSpan = (text: string): string => `\`${text.replace(/[\r\n]+/g, " ").replace(/`/g, "'")}\``;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function checkOutput(review: ReviewResult, skipped?: { overLimit: number; tooLarge: number; treeTruncated: boolean }): CheckOutput {
  const { high, medium, low, awaitingReview, unproven } = review.summary;
  const proven = high + medium + low;

  // Traced findings the optional AI step moved to "worth a look" because it
  // thought the app's own cleaning function works: an opinion, not proof.
  const softened = review.modules
    .flatMap((m) => m.items.flatMap((i) => i.unproven))
    .filter((lead) => lead.id.startsWith("cleaner/")).length;

  const conclusion: Conclusion = high > 0 ? "failure" : proven > 0 || softened > 0 ? "neutral" : "success";
  const checklist = review.summary.checklist ?? 0;
  const left = plural(awaitingReview, "item") + " for you to check" +
    (checklist > 0 ? ` · ${plural(checklist, "good-practice question")}` : "");
  const title = high > 0
    ? `${plural(high, "high-risk problem")} to fix · ${left}`
    : proven > 0
    ? `${plural(proven, "problem")} to fix, none high-risk · ${left}`
    : softened > 0
    ? `${plural(softened, "finding")} an AI thinks ${softened === 1 ? "is" : "are"} safe, for you to confirm · ${left}`
    : `No proven problems · ${left}`;

  const lines: string[] = [];
  lines.push(
    `**${plural(proven, "proven problem")}**` +
      (proven > 0 ? ` (${high} high, ${medium} medium, ${low} low)` : "") +
      ` · **${plural(unproven, "place")} worth a look**, not proven · **${left}**`,
    "",
  );

  if (softened > 0) {
    lines.push(
      `> **An AI's opinion is waiting for you to confirm.** In ${plural(softened, "place")}, the checker traced a visitor's value ` +
        "to a risky operation through a cleaning function your app wrote itself, and an AI that read the function thought it makes " +
        'the value safe. That is an opinion, not proof, so the finding is listed under "worth a look" and this check is not marked as passed.',
      "",
    );
  }
  const cleanerStep = review.stats.cleaners;
  if (cleanerStep && cleanerStep.status !== "used") {
    lines.push(
      `> The AI ${cleanerStep.status === "refused" ? "declined to read" : "could not be reached to read"} your app's own cleaning ` +
        "functions this time, so they were judged by the automated rules alone.",
      "",
    );
  }

  for (const module of review.modules) {
    const order = { high: 0, medium: 1, low: 2 } as const;
    const risks = module.items.flatMap((item) => item.risks).sort((x, y) => order[x.grade] - order[y.grade]);
    if (risks.length === 0) continue;
    lines.push(`### ${inline(module.owasp)} · ${inline(module.title)}`, "");
    for (const risk of risks) {
      // The sentence names the page; the file and line are added here, since a
      // check has no "show me the code" view.
      const where = risk.location ? ` (${codeSpan(risk.location.path)} line ${Number(risk.location.line) || 0})` : "";
      lines.push(
        `**${GRADE_WORD[risk.grade] ?? "RISK"}.** ${inline(risk.what)}${where}`,
        "",
        `*Why this matters:* ${inline(risk.impact)}`,
        "",
        `*What to do:* ${inline(risk.fix)}`,
        "",
        ...(risk.fixDetail ? [`*Exact fix (paste into your AI assistant):* ${inline(risk.fixDetail)}`, ""] : []),
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
    ...notices.map((n) => `\n${inline(n)}`),
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
          message: `${risk.what}\n\nWhy this matters: ${risk.impact}\n\nWhat to do: ${risk.fix}` +
            (risk.fixDetail ? `\n\nExact fix (paste into your AI assistant): ${risk.fixDetail}` : ""),
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
          message: `${lead.what}\n\nIf a visitor's input does reach it: ${lead.why}\n\nWhat to check: ${lead.check}` +
            (lead.checkDetail ? `\n\nExact fix (paste into your AI assistant): ${lead.checkDetail}` : ""),
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
