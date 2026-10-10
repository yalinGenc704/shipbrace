import type { ReviewResult } from "@shipbrace/guardrails";
import { utils, writeFile } from "xlsx";

/**
 * The review as a spreadsheet, so it can be handed to a developer, a client,
 * or an auditor who will never open the dashboard.
 *
 * One row per thing to act on -- each risk, each lead, and each item left for
 * the user -- in the same plain words the page uses. Items that passed are
 * listed too, with what was checked, so the file is a complete record rather
 * than a list of only the bad news.
 */

const STATUS = {
  "action-needed": "Needs fixing",
  "needs-your-review": "Your call",
  pass: "Checked",
} as const;

/**
 * Spreadsheet programs run cells that start with = + - @ as formulas. Review
 * text quotes code from the reviewed repository, which is untrusted, so every
 * cell is made plain text before it is written.
 */
const FORMULA_START = /^[=+\-@\t\r]/;
const asText = (value: string): string => (FORMULA_START.test(value) ? `'${value}` : value);

type Row = Record<string, string>;

export function downloadReview(review: ReviewResult, filename = "security-review.xlsx"): void {
  const rows: Row[] = [];

  for (const module of review.modules) {
    const section = `${module.owasp} ${module.title}`;

    for (const item of module.items) {
      const base = { Section: section, "Checklist item": item.title, Status: STATUS[item.status] };

      for (const risk of item.risks) {
        rows.push({
          ...base,
          Risk: `${risk.grade[0]!.toUpperCase()}${risk.grade.slice(1)}`,
          "What's happening": risk.what,
          "Why this matters": risk.impact,
          "What to do": risk.fix,
          Where: risk.location ? `${risk.location.path} line ${risk.location.line}` : "",
        });
      }
      for (const lead of item.unproven ?? []) {
        rows.push({
          ...base,
          Risk: "Worth a look, not proven",
          "What's happening": lead.what,
          "Why this matters": lead.why,
          "What to do": lead.check,
          Where: lead.location ? `${lead.location.path} line ${lead.location.line}` : "",
        });
      }
      if (item.risks.length === 0 && (item.unproven ?? []).length === 0) {
        rows.push({
          ...base,
          Risk: "",
          "What's happening":
            item.status === "pass"
              ? `Checked: ${item.covers ?? "an automated check ran and found nothing"}.`
              : (item.notApplicable ?? item.question ?? ""),
          "Why this matters": "",
          "What to do": item.status === "pass" ? "" : "Check this yourself and mark it as checked.",
          Where: "",
        });
      }
    }
  }

  const safe = rows.map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, asText(v)])));
  const sheet = utils.json_to_sheet(safe);
  sheet["!cols"] = [{ wch: 34 }, { wch: 44 }, { wch: 14 }, { wch: 22 }, { wch: 70 }, { wch: 60 }, { wch: 60 }, { wch: 32 }];

  const book = utils.book_new();
  utils.book_append_sheet(book, sheet, "Security review");
  writeFile(book, filename);
}
