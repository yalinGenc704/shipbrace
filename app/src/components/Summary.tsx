import type { ReviewResult } from "@aegis/guardrails";
import { ArcElement, Chart, Legend, Tooltip } from "chart.js";
import { Download } from "lucide-react";
import { Doughnut } from "react-chartjs-2";
import type { Mode } from "../lib/review.ts";
import { MODE_LABEL } from "../lib/review.ts";

Chart.register(ArcElement, Tooltip, Legend);

/** Reads the live theme tokens so the chart matches the rest of the page. */
function token(name: string): string {
  if (typeof window === "undefined") return "#888";
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

export function Summary({
  review,
  mode,
  onModeChange,
  outstandingReviews,
}: {
  review: ReviewResult;
  mode: Mode;
  onModeChange: (mode: Mode) => void;
  outstandingReviews: number;
}) {
  const { high, medium, low } = review.summary;
  const total = high + medium + low;

  return (
    <header className="rounded-2xl border border-line bg-surface-raised p-5 sm:p-6">
      <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-ink sm:text-2xl">Security review</h1>
          <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-ink-soft">
            {headline(total, high, outstandingReviews)}
          </p>

          <dl className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
            <Stat label="Need fixing" value={total} tone={high > 0 ? "danger" : "ok"} />
            <Stat label="Your call" value={outstandingReviews} tone="review" />
            <Stat label="Modules clear" value={`${review.summary.clear}/10`} tone="ok" />
          </dl>
        </div>

        {total > 0 && (
          <div className="size-32 shrink-0 self-center" aria-hidden>
            <Doughnut
              data={{
                labels: ["High", "Medium", "Low"],
                datasets: [
                  {
                    data: [high, medium, low],
                    backgroundColor: [token("--color-danger"), token("--color-warn"), token("--color-ink-soft")],
                    borderWidth: 0,
                  },
                ],
              }}
              options={{
                cutout: "68%",
                plugins: { legend: { display: false } },
                animation: { duration: 0 },
              }}
            />
          </div>
        )}
      </div>

      {/*
        The essentials/detailed switch. Both views render the same risks -- the
        detailed one only adds locations and traced paths, so switching can
        never surface a problem the simpler view was hiding.
      */}
      <div
        role="radiogroup"
        aria-label="How much detail to show"
        className="mt-5 inline-flex rounded-lg border border-line p-1"
      >
        {(["essentials", "detailed"] as const).map((value) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={mode === value}
            onClick={() => onModeChange(value)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              mode === value ? "bg-review text-white" : "text-ink-soft hover:text-ink"
            }`}
          >
            {MODE_LABEL[value]}
          </button>
        ))}
      </div>

      {/*
        The spreadsheet library is loaded only when someone asks for the file,
        so the page itself stays as quick to open as before.
      */}
      <button
        type="button"
        onClick={() => void import("../lib/export.ts").then(({ downloadReview }) => downloadReview(review))}
        className="mt-5 ml-3 inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-2 text-sm font-medium text-ink-soft transition-colors hover:text-ink"
      >
        <Download className="size-4" aria-hidden />
        Download as Excel
      </button>
    </header>
  );
}

/**
 * Deliberately never says "you are secure". The review can only report what it
 * checked, and 22 of the 31 items are still the user's to judge -- a headline
 * implying otherwise would be the most harmful sentence on the page.
 */
function headline(total: number, high: number, outstanding: number): string {
  if (total === 0 && outstanding === 0) {
    return "Every automated check passed and you have worked through the whole checklist.";
  }
  if (total === 0) {
    return `No problems were found by the automated checks. ${outstanding} item${
      outstanding === 1 ? "" : "s"
    } still need${outstanding === 1 ? "s" : ""} your judgement -- they cannot be checked automatically.`;
  }
  return `${total} problem${total === 1 ? "" : "s"} found${
    high > 0 ? `, ${high} of them serious` : ""
  }. Work through the modules below, starting at the top.`;
}

const TONE = {
  danger: "text-danger",
  review: "text-review",
  ok: "text-ok",
} as const;

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone: keyof typeof TONE;
}) {
  return (
    <div>
      <dt className="text-xs font-medium tracking-wide text-ink-soft uppercase">{label}</dt>
      <dd className={`text-2xl font-semibold tabular-nums ${TONE[tone]}`}>{value}</dd>
    </div>
  );
}
