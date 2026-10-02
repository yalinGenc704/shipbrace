import { useQuery } from "@tanstack/react-query";
import { FlaskConical, Loader2 } from "lucide-react";
import { useState } from "react";
import type { Mode } from "../lib/review.ts";
import { loadReview } from "../lib/review.ts";
import { useReviewed } from "../lib/reviewed.ts";
import { ModuleCard } from "./ModuleCard.tsx";
import { Summary } from "./Summary.tsx";

export function ReviewPage() {
  const [mode, setMode] = useState<Mode>("essentials");
  const reviewed = useReviewed();

  const { data: review, isPending, error } = useQuery({
    queryKey: ["review"],
    queryFn: loadReview,
  });

  if (isPending) {
    return (
      <p className="flex items-center gap-2 p-8 text-sm text-ink-soft">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        Reviewing your application…
      </p>
    );
  }

  if (error || !review) {
    return (
      <p className="p-8 text-sm text-danger">
        The review could not be loaded. Nothing has been checked — do not treat this as a pass.
      </p>
    );
  }

  const outstanding = review.modules
    .flatMap((m) => m.items)
    .filter((i) => i.status === "needs-your-review" && !reviewed.isReviewed(i.id)).length;

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:py-12">
      <Summary
        review={review}
        mode={mode}
        onModeChange={setMode}
        outstandingReviews={outstanding}
      />

      <ol className="mt-6 space-y-3">
        {review.modules.map((module) => (
          <li key={module.id}>
            <ModuleCard module={module} mode={mode} reviewed={reviewed} />
          </li>
        ))}
      </ol>

      <Unverified items={review.unverified} />

      <p className="mt-8 text-xs leading-relaxed text-ink-soft">
        Checked {review.stats.doors} route{review.stats.doors === 1 ? "" : "s"} and{" "}
        {review.stats.sinks} sensitive operation{review.stats.sinks === 1 ? "" : "s"} in{" "}
        {Math.round(review.stats.durationMs)}ms. This review reports what it was able to check —
        it is not a guarantee that the application is secure.
      </p>
      <ModelNote model={review.stats.model} made={review.stats.proposalsMade} confirmed={review.stats.proposalsConfirmed} />
    </div>
  );
}

/**
 * What the AI step contributed, in one sentence. A refusal or an outage is
 * stated plainly: the review still ran, on rules alone, and the reader should
 * know that rather than assume the AI looked.
 */
function ModelNote({
  model,
  made,
  confirmed,
}: {
  model?: { status: "not-used" | "used" | "refused" | "failed" };
  made: number;
  confirmed: number;
}) {
  if (!model || model.status === "not-used") return null;
  const text = {
    used: `An AI model suggested ${made} place${made === 1 ? "" : "s"} to check; the automated rules confirmed ${confirmed}. Only confirmed findings are counted as risks.`,
    refused: "The AI model declined to look at this code, so this review used the automated rules alone.",
    failed: "The AI model could not be reached, so this review used the automated rules alone.",
  }[model.status];
  return <p className="mt-2 text-xs leading-relaxed text-ink-soft">{text}</p>;
}

/**
 * Model proposals the oracle could not reproduce from the code.
 *
 * Shown, because discarding a lead silently is its own failure -- but visually
 * separated, unstyled by grade, and excluded from every count. Nothing here has
 * been verified, and the section says so in its own words rather than relying
 * on the user to infer it from placement.
 */
function Unverified({ items }: { items: { door: string; rationale: string; whyNotShown: string }[] }) {
  if (items.length === 0) return null;

  return (
    <section className="mt-6 rounded-2xl border border-dashed border-line p-5">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
        <FlaskConical className="size-4 text-ink-soft" aria-hidden />
        Suggested but not confirmed
      </h2>
      <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">
        An AI model suggested these while probing your application, but the automated analysis
        could not reproduce them from your code. They are not counted as risks and may be wrong.
      </p>

      <ul className="mt-4 space-y-3">
        {items.map((item, index) => (
          <li key={`${item.door}-${index}`} className="text-sm">
            <p className="font-mono text-xs text-ink-soft">{item.door}</p>
            <p className="mt-0.5 text-ink">{item.rationale}</p>
            <p className="mt-0.5 text-ink-soft">{item.whyNotShown}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
