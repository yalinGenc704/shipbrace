import type { ReviewResult } from "@shipbrace/guardrails";
import { useQuery } from "@tanstack/react-query";
import { ChevronsDownUp, ChevronsUpDown, CircleSlash, FlaskConical } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { Mode } from "../lib/review.ts";
import { loadReview } from "../lib/review.ts";
import { useReviewed } from "../lib/reviewed.ts";
import { Home } from "./Home.tsx";
import { checklistKey, liveRisks, ModuleCard } from "./ModuleCard.tsx";
import { Loading, StatusPill } from "./ui.tsx";
import { Summary } from "./Summary.tsx";

export function ReviewPage() {
  const { data: review, isPending, error } = useQuery({
    queryKey: ["review"],
    queryFn: loadReview,
  });

  if (isPending) return <Loading>Reviewing your application…</Loading>;

  if (review === null) return <Home />;

  if (error || !review) {
    return (
      <p className="p-8 text-sm text-danger">
        The review could not be loaded. Nothing has been checked — do not treat this as a pass.
      </p>
    );
  }

  return <ReviewView review={review} />;
}

/**
 * One review, wherever it came from: computed just now, or kept from a push.
 * `context` sits above it and says which review this is.
 */
export function ReviewView({ review, context }: { review: ReviewResult; context?: ReactNode }) {
  const [mode, setMode] = useState<Mode>("essentials");
  const reviewed = useReviewed();

  const items = review.modules.flatMap((m) => m.items);
  const outstanding = items.filter((i) => i.status === "needs-your-review" && !reviewed.isReviewed(i.id)).length;
  const checklist = items.filter((i) => i.status === "checklist");
  const checklistTicked = checklist.filter((i) => reviewed.isReviewed(checklistKey(i))).length;
  // Risks the reader marked as intended no longer count as needing a fix.
  const live = review.modules.flatMap((m) => liveRisks(m, reviewed));

  // Modules with something to fix or check start open; the rest start closed.
  const [open, setOpen] = useState<Set<string>>(
    () =>
      new Set(
        review.modules
          .filter((m) => m.items.some((i) => i.risks.length > 0 || i.unproven.length > 0))
          .map((m) => m.id),
      ),
  );
  const allClosed = open.size === 0;
  const toggle = (id: string): void =>
    setOpen((previous) => {
      const next = new Set(previous);
      if (!next.delete(id)) next.add(id);
      return next;
    });

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:py-12">
      {context}
      <Summary
        review={review}
        mode={mode}
        onModeChange={setMode}
        outstandingReviews={outstanding}
        checklist={{ ticked: checklistTicked, total: checklist.length }}
        live={live}
      />

      <div className="mt-6 flex justify-end">
        <button
          type="button"
          onClick={() => setOpen(allClosed ? new Set(review.modules.map((m) => m.id)) : new Set())}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm font-medium text-ink-soft transition-colors hover:text-ink"
        >
          {allClosed
            ? <ChevronsUpDown className="size-4" aria-hidden />
            : <ChevronsDownUp className="size-4" aria-hidden />}
          {allClosed ? "Expand all" : "Collapse all"}
        </button>
      </div>

      <ol className="mt-3 space-y-3">
        {review.modules.map((module) => (
          <li key={module.id}>
            <ModuleCard
              module={module}
              mode={mode}
              reviewed={reviewed}
              open={open.has(module.id)}
              onToggle={() => toggle(module.id)}
            />
          </li>
        ))}
      </ol>

      <DoesNotApply review={review} />

      <Unverified items={review.unverified} />

      <p className="mt-8 text-xs leading-relaxed text-ink-soft">
        Looked at {review.stats.doors} page{review.stats.doors === 1 ? "" : "s"} and action
        {review.stats.doors === 1 ? "" : "s"}, and {review.stats.sinks} place{review.stats.sinks === 1 ? "" : "s"} where
        your code does something risky (database, files, commands and so on), in{" "}
        {Math.round(review.stats.durationMs)}ms. This review reports what it was able to check — it is not a
        guarantee that the application is secure.
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
        An AI model suggested these while looking over your code, but the automated checks could not
        confirm them. They are not counted as risks and may be wrong.
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

/**
 * Items about something this app does not have (no Supabase, no passwords),
 * gathered in one place at the end. They are not passes -- nothing was
 * checked -- and not the reader's to decide, so they stay out of the modules
 * and out of every count. Each says why, so a wrong guess is easy to spot.
 */
function DoesNotApply({ review }: { review: ReviewResult }) {
  const items = review.modules.flatMap((module) =>
    module.items.filter((item) => item.status === "does-not-apply").map((item) => ({ module, item }))
  );
  const [open, setOpen] = useState(false);
  if (items.length === 0) return null;

  return (
    <section className="mt-6 rounded-2xl border border-line bg-surface-raised">
      <h2>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-surface sm:p-5"
        >
          <CircleSlash className="mt-0.5 size-5 shrink-0 text-ink-soft" aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="text-base font-semibold text-ink">Doesn't apply to this app ({items.length})</span>
            <span className="mt-1.5 block text-sm leading-relaxed text-ink-soft">
              These checks are about things this app doesn't seem to have, so there was nothing to check. If
              one of them is wrong, check that item yourself.
            </span>
          </span>
        </button>
      </h2>
      {open && (
        <ul className="divide-y divide-line border-t border-line">
          {items.map(({ module, item }) => (
            <li key={item.id} className="p-4 sm:px-5">
              <div className="flex items-start justify-between gap-3">
                <span className="text-sm font-medium text-ink">
                  <span className="mr-2 rounded bg-surface px-1.5 py-0.5 font-mono text-xs text-ink-soft">
                    {module.owasp}
                  </span>
                  {item.title}
                </span>
                <StatusPill status="does-not-apply" />
              </div>
              {item.notApplicable && <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">{item.notApplicable}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
