import type { Risk } from "@aegis/guardrails";
import { FileCode2, MoveRight } from "lucide-react";
import type { Mode } from "../lib/review.ts";
import { Field, GradeBadge } from "./ui.tsx";

/**
 * One confirmed risk, in the three parts a reader needs to act:
 * what is happening, why it matters, and what to do about it.
 *
 * The labels are questions a person would actually ask, not security
 * terminology. Someone who has never heard of SQL injection should be able to
 * read this and understand both the stakes and the next step.
 */
export function RiskCard({ risk, mode }: { risk: Risk; mode: Mode }) {
  return (
    <article className="rounded-xl border border-line bg-surface-raised p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <GradeBadge grade={risk.grade} />

        {mode === "detailed" && risk.location && (
          <span className="inline-flex items-center gap-1.5 font-mono text-xs text-ink-soft">
            <FileCode2 className="size-3.5" aria-hidden />
            {risk.location.path}:{risk.location.line}
          </span>
        )}
      </div>

      <dl className="space-y-3">
        <Field label="What's happening">{risk.what}</Field>
        <Field label="Why this matters">{risk.impact}</Field>
        <Field label="What to do">{risk.fix}</Field>
      </dl>

      {mode === "detailed" && <Evidence risk={risk} />}
    </article>
  );
}

/**
 * Only shown in detailed mode. The excerpt is redacted upstream, so a line that
 * contained a key is safe to render here -- that redaction happens before the
 * risk object exists, not at display time, so there is no path by which the
 * real value reaches this component.
 */
function Evidence({ risk }: { risk: Risk }) {
  if (!risk.location?.excerpt && !risk.evidence) return null;

  return (
    <div className="mt-4 space-y-2 border-t border-line pt-3">
      {risk.location?.excerpt && (
        <pre className="overflow-x-auto rounded-lg bg-surface p-3 font-mono text-xs text-ink">
          <code>{risk.location.excerpt}</code>
        </pre>
      )}

      {risk.evidence && (
        <div>
          <p className="text-xs font-semibold tracking-wide text-ink-soft uppercase">
            How the value travels
          </p>
          <p className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-xs text-ink-soft">
            {risk.evidence.split("→").map((step, index, all) => (
              <span key={`${step}-${index}`} className="inline-flex items-center gap-1.5">
                <span className="rounded bg-surface px-1.5 py-0.5">{step.trim()}</span>
                {index < all.length - 1 && <MoveRight className="size-3" aria-hidden />}
              </span>
            ))}
          </p>
        </div>
      )}

      <p className="text-xs text-ink-soft">
        Found by{" "}
        {risk.confirmedBy === "oracle"
          ? "tracing the value through the code"
          : "a pattern check"}
        .
      </p>
    </div>
  );
}
