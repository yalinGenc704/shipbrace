import type { Risk } from "@shipbrace/guardrails";
import { Check, Copy, FileCode2, MoveRight, Undo2 } from "lucide-react";
import { useState } from "react";
import type { Mode } from "../lib/review.ts";
import { Field, GradeBadge } from "./ui.tsx";

/**
 * One confirmed risk, in the three parts a reader needs to act:
 * what is happening, why it matters, and what to do about it.
 *
 * The labels are questions a person would actually ask, not security
 * terminology. Someone who has never heard of SQL injection should be able to
 * read this and understand both the stakes and the next step. The exact,
 * code-level fix sits apart, ready to paste into an AI assistant, so the plain
 * part stays plain.
 */
export function RiskCard({
  risk,
  mode,
  itemTitle,
  intended,
  onIntendedChange,
}: {
  risk: Risk;
  mode: Mode;
  /** The checklist item this risk belongs to, shown above it. */
  itemTitle?: string;
  intended?: boolean;
  onIntendedChange?: () => void;
}) {
  if (intended) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-dashed border-line px-4 py-3 text-sm text-ink-soft">
        <span>
          <span className="font-medium text-ink">You marked this as intended:</span> {risk.what}
        </span>
        <button
          type="button"
          onClick={onIntendedChange}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium hover:text-ink"
        >
          <Undo2 className="size-3.5" aria-hidden />
          Undo
        </button>
      </div>
    );
  }

  return (
    <article className="rounded-xl border border-line bg-surface-raised p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <GradeBadge grade={risk.grade} />
          {itemTitle && <span className="text-xs font-medium text-ink-soft">{itemTitle}</span>}
        </div>

        {mode === "detailed" && risk.location && (
          <span className="inline-flex shrink-0 items-center gap-1.5 font-mono text-xs text-ink-soft">
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

      {risk.fixDetail && <ExactFix text={risk.fixDetail} />}

      {risk.mayBeIntended && onIntendedChange && (
        <button
          type="button"
          onClick={onIntendedChange}
          className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm font-medium text-ink-soft transition-colors hover:text-ink"
        >
          This is intended
        </button>
      )}

      {mode === "detailed" && <Evidence risk={risk} />}
    </article>
  );
}

/** The code-level fix, with a copy button: what the reader hands their AI assistant. */
export function ExactFix({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = (): void => {
    void navigator.clipboard
      ?.writeText(text)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {});
  };

  return (
    <div className="mt-3 rounded-lg bg-surface p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-semibold tracking-wide text-ink-soft uppercase">
          Exact fix (paste into your AI assistant)
        </p>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium text-ink-soft hover:text-ink"
        >
          {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="mt-1 font-mono text-xs leading-relaxed break-words text-ink">{text}</p>
    </div>
  );
}

const FOUND_BY: Record<Risk["confirmedBy"], string> = {
  oracle: "tracing the value through the code",
  rule: "a pattern check",
  "route-check": "checking each page for a sign-in step",
};

/**
 * Only shown in detailed mode. The excerpt is redacted upstream, so a line that
 * contained a key is safe to render here -- that redaction happens before the
 * risk object exists, not at display time, so there is no path by which the
 * real value reaches this component.
 */
function Evidence({ risk }: { risk: Risk }) {
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

      <p className="text-xs text-ink-soft">Found by {FOUND_BY[risk.confirmedBy]}.</p>
    </div>
  );
}
