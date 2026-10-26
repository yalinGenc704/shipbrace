import type { Grade, ItemStatus } from "@shipbrace/guardrails";
import { AlertTriangle, Check, CircleHelp, CircleSlash, ListChecks, Loader2, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

/**
 * Status vocabulary, in the words a non-technical reader needs.
 *
 * Note the deliberate asymmetry: a failed check says what to do ("Needs
 * fixing"), an unchecked item says whose job it is ("Needs your check"), a
 * general good-practice question says it belongs to every app ("Checklist"), a
 * passed check names the thing that checked it, and an item about something
 * the app does not have says so ("Doesn't apply") without looking like a pass. Nothing says "secure" -- no scanner
 * can promise that, and a badge that implies it would be the most damaging
 * thing on the page.
 */
const STATUS: Record<ItemStatus, { label: string; className: string; icon: ReactNode }> = {
  "action-needed": {
    label: "Needs fixing",
    className: "bg-danger-bg text-danger",
    icon: <AlertTriangle className="size-3.5" aria-hidden />,
  },
  "needs-your-review": {
    label: "Needs your check",
    className: "bg-review-bg text-review",
    icon: <CircleHelp className="size-3.5" aria-hidden />,
  },
  checklist: {
    label: "Checklist",
    className: "bg-surface text-ink-soft",
    icon: <ListChecks className="size-3.5" aria-hidden />,
  },
  pass: {
    label: "Checked",
    className: "bg-ok-bg text-ok",
    icon: <ShieldCheck className="size-3.5" aria-hidden />,
  },
  "does-not-apply": {
    label: "Doesn't apply",
    className: "bg-surface text-ink-soft",
    icon: <CircleSlash className="size-3.5" aria-hidden />,
  },
};

export function StatusPill({ status }: { status: ItemStatus }) {
  const { label, className, icon } = STATUS[status];

  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${className}`}
    >
      {icon}
      {label}
    </span>
  );
}

const GRADE: Record<Grade, { label: string; className: string }> = {
  high: { label: "High risk", className: "bg-danger text-white" },
  medium: { label: "Medium risk", className: "bg-warn text-white" },
  low: { label: "Low risk", className: "bg-ink-soft text-white" },
};

export function GradeBadge({ grade }: { grade: Grade }) {
  const { label, className } = GRADE[grade];

  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide uppercase ${className}`}
    >
      {label}
    </span>
  );
}

/** A one-line "working on it" message, used while a page loads. */
export function Loading({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-center gap-2 p-8 text-sm text-ink-soft">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      {children}
    </p>
  );
}

/** One labelled paragraph of a risk explanation. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-semibold tracking-wide text-ink-soft uppercase">{label}</dt>
      <dd className="mt-1 text-sm leading-relaxed text-ink">{children}</dd>
    </div>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
}) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-ink-soft select-none">
      <span
        className={`flex size-5 items-center justify-center rounded-md border transition-colors ${
          checked ? "border-ok bg-ok text-white" : "border-line bg-surface-raised"
        }`}
      >
        {checked && <Check className="size-3.5" aria-hidden />}
      </span>
      <input type="checkbox" checked={checked} onChange={onChange} className="sr-only" />
      {label}
    </label>
  );
}
