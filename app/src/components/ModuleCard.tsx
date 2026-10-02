import type { ActionItem, ReviewModule, Unproven } from "@aegis/guardrails";
import { ChevronRight, Eye, FileCode2 } from "lucide-react";
import { useState } from "react";
import type { Mode } from "../lib/review.ts";
import type { ReviewedState } from "../lib/reviewed.ts";
import { RiskCard } from "./RiskCard.tsx";
import { Checkbox, StatusPill } from "./ui.tsx";

/**
 * One of the ten modules, as a collapsible section of the checklist.
 *
 * Modules with something outstanding start open and the rest start closed, so
 * the page opens on the work rather than on a wall of green. The OWASP code is
 * shown because it lets a user (or someone they hire) look the category up in
 * a standard this product does not control.
 */
export function ModuleCard({
  module,
  mode,
  reviewed,
}: {
  module: ReviewModule;
  mode: Mode;
  reviewed: ReviewedState;
}) {
  const risks = module.items.flatMap((item) => item.risks);
  const outstanding = module.items.filter(
    (item) => item.status === "needs-your-review" && !reviewed.isReviewed(item.id),
  ).length;

  const leads = module.items.flatMap((item) => item.unproven ?? []);
  const [open, setOpen] = useState(risks.length > 0 || leads.length > 0);
  const panelId = `module-${module.id}`;

  return (
    <section className="overflow-hidden rounded-2xl border border-line bg-surface-raised">
      <h2>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-surface sm:p-5"
        >
          <ChevronRight
            className={`mt-0.5 size-5 shrink-0 text-ink-soft transition-transform ${open ? "rotate-90" : ""}`}
            aria-hidden
          />

          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-xs text-ink-soft">
                {module.owasp}
              </span>
              <span className="text-base font-semibold text-ink">{module.title}</span>
            </span>
            <span className="mt-1.5 block text-sm leading-relaxed text-ink-soft">
              {module.summary}
            </span>
          </span>

          <span className="flex shrink-0 flex-col items-end gap-1.5">
            {risks.length > 0 && <StatusPill status="action-needed" />}
            {risks.length === 0 && outstanding > 0 && <StatusPill status="needs-your-review" />}
            {risks.length === 0 && outstanding === 0 && <StatusPill status="pass" />}
            <span className="text-xs text-ink-soft">
              {risks.length > 0 && `${risks.length} to fix`}
              {risks.length === 0 && outstanding > 0 && `${outstanding} to check`}
              {risks.length === 0 && outstanding === 0 && "nothing outstanding"}
            </span>
          </span>
        </button>
      </h2>

      {open && (
        <div id={panelId} className="border-t border-line">
          <ul className="divide-y divide-line">
            {module.items.map((item) => (
              <li key={item.id}>
                <Item item={item} mode={mode} reviewed={reviewed} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Item({
  item,
  mode,
  reviewed,
}: {
  item: ActionItem;
  mode: Mode;
  reviewed: ReviewedState;
}) {
  const ticked = reviewed.isReviewed(item.id);
  const status = item.status === "needs-your-review" && ticked ? "pass" : item.status;

  return (
    <div className="p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-sm font-medium text-ink">{item.title}</h3>
        <StatusPill status={status} />
      </div>

      {/*
        The question belongs to an item the user still owns. Showing it on a
        passing item would read as an unanswered request on something already
        settled.
      */}
      {item.status === "needs-your-review" && !ticked && (
        <>
          {item.notApplicable && (
            <p className="mt-2 text-sm leading-relaxed text-ink-soft">
              <span className="font-medium text-ink">Could not check automatically.</span>{" "}
              {item.notApplicable}
            </p>
          )}
          {item.question && (
            <p className="mt-2 text-sm leading-relaxed text-ink-soft">{item.question}</p>
          )}
        </>
      )}

      {item.notice && <p className="mt-2 text-xs leading-relaxed text-ink-soft">{item.notice}</p>}

      {/* Above the checkbox, because ticking it means "I looked at these". */}
      {(item.unproven ?? []).length > 0 && <Leads leads={item.unproven} mode={mode} />}

      {item.status === "needs-your-review" && (
        <div className="mt-3">
          <Checkbox
            checked={ticked}
            onChange={() => reviewed.toggle(item.id)}
            label={ticked ? "You marked this as checked" : "I've checked this"}
          />
        </div>
      )}

      {/*
        Naming the detector on a passing item is what makes "Checked" mean
        something. An item with no detector is never shown as passed by the
        engine, so this only ever describes a check that really ran.
      */}
      {item.status === "pass" && item.covers && (
        <p className="mt-2 text-xs leading-relaxed text-ink-soft">Checked: {item.covers}.</p>
      )}
      {item.status === "pass" && mode === "detailed" && item.detector && (
        <p className="mt-1 font-mono text-xs text-ink-soft">checked by {item.detector}</p>
      )}

      {item.risks.length > 0 && (
        <ul className="mt-4 space-y-3">
          {item.risks.map((risk) => (
            <li key={risk.id}>
              <RiskCard risk={risk} mode={mode} />
            </li>
          ))}
        </ul>
      )}

    </div>
  );
}

/**
 * Lines that are written in a risky way, where nothing proved a visitor's
 * input reaches them.
 *
 * Deliberately not a risk card: no grade, no "needs fixing", a dashed outline,
 * and a sentence saying in plain words that this is unproven. Everything styled
 * as a risk has been traced; keeping that true is what lets a user trust the
 * red badges without second-guessing each one.
 */
function Leads({ leads, mode }: { leads: Unproven[]; mode: Mode }) {
  return (
    <div className="mt-4 rounded-xl border border-dashed border-line p-4">
      <p className="flex items-center gap-2 text-sm font-semibold text-ink">
        <Eye className="size-4 text-ink-soft" aria-hidden />
        Worth a look, not proven
      </p>
      <p className="mt-1 text-sm leading-relaxed text-ink-soft">
        These lines are written in a way that can be risky, but the automated check could not
        show that anything a visitor sends reaches them. They are not counted as risks. If you
        are unsure, the fix is usually small and safe to make anyway.
      </p>

      <ul className="mt-3 space-y-3">
        {leads.map((lead) => (
          <li key={lead.id} className="text-sm">
            <p className="text-ink">{lead.what}</p>
            <p className="mt-1 leading-relaxed text-ink-soft">
              <span className="font-medium text-ink">If a visitor's input does reach it: </span>
              {lead.why}
            </p>
            <p className="mt-1 leading-relaxed text-ink-soft">
              <span className="font-medium text-ink">What to check: </span>
              {lead.check}
            </p>
            {mode === "detailed" && lead.location?.excerpt && (
              <div className="mt-2">
                <p className="inline-flex items-center gap-1.5 font-mono text-xs text-ink-soft">
                  <FileCode2 className="size-3.5" aria-hidden />
                  {lead.location.path}:{lead.location.line}
                </p>
                <pre className="mt-1 overflow-x-auto rounded-lg bg-surface p-3 font-mono text-xs text-ink">
                  <code>{lead.location.excerpt}</code>
                </pre>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
