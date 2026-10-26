import type { ActionItem, Grade, ReviewModule, Risk, Unproven } from "@shipbrace/guardrails";
import { ChevronRight, Eye, FileCode2 } from "lucide-react";
import type { ReactNode } from "react";
import type { Mode } from "../lib/review.ts";
import type { ReviewedState } from "../lib/reviewed.ts";
import { ExactFix, RiskCard } from "./RiskCard.tsx";
import { Checkbox, StatusPill } from "./ui.tsx";

const GRADE_ORDER: Record<Grade, number> = { high: 0, medium: 1, low: 2 };

/** Every risk in a module with its checklist item, most serious first. */
export function risksOf(module: ReviewModule): Array<{ risk: Risk; item: ActionItem }> {
  return module.items
    .flatMap((item) => item.risks.map((risk) => ({ risk, item })))
    .sort((a, b) => GRADE_ORDER[a.risk.grade] - GRADE_ORDER[b.risk.grade]);
}

/**
 * The key an "intended" mark is saved under. A risk's id is only its file and
 * line, which another commit or repository can reuse for a different page, so
 * the mark also holds the finding's own words: a changed finding is unmarked.
 */
export const intendedKey = (risk: Risk): string => `${risk.id}#${risk.what}`;

/**
 * The key a checklist tick is saved under: apart from "I've checked this", so
 * thinking a general question through never ticks off the same item where
 * another review found something in the code.
 */
export const checklistKey = (item: ActionItem): string => `checklist:${item.id}`;

export const isIntended = (risk: Risk, reviewed: ReviewedState): boolean =>
  risk.mayBeIntended === true && reviewed.isReviewed(intendedKey(risk));

/** Risks the reader has not marked as intended: what still needs fixing. */
export function liveRisks(module: ReviewModule, reviewed: ReviewedState): Risk[] {
  return module.items.flatMap((item) => item.risks).filter((risk) => !isIntended(risk, reviewed));
}

/**
 * One of the ten modules, as a collapsible section of the checklist.
 *
 * Inside, four parts in the order a reader acts on them: problems to fix,
 * most serious first across the whole module; items about this code that need
 * the reader's own check; the general checklist questions; and what passed. Items about something the app does not have are not
 * here at all -- they are listed once, at the end of the page.
 *
 * The OWASP code is shown because it lets a user (or someone they hire) look
 * the category up in a standard this product does not control.
 */
export function ModuleCard({
  module,
  mode,
  reviewed,
  open,
  onToggle,
}: {
  module: ReviewModule;
  mode: Mode;
  reviewed: ReviewedState;
  open: boolean;
  onToggle: () => void;
}) {
  const risks = risksOf(module);
  const toFix = liveRisks(module, reviewed).length;
  const yours = module.items.filter((item) => item.status === "needs-your-review");
  const outstanding = yours.filter((item) => !reviewed.isReviewed(item.id)).length;
  const checklist = module.items.filter((item) => item.status === "checklist");
  const checklistLeft = checklist.filter((item) => !reviewed.isReviewed(checklistKey(item))).length;
  const passed = module.items.filter((item) => item.status === "pass");
  const notices = [...new Set(module.items.flatMap((item) => (item.notice ? [item.notice] : [])))];
  const panelId = `module-${module.id}`;

  return (
    <section className="overflow-hidden rounded-2xl border border-line bg-surface-raised">
      <h2>
        <button
          type="button"
          onClick={onToggle}
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
            {toFix > 0 && <StatusPill status="action-needed" />}
            {toFix === 0 && outstanding > 0 && <StatusPill status="needs-your-review" />}
            {toFix === 0 && outstanding === 0 && checklistLeft > 0 && <StatusPill status="checklist" />}
            {toFix === 0 && outstanding === 0 && checklistLeft === 0 && <StatusPill status="pass" />}
            <span className="text-right text-xs text-ink-soft">
              {[toFix > 0 && `${toFix} to fix`, outstanding > 0 && `${outstanding} to check`]
                .filter(Boolean)
                .join(" · ") || "nothing outstanding"}
              {checklistLeft > 0 && (
                <span className="block">{checklistLeft} on your checklist</span>
              )}
            </span>
          </span>
        </button>
      </h2>

      {open && (
        <div id={panelId} className="space-y-6 border-t border-line p-4 sm:p-5">
          {risks.length > 0 && (
            <Part title="Needs fixing" note="Most serious first.">
              <ul className="space-y-3">
                {risks.map(({ risk, item }, index) => (
                  <li key={`${risk.id}-${index}`}>
                    <RiskCard
                      risk={risk}
                      mode={mode}
                      itemTitle={item.title}
                      intended={isIntended(risk, reviewed)}
                      {...(risk.mayBeIntended ? { onIntendedChange: () => reviewed.toggle(intendedKey(risk)) } : {})}
                    />
                  </li>
                ))}
              </ul>
            </Part>
          )}

          {yours.length > 0 && (
            <Part title="Needs your check" note="Automated checks can't settle these. Look, then tick each one off.">
              <ul className="divide-y divide-line rounded-xl border border-line">
                {yours.map((item) => (
                  <li key={item.id}>
                    <YourCheck item={item} mode={mode} reviewed={reviewed} />
                  </li>
                ))}
              </ul>
            </Part>
          )}

          {checklist.length > 0 && (
            <Part title="Your checklist" note="Good practice for every app, not something found in your code. Tick each off once you've thought it through.">
              <ul className="divide-y divide-line rounded-xl border border-dashed border-line">
                {checklist.map((item) => (
                  <li key={item.id}>
                    <ChecklistQuestion item={item} reviewed={reviewed} />
                  </li>
                ))}
              </ul>
            </Part>
          )}

          {passed.length > 0 && (
            <Part title="Checked">
              <ul className="space-y-2">
                {passed.map((item) => (
                  <li key={item.id} className="text-sm">
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-ink">{item.title}</span>
                      <StatusPill status="pass" />
                    </div>
                    {/*
                      What was checked is what makes "Checked" mean something:
                      a pass is only ever as wide as the check behind it.
                    */}
                    {item.covers && (
                      <p className="mt-1 text-xs leading-relaxed text-ink-soft">Checked: {item.covers}.</p>
                    )}
                  </li>
                ))}
              </ul>
            </Part>
          )}

          {notices.map((notice) => (
            <p key={notice} className="text-xs leading-relaxed text-ink-soft">
              {notice}
            </p>
          ))}
        </div>
      )}
    </section>
  );
}

function Part({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold tracking-wide text-ink-soft uppercase">{title}</h3>
      {note && <p className="mt-0.5 text-xs text-ink-soft">{note}</p>}
      <div className="mt-3">{children}</div>
    </div>
  );
}

/**
 * A general question. Quieter than "Needs your check" on purpose: nothing was
 * found in the code, so it carries no badge that could read as a warning
 * until it is ticked.
 */
function ChecklistQuestion({ item, reviewed }: { item: ActionItem; reviewed: ReviewedState }) {
  const ticked = reviewed.isReviewed(checklistKey(item));

  return (
    <div className="p-4">
      <div className="flex items-start justify-between gap-3">
        <h4 className="text-sm font-medium text-ink">{item.title}</h4>
        {ticked && <StatusPill status="pass" />}
      </div>
      {!ticked && (item.notApplicable ?? item.question) && (
        <p className="mt-2 text-sm leading-relaxed text-ink-soft">{item.notApplicable ?? item.question}</p>
      )}
      <div className="mt-3">
        <Checkbox
          checked={ticked}
          onChange={() => reviewed.toggle(checklistKey(item))}
          label={ticked ? "You've thought this through" : "I've thought this through"}
        />
      </div>
    </div>
  );
}

/** An item the reader owns: why it came back to them, any leads, and the tick box. */
function YourCheck({ item, mode, reviewed }: { item: ActionItem; mode: Mode; reviewed: ReviewedState }) {
  const ticked = reviewed.isReviewed(item.id);

  return (
    <div className="p-4">
      <div className="flex items-start justify-between gap-3">
        <h4 className="text-sm font-medium text-ink">{item.title}</h4>
        <StatusPill status={ticked ? "pass" : "needs-your-review"} />
      </div>

      {!ticked && item.notApplicable && (
        <p className="mt-2 text-sm leading-relaxed text-ink-soft">
          <span className="font-medium text-ink">Could not check automatically.</span> {item.notApplicable}
        </p>
      )}
      {!ticked && !item.notApplicable && item.question && (
        <p className="mt-2 text-sm leading-relaxed text-ink-soft">{item.question}</p>
      )}

      {/* Above the checkbox, because ticking it means "I looked at these". */}
      {item.unproven.length > 0 && <Leads leads={item.unproven} mode={mode} />}

      <div className="mt-3">
        <Checkbox
          checked={ticked}
          onChange={() => reviewed.toggle(item.id)}
          label={ticked ? "You marked this as checked" : "I've checked this"}
        />
      </div>
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
        These lines are written in a way that can be risky, but the automated check could not show that
        anything a visitor sends reaches them. They are not counted as problems; if unsure, the fix is
        usually small and safe to make anyway.
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
            {lead.checkDetail && <ExactFix text={lead.checkDetail} />}
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
