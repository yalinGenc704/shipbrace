/**
 * The plain-words rule, shared by the tests that enforce it.
 *
 * ShipBrace's own sentences never use these words. The one exception is a
 * name from the reviewed code shown in code style (`sanitizeInput`): the
 * report has to name the function so it can be found. Only a single name is
 * exempt -- a whole sentence in backticks is still ShipBrace's wording -- and
 * a stray backtick, which would hide everything up to the next one, counts
 * as a leak in itself. Check one piece of text at a time, not several joined.
 */
export const JARGON = ["taint", "sink", "sanitiz", "cwe", "payload"] as const;

const NAME_IN_CODE_STYLE = /`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`/g;

/** The jargon words found in `text` outside single names in code style. */
export function leakedJargon(text: string): string[] {
  const own = text.replace(NAME_IN_CODE_STYLE, " ").toLowerCase();
  const leaked: string[] = JARGON.filter((word) => own.includes(word));
  if ((text.match(/`/g) ?? []).length % 2 === 1) leaked.push("an unpaired backtick");
  return leaked;
}
