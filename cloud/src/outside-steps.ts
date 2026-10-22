/** The steps a review may take outside its container: the AI's suggestions, and the package lookup. */
export type OutsideStep = "propose" | "lookup";

/**
 * Whether a review may use an outside step now: only one it was allowed
 * before it started, and only once. No list recorded means nothing allowed.
 */
export function mayAsk(allowed: readonly string[] | undefined, alreadyAsked: boolean, step: string): boolean {
  return !alreadyAsked && (allowed ?? []).includes(step);
}
