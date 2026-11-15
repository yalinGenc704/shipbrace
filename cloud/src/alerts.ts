/**
 * The nightly alert, by email as well as in the log (Murat's choice,
 * 2026-11-15: Cloudflare's own email service, no other company).
 *
 * The binding may only send from `ALERT_SENDER` (wrangler.jsonc). While the
 * account uses Email Routing only (not Cloudflare's paid Email Sending),
 * Cloudflare delivers only to addresses verified on the account, so even a
 * taken-over Worker can email no one else. Turning Email Sending on removes
 * that limit: add `allowed_destination_addresses` first (wrangler.jsonc).
 * The address itself is a secret (`ALERT_EMAIL`): the repository is public.
 */

/** A send that has not finished by then is given up on, so the nightly clean-up is never held up. */
const SEND_TIMEOUT_MS = 15_000;

export const ALERT_SENDER = "alerts@shipbrace.com";

/** Sends the alert line to the owner. Not set up (no binding or address): nothing to do. */
export async function emailAlert(
  email: SendEmail | undefined,
  to: string | undefined,
  line: string,
): Promise<"sent" | "not set up"> {
  if (!email || !to?.trim()) return "not set up";
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("the email service did not answer in time")), SEND_TIMEOUT_MS);
  });
  const sending = email.send({
    from: { email: ALERT_SENDER, name: "ShipBrace alerts" },
    to: to.trim(),
    subject: "ShipBrace: refused attempts in the last 24 hours",
    // The line holds counts and fixed words only (audit.ts, alertLine).
    text: `${line}\n\nThis is ShipBrace's nightly check. It emails only when 5 or more attempts were refused in a day.\n`,
  });
  try {
    await Promise.race([sending, timeout]);
  } finally {
    clearTimeout(timer);
  }
  return "sent";
}
