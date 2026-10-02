import { createHmac, createSign, timingSafeEqual } from "node:crypto";

/**
 * Proving who is talking, in both directions.
 *
 * GitHub signs every webhook with a secret shared when the App is created;
 * anything without a valid signature is someone else pretending to be GitHub
 * and is refused before its body is even parsed. In the other direction, the
 * App proves itself to GitHub with a short-lived token signed by its private
 * key, then trades that for a one-hour token scoped to one installation --
 * the narrowest credential that can read that repository.
 */

/** `X-Hub-Signature-256` is `sha256=<hex HMAC of the raw body>`. */
export function verifyWebhookSignature(secret: string, rawBody: string, header: string | undefined): boolean {
  if (!header?.startsWith("sha256=")) return false;
  const expected = createHmac("sha256", secret).update(rawBody, "utf8").digest();
  let given: Buffer;
  try {
    given = Buffer.from(header.slice("sha256=".length), "hex");
  } catch {
    return false;
  }
  // Same length first: timingSafeEqual throws otherwise, and a length check
  // reveals nothing an attacker does not already know.
  return given.length === expected.length && timingSafeEqual(given, expected);
}

const base64url = (input: Buffer | string) =>
  Buffer.from(input).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

/**
 * The App's own token: RS256, at most ten minutes long. Backdated a minute
 * because GitHub rejects tokens "issued in the future" when clocks drift.
 */
export function appJwt(appId: string, privateKeyPem: string, nowSeconds = Math.floor(Date.now() / 1000)): string {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 9 * 60, iss: appId }));
  const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKeyPem);
  return `${header}.${payload}.${base64url(signature)}`;
}
