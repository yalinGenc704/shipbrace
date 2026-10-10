/**
 * The small amount of cryptography sign-in needs, on Web Crypto only (it runs
 * in Workers and in Node's tests alike).
 *
 * - Session cookies are 32 random bytes. The database keeps only their
 *   SHA-256, so a leaked copy of it does not let anyone sign in.
 * - Each person's GitHub token is encrypted with AES-GCM under SESSION_KEY (a
 *   secret, 32 random bytes in base64). A leaked database without the key
 *   holds no usable tokens.
 */

const encoder = new TextEncoder();

const toBase64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** `bytes` random bytes, URL-safe. 32 bytes is the session and state size. */
export const randomToken = (bytes = 32) => toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function keyFrom(secret: string): Promise<CryptoKey> {
  const raw = fromBase64Url(secret.trim());
  if (raw.length !== 32) throw new Error("SESSION_KEY must be 32 random bytes, base64-encoded");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** `iv.ciphertext`, both base64url. A fresh random IV every time. */
export async function encrypt(secret: string, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyFrom(secret), encoder.encode(plaintext));
  return `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(sealed))}`;
}

/** Throws if the value was altered or sealed under another key. */
export async function decrypt(secret: string, sealed: string): Promise<string> {
  const [iv, body] = sealed.split(".");
  if (!iv || !body) throw new Error("not an encrypted value");
  const opened = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(iv) },
    await keyFrom(secret),
    fromBase64Url(body),
  );
  return new TextDecoder().decode(opened);
}
