/**
 * The unguessable addresses of kept reviews (see history.ts): 18 random bytes,
 * written as 24 URL-safe characters. Web Crypto, so the same code runs on a
 * laptop and on Cloudflare Workers.
 */
export const LINK_ID = /^[A-Za-z0-9_-]{24}$/;

export function newLinkId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");
}
