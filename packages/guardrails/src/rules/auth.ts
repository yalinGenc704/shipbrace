import type { Finding, Rule } from "../types.ts";
import { isSource, isTestPath, locate, scanLines } from "../util.ts";

/**
 * `origin: "*"` plus credentials is the combination an LLM produces when told
 * "fix the CORS error" -- it silences the browser and opens the API to every site.
 */
export const permissiveCors: Rule = {
  id: "auth/permissive-cors",
  category: "auth",
  severity: "high",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    const re = /origin\s*:\s*(['"`]\*['"`]|true)|Access-Control-Allow-Origin['"`]?\s*[,:]\s*['"`]\*/;

    return scanLines(file, re).map((hit): Finding => ({
      ruleId: permissiveCors.id,
      category: "auth",
      severity: "high",
      confidence: "likely",
      title: "Any website is allowed to call your API",
      why:
        `This sets the allowed origin to "any". A page on an unrelated site can then make ` +
        `requests to your server, and if it does so with a logged-in visitor's browser, it ` +
        `can act as that user. During development this looks like it simply made an error ` +
        `go away.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "Replace the wildcard with an explicit list of the domains your own frontend is " +
          "served from, read from an environment variable so it differs per environment.",
      },
      learnMore: "/explain/cors",
    }));
  },
};

/**
 * Tokens in localStorage are readable by any script on the page, so a single XSS
 * becomes a full account takeover. httpOnly cookies are not readable by script.
 */
export const tokenInLocalStorage: Rule = {
  id: "auth/token-in-localstorage",
  category: "auth",
  severity: "high",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    const re = /localStorage\.setItem\(\s*['"`][^'"`]*(token|jwt|auth|session|refresh)[^'"`]*['"`]/i;

    return scanLines(file, re).map((hit): Finding => ({
      ruleId: tokenInLocalStorage.id,
      category: "auth",
      severity: "high",
      confidence: "likely",
      title: "The login token is stored where any script on the page can read it",
      why:
        `Browser local storage is readable by every piece of JavaScript running on your ` +
        `site, including code pulled in from third parties. If any of it is ever ` +
        `compromised, the stored token can be copied and used to log in as that user. ` +
        `A cookie marked httpOnly cannot be read by scripts at all.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "Have the server set the token as an httpOnly, Secure, SameSite=Lax cookie, and " +
          "send requests with `credentials: \"include\"` instead of attaching a header.",
      },
      learnMore: "/explain/token-storage",
    }));
  },
};

/** A fallback secret means the app silently runs on a publicly-known signing key. */
export const weakJwtSecret: Rule = {
  id: "auth/default-jwt-secret",
  category: "auth",
  severity: "critical",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    // JWT_SECRET read from env with a hardcoded `||` / `??` fallback.
    const re = /(?:JWT_SECRET|TOKEN_SECRET|AUTH_SECRET)\s*(?:\]|\))?\s*(?:\|\||\?\?)\s*['"`]([^'"`]+)['"`]/i;

    return scanLines(file, re).map((hit): Finding => ({
      ruleId: weakJwtSecret.id,
      category: "auth",
      severity: "critical",
      confidence: "certain",
      title: "Login tokens fall back to a signing key written in the code",
      why:
        `The signing key is what proves a login token is genuine. This line supplies a ` +
        `built-in value to use when the real one is missing, so a misconfigured deploy ` +
        `starts up successfully using a key that is published in your repository. Anyone ` +
        `who reads it can mint a token for any account, including an administrator's.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "Remove the fallback and exit at startup if the variable is unset, so a " +
          "misconfigured deploy fails loudly instead of running insecurely.",
      },
      learnMore: "/explain/jwt-secret",
    }));
  },
};

export const authRules: Rule[] = [permissiveCors, tokenInLocalStorage, weakJwtSecret];
