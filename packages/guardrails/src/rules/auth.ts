import type { Finding, Rule } from "../types.ts";
import { dottedName, isStringLiteral, parseFile, walk, type Node } from "../analysis/ast.ts";
import { isSource, isTestPath, locate, scanLines } from "../util.ts";

/**
 * `origin: "*"` plus credentials is the combination an LLM produces when told
 * "fix the CORS error" -- it silences the browser and opens the API to every site.
 */
const permissiveCors: Rule = {
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
      title: "Your app accepts behind-the-scenes requests from any website",
      why:
        `A page on someone else's site could then use a signed-in visitor's browser to act as them. ` +
        `AI tools often add this setting just to make an error go away.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description: "Allow only your own website addresses.",
        detail:
          "Replace the CORS wildcard (`*` / `origin: true`) with an explicit list of your frontend's origins, " +
          "read from an environment variable so it can differ between test and live.",
      },
      learnMore: "/explain/cors",
    }));
  },
};

/**
 * Tokens in localStorage are readable by any script on the page, so a single XSS
 * becomes a full account takeover. httpOnly cookies are not readable by script.
 */
const tokenInLocalStorage: Rule = {
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
      title: "Your app keeps the visitor's sign-in pass where any code on the page can read it",
      why:
        `Every piece of code running on your pages can read it, including code from other companies. ` +
        `If any of that code is ever compromised, the pass can be copied and used to sign in as the visitor.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description: "Keep the sign-in pass in a cookie that code on the page cannot read.",
        detail:
          "Stop storing the token in localStorage: have the server set it as an httpOnly, Secure, " +
          "SameSite=Lax cookie, and send requests with `credentials: \"include\"` instead of an Authorization header.",
      },
      learnMore: "/explain/token-storage",
    }));
  },
};

/**
 * A login cookie set without `httpOnly` is readable by every script on the
 * page, which turns one injected script into a stolen login. Express's
 * `res.cookie` and Hono's `setCookie` do not set it unless asked. Only
 * cookies whose name says they carry a login are judged, and options built
 * elsewhere (a variable) are given the benefit of the doubt.
 */
const loginCookieReadable: Rule = {
  id: "auth/cookie-readable-by-scripts",
  category: "auth",
  severity: "high",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    if (!/cookie/i.test(file.content)) return [];
    const parsed = parseFile(file);
    if (!parsed) return [];
    const findings: Finding[] = [];
    walk(parsed.program, (node) => {
      if (node.type !== "CallExpression") return;
      const callee = dottedName(node.callee) ?? "";
      // Express/Fastify `res.cookie`, `reply.setCookie`, Hono `setCookie(c, ...)`.
      // SvelteKit and Koa set httpOnly unless told not to, so they are not judged.
      const hono = callee === "setCookie";
      if (!hono && !/^(?:res|response|reply)\.(?:cookie|setCookie)$/.test(callee)) return;
      const args = (node.arguments ?? []) as Node[];
      const [nameArg, valueArg, options] = hono ? args.slice(1) : args;
      if (!isStringLiteral(nameArg) || !LOGIN_COOKIE.test(String(nameArg.value)) || NOT_A_LOGIN.test(String(nameArg.value))) return;
      // Clearing a cookie on sign-out stores nothing worth stealing.
      if (isStringLiteral(valueArg) && String(valueArg.value) === "") return;
      if (options && options.type !== "ObjectExpression") return;
      const props = (options?.properties ?? []) as Node[];
      if (props.some((p) => p.type === "SpreadElement")) return;
      const named = (key: string): Node | undefined =>
        props.find((p) => String((p.key as Node | undefined)?.name ?? "").toLowerCase() === key.toLowerCase())?.value as Node | undefined;
      if (named("maxAge")?.value === 0) return;
      const httpOnly = named("httpOnly");
      if (httpOnly && httpOnly.value !== false) return;
      const line = file.content.slice(0, node.start).split("\n").length;
      findings.push({
        ruleId: loginCookieReadable.id,
        category: "auth",
        severity: "high",
        confidence: "likely",
        title: `The sign-in cookie \`${String(nameArg.value)}\` can be read by any code running on your page`,
        why:
          "Any code on your site -- including some slipped in through a comment or another company's " +
          "package -- can copy it and sign in as the visitor.",
        location: { path: file.path, line },
        fix: {
          kind: "manual",
          description: "Mark the cookie so that code on the page can't read it.",
          detail: "Set the cookie with `{ httpOnly: true, secure: true, sameSite: \"lax\" }`.",
        },
        learnMore: "/explain/token-storage",
      });
    });
    return findings;
  },
};

/** Cookie names that carry a login, and ones that look like it but are meant for scripts. */
const LOGIN_COOKIE = /session|token|auth|jwt|\bsid\b|login/i;
const NOT_A_LOGIN = /csrf|xsrf|expires|_at$|At$|consent|theme|lang/i;

/** A fallback secret means the app silently runs on a publicly-known signing key. */
const weakJwtSecret: Rule = {
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
      title: "If the sign-in secret is missing, your app quietly uses a backup written in the code",
      why:
        `That backup secret is visible to anyone who can read your code. With it they can sign in ` +
        `as any account, including an administrator's.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "Remove the backup secret, so the app refuses to start without the real one instead of running unprotected.",
        detail:
          "Delete the `|| \"...\"` / `?? \"...\"` fallback and throw at startup if the secret environment variable is unset.",
      },
      learnMore: "/explain/jwt-secret",
    }));
  },
};

export const authRules: Rule[] = [permissiveCors, tokenInLocalStorage, loginCookieReadable, weakJwtSecret];
