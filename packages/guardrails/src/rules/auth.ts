import type { Finding, Rule, SourceFile } from "../types.ts";
import { codeOnlyLines, dottedName, isStringLiteral, locationOf, parseFile, textOf, walk, type Node } from "../analysis/ast.ts";
import { isSource, isTestPath, locate, scanLines, type LineHit } from "../util.ts";

/**
 * Lines where `re` matches real code, not a comment or a sentence in quotes.
 * Each rule here looks for a danger, so text about the danger -- a message
 * telling someone to remove `origin: true`, sample code kept as text -- must
 * not count as the danger itself. `inCode` is the part that must be real code,
 * when the rest of the pattern reads inside quotes (a key named 'auth token').
 */
function codeHits(file: SourceFile, re: RegExp, inCode: RegExp = re): LineHit[] {
  const code = codeOnlyLines(file);
  return scanLines(file, re).filter((hit) => {
    inCode.lastIndex = 0;
    return inCode.test(code[hit.line - 1] ?? "");
  });
}

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
    const choices = corsChoiceLines(file);

    // One setting per line is told apart; a line holding two is kept as a risk.
    const single = (hit: LineHit) => (hit.text.match(new RegExp(re.source, "g")) ?? []).length === 1;
    return codeHits(file, re).map((hit): Finding => choices.has(hit.line) && single(hit) ? corsChoice(file, hit) : ({
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
 * Lines where an "every website" setting is one side of a choice (`a ? {
 * origin: true } : b`): a library or framework translating a setting its
 * user picks, whose default may be off. Which side runs is not in this code,
 * so it is worth a look rather than a proven risk. Written straight into
 * `cors(...)` or a single object, it stays a risk.
 */
function corsChoiceLines(file: SourceFile): Set<number> {
  const lines = new Set<number>();
  const parsed = parseFile(file);
  if (!parsed) return lines;
  walk(parsed.program, (node, parents) => {
    if (node.type !== "Property" || dottedName(node.key) !== "origin") return;
    const value = node.value as Node | undefined;
    const [object, choice] = parents;
    if (!allowsAll(value) || object?.type !== "ObjectExpression" || choice?.type !== "ConditionalExpression") return;
    const other = choice.consequent === object ? choice.alternate : choice.alternate === object ? choice.consequent : undefined;
    // Handed straight to cors(), nothing and a setting with no origin are its default: every website.
    const intoCors = parents[2]?.type === "CallExpression" && /cors/i.test(dottedName(parents[2].callee) ?? "");
    if (!other || permissiveChoice(other as Node, intoCors)) return;
    // A choice made on which environment this is (live, development, test) is
    // no doubt about the live site: one side of it is the live site.
    if (/prod|dev|test|local|stag|NODE_ENV|environment/i.test(textOf(parsed, choice.test as Node))) return;
    lines.add(locationOf(parsed, node).line);
  });
  return lines;
}

const allowsAll = (value: Node | undefined): boolean =>
  (value?.type === "Literal" && value.value === true) || (isStringLiteral(value) && value.value === "*");

/**
 * Whether a branch also lets every website in: an object allowing all,
 * `true`, `"*"`, or nothing at all (`undefined`), which is the cors
 * package's own default of every website; handed straight to `cors()`,
 * `null` and a setting with no origin are that default too. Nested choices
 * count when any of their branches does.
 */
function permissiveChoice(branch: Node, intoCors: boolean): boolean {
  if (allowsAll(branch)) return true;
  if (branch.type === "Identifier" && branch.name === "undefined") return true;
  if (branch.type === "UnaryExpression" && branch.operator === "void") return true;
  if (intoCors && branch.type === "Literal" && branch.value === null) return true;
  if (branch.type === "ConditionalExpression") {
    return permissiveChoice(branch.consequent as Node, intoCors) || permissiveChoice(branch.alternate as Node, intoCors);
  }
  if (branch.type === "ObjectExpression") {
    const properties = (branch.properties ?? []) as Node[];
    const origin = properties.find((p) => p.type === "Property" && dottedName(p.key) === "origin");
    if (origin) return allowsAll(origin.value as Node);
    // No origin of its own: the cors default when handed to it, or unknown with a spread.
    return intoCors || properties.some((p) => p.type === "SpreadElement");
  }
  return false;
}

const corsChoice = (file: SourceFile, hit: LineHit): Finding => ({
  ruleId: "auth/permissive-cors-option",
  category: "auth",
  severity: "medium",
  confidence: "possible",
  title: "One setting lets any website send requests on a signed-in visitor's behalf",
  why:
    "The code chooses between settings, and one choice accepts requests from every website. " +
    "Whether your live site uses it depends on how the app is set up.",
  location: locate(file, hit),
  fix: {
    kind: "manual",
    description: "Confirm your live site uses the choice that allows only your own website addresses.",
    detail:
      "Check which branch of this conditional CORS setting runs in production; if it is the `origin: true` / `*` one, " +
      "configure an explicit list of your frontend's origins instead.",
  },
  learnMore: "/explain/cors",
});

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

    return codeHits(file, re, /localStorage\.setItem\s*\(/).map((hit): Finding => ({
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

    return codeHits(file, re).map((hit): Finding => ({
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
