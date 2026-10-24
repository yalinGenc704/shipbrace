import type { Finding, Rule } from "../types.ts";
import { isExampleEnv, isSource, isTestPath, locate, scanLines } from "../util.ts";

/**
 * Provider-issued credentials have recognisable shapes. Matching the shape
 * rather than the variable name is what makes this `certain` -- a string
 * starting `ghp_` is a GitHub token no matter what it was assigned to.
 */
const TOKEN_SHAPES: Array<{ re: RegExp; vendor: string }> = [
  { re: /\bsk-[A-Za-z0-9_-]{16,}\b/, vendor: "an LLM provider API key" },
  { re: /\bghp_[A-Za-z0-9]{30,}\b/, vendor: "a GitHub personal access token" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/, vendor: "a GitHub fine-grained token" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, vendor: "a Slack token" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, vendor: "an AWS access key" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, vendor: "a private key" },
];

/**
 * Values that are obviously made up: tutorial placeholders ("sk-your-key-here"),
 * runs of one character, or the alphabet or digits in order. A real key is
 * random, so the chance of one containing six repeated or six consecutive
 * characters, or one of these words, is negligible -- while flagging a
 * placeholder is a warning on correct code, the kind that teaches people to
 * stop reading the warnings.
 */
// Case-sensitive on purpose: placeholders are written in one case, while a
// random key mixes cases, so matching either case would mistake real keys for
// placeholders far more often.
const PLACEHOLDER_WORD = /example|EXAMPLE|sample|placeholder|your|YOUR|dummy|fake|changeme|redacted|xxxxx|XXXXX/;

function looksMadeUp(value: string): boolean {
  if (PLACEHOLDER_WORD.test(value)) return true;
  if (/(.)\1{5,}/.test(value)) return true;
  return hasRun(value.toLowerCase(), 6);
}

/** True when `value` holds `length` consecutive characters in order, like "abcdef" or "345678". */
function hasRun(value: string, length: number): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    const step = value.charCodeAt(i) - value.charCodeAt(i - 1);
    const sameClass = /[a-z]/.test(value[i]!) === /[a-z]/.test(value[i - 1]!) && /[a-z0-9]/.test(value[i]!);
    run = step === 1 && sameClass ? run + 1 : 1;
    if (run >= length) return true;
  }
  return false;
}

const hardcodedCredential: Rule = {
  id: "secrets/hardcoded-credential",
  category: "secrets",
  severity: "critical",
  appliesTo: (p) => (isSource(p) || /\.(json|ya?ml|toml|env.*)$/.test(p)) && !isExampleEnv(p),

  check(file, snapshot) {
    /**
     * A key in an untracked `.env` is correctly stored, not leaked.
     *
     * This rule exists to catch credentials written into code. An environment
     * file that git ignores is the destination this rule tells people to move
     * them to -- flagging it would punish the exact behaviour the product asks
     * for, and teach users that the warnings are noise. A `.env` that *is*
     * tracked is a real problem, and `committed-dotenv` reports it.
     */
    const isDotenv = /(^|\/)\.env(\.|$)/.test(file.path);
    if (isDotenv && !snapshot.tracked.has(file.path)) return [];

    const findings: Finding[] = [];

    /**
     * Test files are downgraded, not skipped.
     *
     * Credential-shaped strings in tests are usually invented fixtures, and
     * grading those "critical" buries the real findings -- on this project's own
     * code every single critical was a test fixture. But a genuine key does
     * sometimes get pasted into a test, so hiding them outright would miss a
     * real leak. Reported, lower, and labelled.
     */
    const inTest = isTestPath(file.path);

    for (const { re, vendor } of TOKEN_SHAPES) {
      for (const hit of scanLines(file, re, { includeComments: true })) {
        const value = hit.match[0];
        if (vendor !== "a private key" && looksMadeUp(value)) continue;
        findings.push({
          ruleId: hardcodedCredential.id,
          category: "secrets",
          severity: inTest ? "medium" : "critical",
          // A commented-out key is still a leaked key -- it is in git history either way.
          confidence: inTest ? "possible" : "certain",
          title: inTest
            ? `Something shaped like ${vendor} appears in a test file`
            : `${vendor} is written directly into your code`,
          why: inTest
            ? `Test files often contain made-up values, so this is worth a glance to confirm it is one. ` +
              `A real key in a test is exposed exactly as if it were in the app itself.`
            : `Anyone who can read your code can use it as you. Deleting the line later doesn't help, ` +
              `because GitHub keeps every old version -- the key has to be cancelled and replaced.`,
          location: locate(file, hit),
          fix: {
            kind: "manual",
            description: inTest
              ? `Confirm the value is made up. If it is real, cancel it on the provider's website ` +
                `and put an obviously fake value in the test.`
              : `First cancel this key on the provider's website (it is already exposed), then make a ` +
                `new one and keep it in your hosting service's secret settings, not in the code.`,
            detail: inTest
              ? "If the value is a real credential, revoke it with the provider and replace it with a clearly fake placeholder."
              : "Revoke the credential with the provider, issue a new one, read it from an environment variable, and remove the literal from the code.",
          },
          learnMore: "/explain/hardcoded-credential",
        });
      }
    }
    return findings;
  },
};

/**
 * A committed .env is the single most common way an LLM-built project leaks
 * production credentials: the model writes real values into .env to make the
 * app run, and nothing stops the next `git add .`.
 */
const committedDotenv: Rule = {
  id: "secrets/committed-dotenv",
  category: "secrets",
  severity: "critical",
  appliesTo: (p) => /(^|\/)\.env(\.|$)/.test(p) && !isExampleEnv(p),

  check(file, snapshot) {
    if (!snapshot.tracked.has(file.path)) return [];

    const populated = scanLines(file, /^\s*(?!#)([A-Z][A-Z0-9_]*)\s*=\s*\S+/);
    if (populated.length === 0) return [];

    return [{
      ruleId: committedDotenv.id,
      category: "secrets",
      severity: "critical",
      confidence: "certain",
      title: "Your file of passwords and keys (.env) is saved to GitHub with your code",
      why:
        `\`${file.path}\` holds ${populated.length} setting(s), and files like it are where passwords and keys live. ` +
        `Anyone who can see your code can read them.`,
      // The name only: every value in a committed .env is presumed secret,
      // whatever it is called.
      location: { path: file.path, line: populated[0]!.line, excerpt: `${populated[0]!.match[1]}=[redacted]` },
      fix: {
        kind: "manual",
        description: "Take the file out of GitHub, then change every password and key that was in it.",
        detail:
          `Add \`${file.path}\` to .gitignore, stop tracking it with \`git rm --cached ${file.path}\`, ` +
          `and rotate every credential it contained.`,
      },
      learnMore: "/explain/committed-dotenv",
    }];
  },
};

/**
 * Build tools copy variables with a "public" prefix into the JavaScript sent
 * to every visitor: Vite's `VITE_`, Next's `NEXT_PUBLIC_`, Create React App's
 * `REACT_APP_`, Expo's `EXPO_PUBLIC_`, SvelteKit's `PUBLIC_`. A secret behind
 * one of those prefixes ships to the world -- and reads as "correct" because
 * the app works. Supabase's service-role key in browser code is the same
 * mistake: it bypasses every row rule.
 *
 * Server-side files (under `api/` or `server/`, route handlers, `.server.`)
 * can read such names without exposing them, so they are left out.
 */
const PUBLIC_SECRET =
  /(?:import\.meta\.env|process\.env)\.((?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)(\w*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|SERVICE_ROLE)\w*))/i;
const SERVER_SIDE = /(?:^|\/)(?:api|server|functions|supabase\/functions)\/|(?:^|\/)route\.[cm]?[jt]sx?$|\.server\.[cm]?[jt]sx?$/;
/**
 * Keys that are public by design: the provider expects them in the browser
 * and limits what they can do (by domain, by read-only access, by rules).
 */
const PUBLIC_BY_DESIGN =
  /PUBLIC|PUBLISHABLE|ANON|SITE_KEY|FIREBASE_\w*KEY|MAPBOX|MAPS|POSTHOG|ALGOLIA_SEARCH|SEARCH_ONLY|SENTRY|CLIENT_ID|MEASUREMENT_ID|AMPLITUDE|SEGMENT|MIXPANEL|PLAUSIBLE|TURNSTILE|HCAPTCHA|RECAPTCHA|PUSHER_KEY|INTERCOM|CRISP/i;
/** Files that clearly run in the browser; the service-role check runs only there. */
const BROWSER_CODE = /^\s*["']use client["']/m;
const BROWSER_PATH = /(?:^|\/)(?:client|frontend|web)\/src\/|(?:^|\/)src\/(?:components|hooks)\//;
const SERVICE_ROLE = /createClient\s*\([^;]{0,400}?(?:SERVICE_ROLE|service_role|serviceRole)/;

const secretInClientBundle: Rule = {
  id: "secrets/client-exposed-env",
  category: "secrets",
  severity: "critical",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    if (SERVER_SIDE.test(file.path) && !/^\s*["']use client["']/m.test(file.content)) return [];

    const exposed = scanLines(file, PUBLIC_SECRET).flatMap((hit): Finding[] => {
      const name = hit.match[1]!;
      // Publishable keys are deliberately client-side; flagging them is noise.
      // Judged on the part after the prefix: NEXT_PUBLIC_ itself says PUBLIC.
      if (PUBLIC_BY_DESIGN.test(hit.match[2]!)) return [];

      return [{
        ruleId: secretInClientBundle.id,
        category: "secrets",
        severity: "critical",
        confidence: "likely",
        title: `\`${name}\` is sent to every visitor's browser, where anyone can read it`,
        why:
          `Settings whose names start this way are copied into the code every visitor downloads. ` +
          `Keys that give access to something must stay on your server, where browsers can't see them.`,
        location: locate(file, hit),
        fix: {
          kind: "manual",
          description:
            "Move the code that uses this key to your server, and have the page ask your server instead of the service directly. Then replace the key.",
          detail:
            `Rename \`${name}\` without the public prefix, move the call that uses it into a server route, ` +
            `have the browser call that route, and rotate the key since it has been public.`,
        },
        learnMore: "/explain/client-exposed-env",
      }];
    });

    // Only in code that is plainly browser code: the same call in a server
    // file, an admin helper or a seed script is how the key is meant to be used.
    const inBrowser = BROWSER_CODE.test(file.content) || (BROWSER_PATH.test(file.path) && !SERVER_SIDE.test(file.path));
    const role = inBrowser ? SERVICE_ROLE.exec(file.content) : null;
    const serviceRole = !role ? [] : [{ line: file.content.slice(0, role.index).split("\n").length }].map((hit): Finding => ({
      ruleId: secretInClientBundle.id,
      category: "secrets",
      severity: "critical",
      confidence: "likely",
      title: "Your Supabase master key is in code sent to visitors' browsers",
      why:
        "This key (the service-role key) ignores every access rule in your database. Anyone can copy " +
        "it from the browser and read or change everything.",
      location: { path: file.path, line: hit.line },
      fix: {
        kind: "manual",
        description:
          "Use the public key in the browser and keep the master key on your server only. Replace the master key now in Supabase.",
        detail:
          "Use the anon key in browser code with row level security on every table; move service-role usage " +
          "to server-only code and rotate the service-role key in the Supabase dashboard.",
      },
      learnMore: "/explain/client-exposed-env",
    }));
    return [...exposed, ...serviceRole];
  },
};

export const secretsRules: Rule[] = [hardcodedCredential, committedDotenv, secretInClientBundle];
