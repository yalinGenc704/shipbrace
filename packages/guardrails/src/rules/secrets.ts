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
            ? `This looks like ${vendor}, but it sits in a test file where invented values ` +
              `are normal. Worth a glance to confirm it is made up: a real key pasted into ` +
              `a test is exposed exactly as if it were in the application itself.`
            : `This file contains what looks like ${vendor}. Anyone who can read the ` +
              `repository can use it as you. Because git keeps history, deleting the line ` +
              `later does not undo the exposure -- the key has to be revoked and reissued.`,
          location: locate(file, hit),
          fix: {
            kind: "manual",
            description: inTest
              ? `Confirm the value is invented. If it is real, revoke it with the provider ` +
                `and replace it in the test with an obviously fake value.`
              : `Revoke this credential with the provider first, then issue a new one and ` +
                `store it as an environment variable instead of committing it.`,
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
      title: "Your environment file with real values is committed to git",
      why:
        `\`${file.path}\` holds ${populated.length} configured value(s) and is tracked by git. ` +
        `Environment files are where passwords and API keys live, and this one will be ` +
        `pushed to GitHub with the rest of your code.`,
      // The name only: every value in a committed .env is presumed secret,
      // whatever it is called.
      location: { path: file.path, line: populated[0]!.line, excerpt: `${populated[0]!.match[1]}=[redacted]` },
      fix: {
        kind: "manual",
        description:
          `Add \`${file.path}\` to .gitignore, remove it from tracking with ` +
          `\`git rm --cached ${file.path}\`, and rotate every credential it contained.`,
      },
      learnMore: "/explain/committed-dotenv",
    }];
  },
};

/**
 * Vite inlines every VITE_-prefixed variable into the browser bundle at build
 * time. Putting a server-side secret behind that prefix ships it to every
 * visitor -- and it reads as "correct" because the app works.
 */
const secretInClientBundle: Rule = {
  id: "secrets/client-exposed-env",
  category: "secrets",
  severity: "critical",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    const re = /import\.meta\.env\.(VITE_\w*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)\w*)/i;

    return scanLines(file, re).flatMap((hit): Finding[] => {
      const name = hit.match[1]!;
      // Publishable keys are deliberately client-side; flagging them is noise.
      if (/PUBLIC|PUBLISHABLE|ANON/i.test(name)) return [];

      return [{
        ruleId: secretInClientBundle.id,
        category: "secrets",
        severity: "critical",
        confidence: "likely",
        title: `\`${name}\` is bundled into code that runs in the browser`,
        why:
          `Anything named \`VITE_*\` is copied into the JavaScript sent to every visitor, ` +
          `so \`${name}\` is readable by anyone who opens developer tools. Values that ` +
          `grant access must be used on the server, where the browser cannot see them.`,
        location: locate(file, hit),
        fix: {
          kind: "manual",
          description:
            `Move the call that uses \`${name}\` into a server route, and have the browser ` +
            `call that route instead of the third-party service directly.`,
        },
        learnMore: "/explain/client-exposed-env",
      }];
    });
  },
};

export const secretsRules: Rule[] = [hardcodedCredential, committedDotenv, secretInClientBundle];
