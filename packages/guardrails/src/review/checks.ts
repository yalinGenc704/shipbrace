import { dottedName, locationOf, parseFile, walk, type Node } from "../analysis/ast.ts";
import type { Inventory } from "../analysis/inventory.ts";
import { modelFields } from "../analysis/schemas.ts";
import { fileChecks } from "./project-files.ts";
import type { CodeLocation, RepoSnapshot, SourceFile } from "../types.ts";
import { isSource, isTestPath, redact } from "../util.ts";
import type { Grade, Risk } from "./modules.ts";

/**
 * Project-level checks.
 *
 * The pattern rules look at one file and the oracle looks at one route handler,
 * but several checklist items ask about the project as a whole: is a lockfile
 * committed, does the database publish a port, are versions pinned. Those need
 * the whole snapshot, so they live here.
 *
 * The important part of the design is `not-applicable`.
 *
 * "Is the database reachable from the internet?" has no honest answer in a
 * project with no compose file. Reporting a pass there would reintroduce the
 * exact false assurance the checklist is built to avoid -- the user would see a
 * green tick for a question nobody asked. So a check that cannot run says so,
 * and the item goes back to the user with an explanation.
 */

/** `notice`: something worth knowing that is not a problem (shown on the item). */
export type CheckOutcome =
  | { status: "pass"; notice?: string }
  | { status: "risks"; risks: Risk[]; notice?: string }
  | { status: "not-applicable"; reason: string; notice?: string };

export interface ProjectCheck {
  /** Stable name, shown as the detector on a passing item. */
  id: string;
  /** The action item this check answers. */
  itemId: string;
  run: (snapshot: RepoSnapshot, inventory: Inventory) => CheckOutcome;
}

// --- helpers -----------------------------------------------------------------

const sourceFiles = (snapshot: RepoSnapshot): SourceFile[] =>
  snapshot.files.filter((f) => isSource(f.path) && !isTestPath(f.path));

const fileNamed = (snapshot: RepoSnapshot, re: RegExp): SourceFile | undefined =>
  snapshot.files.find((f) => re.test(f.path));

const anyMatch = (files: SourceFile[], re: RegExp): boolean =>
  files.some((f) => re.test(f.content));

function lineOf(file: SourceFile, re: RegExp): CodeLocation {
  const lines = file.content.split(/\r?\n/);
  const index = lines.findIndex((line) => re.test(line));

  return {
    path: file.path,
    line: index === -1 ? 1 : index + 1,
    // Redacted here, before a finding exists: the line that proves a secret
    // is hardcoded is the line that contains it.
    ...(index === -1 ? {} : { excerpt: redact(lines[index]!.trim()).slice(0, 300) }),
  };
}

function risk(
  id: string,
  grade: Grade,
  what: string,
  impact: string,
  fix: string,
  location?: CodeLocation,
): Risk {
  return {
    id: `${id}@${location?.path ?? "-"}:${location?.line ?? 0}`,
    grade,
    what,
    impact,
    fix,
    ...(location ? { location } : {}),
    confirmedBy: "rule",
  };
}

// --- A02: the database must not be reachable from outside --------------------

/**
 * Reads the compose file by indentation rather than with a YAML parser, which
 * this package deliberately has no dependency on. Service blocks are two spaces
 * in and their keys four, so a `ports:` belonging to the database is
 * unambiguous without parsing the whole document.
 */
const exposedServices: ProjectCheck = {
  id: "compose:no-public-database",
  itemId: "config/exposed-services",

  run(snapshot) {
    const compose = fileNamed(snapshot, /(^|\/)docker-compose\.ya?ml$/);
    if (!compose) {
      return {
        status: "not-applicable",
        reason: "This project has no docker-compose file, so there is nothing to read.",
      };
    }

    const lines = compose.content.split(/\r?\n/);
    const risks: Risk[] = [];

    let service: string | null = null;
    let image = "";
    let publishes = -1;

    const settle = (): void => {
      if (service && /postgres|mysql|mariadb|mongo|redis/i.test(image) && publishes !== -1) {
        risks.push(
          risk(
            "check/exposed-database",
            "high",
            `The "${service}" service in ${compose.path} publishes a port to the host (line ${publishes + 1}).`,
            "Your database is reachable from outside the application. Databases are constantly scanned for on the public internet, and a weak or default password is enough to lose everything in it. Nothing outside your own application needs to reach it.",
            `Delete the "ports:" entry from the "${service}" service. Other services in the same compose file can still reach it by name; only the outside world loses access.`,
            { path: compose.path, line: publishes + 1, excerpt: lines[publishes]!.trim() },
          ),
        );
      }
    };

    for (const [index, line] of lines.entries()) {
      const serviceStart = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);

      if (serviceStart) {
        settle();
        service = serviceStart[1]!;
        image = "";
        publishes = -1;
        continue;
      }
      if (!service) continue;

      const imageLine = /^ {4}image:\s*(\S+)/.exec(line);
      if (imageLine) image = imageLine[1]!;
      if (/^ {4}ports:\s*$/.test(line)) publishes = index;
    }
    settle();

    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- A02: protective headers -------------------------------------------------

const securityHeaders: ProjectCheck = {
  id: "server:protective-headers",
  itemId: "config/security-headers",

  run(snapshot, inventory) {
    const files = sourceFiles(snapshot);
    if (inventory.doors.length === 0) {
      return {
        status: "not-applicable",
        reason: "No web routes were found, so there is no server response to add headers to.",
      };
    }
    if (anyMatch(files, /\b(secureHeaders|helmet|Content-Security-Policy)\b/)) {
      return { status: "pass" };
    }

    const entry = files.find((f) => /\b(new Hono|express\(\))/.test(f.content)) ?? files[0]!;

    return {
      status: "risks",
      risks: [
        risk(
          "check/missing-security-headers",
          "medium",
          `No protective response headers are configured in ${entry.path}.`,
          "Browsers offer several protections that only switch on when your server asks for them -- refusing to let your site be framed by someone else's, and refusing to run scripts from places you did not approve. Without them, a small problem elsewhere in the site becomes a much larger one.",
          "Add Hono's `secureHeaders()` middleware near the top of your server file. It is one line and needs no configuration to be useful.",
          lineOf(entry, /new Hono|express\(\)/),
        ),
      ],
    };
  },
};

// --- A10: error detail must not leak -----------------------------------------

const errorDetail: ProjectCheck = {
  id: "server:no-internal-errors-returned",
  itemId: "config/error-detail",

  run(snapshot, inventory) {
    if (inventory.doors.length === 0) {
      return { status: "not-applicable", reason: "No web routes were found." };
    }

    const leak = /\.(?:json|text|send)\s*\([^)]*\b(?:err|error|e)\s*\.\s*(?:stack|message)\b/;
    const risks: Risk[] = [];

    for (const file of sourceFiles(snapshot)) {
      if (!leak.test(file.content)) continue;

      risks.push(
        risk(
          "check/error-detail-leak",
          "medium",
          `${file.path} sends internal error text back to the visitor.`,
          "The detail inside an error describes how your system is built -- file paths, database structure, library versions. Handing that to whoever triggered the error tells an attacker exactly where to push next.",
          "Send a short, fixed message to the visitor and write the detail to your server logs instead, where only you can read it.",
          lineOf(file, leak),
        ),
      );
    }
    if (risks.length > 0) return { status: "risks", risks };

    /**
     * An Express app with no error handler of its own uses Express's, which
     * prints the full internal error to the visitor unless the server runs with
     * NODE_ENV=production. How it will be run is not in the code, so this goes
     * back to the user as a specific question -- not a pass, which is what it
     * used to be, on an app that does leak.
     */
    const files = sourceFiles(snapshot);
    const usesExpress = anyMatch(files, /\bexpress\s*\(\s*\)/);
    const ownHandler = anyMatch(files, /\.use\s*\(\s*(?:async\s*)?(?:function\s*\w*\s*)?\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/);
    if (usesExpress && !ownHandler) {
      return {
        status: "not-applicable",
        reason:
          "This app relies on Express's built-in error page, which shows visitors the full internal error -- file paths and code -- unless the server runs with NODE_ENV=production. Confirm it does, or add an error handler of your own that sends a short message.",
      };
    }
    return { status: "pass" };
  },
};

// --- A03: versions must be pinned --------------------------------------------

const pinnedVersions: ProjectCheck = {
  id: "manifest:exact-versions",
  itemId: "components/pinned",

  run(snapshot) {
    if (snapshot.manifests.size === 0) {
      return { status: "not-applicable", reason: "No package.json was found in this project." };
    }

    const risks: Risk[] = [];
    // Packages that are part of this same project, linked rather than downloaded.
    const local = new Set([...snapshot.manifests.values()].map((m) => m.name).filter(Boolean));

    for (const [path, manifest] of snapshot.manifests) {
      /**
       * Development tools count too: they run during every build, with the
       * same access to the code and its secrets. And `latest` is the loosest
       * version there is -- it was how one slipped through unflagged.
       */
      const deps = {
        ...(manifest.dependencies as Record<string, unknown> | undefined),
        ...(manifest.devDependencies as Record<string, unknown> | undefined),
      };

      const loose = Object.entries(deps)
        .filter(([name]) => !local.has(name))
        .filter(([, version]) =>
          typeof version === "string" && /^[\^~]|[*x]$|\s-\s|^(?:latest|next|beta|canary|\*)$/.test(version)
        )
        .map(([name, version]) => `${name}@${String(version)}`);

      if (loose.length === 0) continue;

      risks.push(
        risk(
          "check/unpinned-dependencies",
          "low",
          `${path} accepts a range of versions for ${loose.length} package${loose.length === 1 ? "" : "s"} (${loose.slice(0, 3).join(", ")}${loose.length > 3 ? ", …" : ""}).`,
          "A range means two installs of the same code can pull different versions of somebody else's package. The version you reviewed and the version that ends up running for your visitors are then not guaranteed to be the same.",
          "Replace the leading ^ or ~ with the exact version you want, and let your lockfile and a scheduled update process handle upgrades deliberately.",
          { path, line: 1 },
        ),
      );
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- A01: mass assignment needs to know what fields tables have --------------

/**
 * Mass assignment is judged against the fields each table has. With no
 * table definitions in the project there is nothing to judge it against, so
 * the item goes back to the user instead of showing a pass.
 */
const massAssignmentTables: ProjectCheck = {
  id: "schemas:model-fields",
  itemId: "access-control/mass-assignment",

  run(snapshot) {
    if (modelFields(snapshot).size === 0) {
      return {
        status: "not-applicable",
        reason:
          "No table definitions were found (Prisma, SQL, Mongoose, Sequelize or Drizzle), so whether saving a whole form lets visitors set fields like a role could not be judged.",
      };
    }
    return { status: "pass" };
  },
};

// --- A08: messages from other services must be checked as genuine -----------

/** Routes another service posts to. */
const WEBHOOK_PATH = /(?:^|\/)(?:webhooks?|hooks?)(?:\/|$)/i;

/**
 * Signs that a message's signature is checked: Stripe's `constructEvent`, an
 * HMAC compared in constant time, a webhook library's own check (Octokit,
 * Svix, Shopify, Paddle, Razorpay, Twilio), or a signature header being read.
 * A bare `.verify(` is not enough: `jwt.verify` in a login route proves
 * nothing about the webhook.
 */
const VERIFIES =
  /constructEvent|createHmac|timingSafeEqual|(?:webhooks?|wh|svix|Webhook)\.(?:verify|validate|unmarshal)\s*\(|verifyAndReceive|verify\w*Signature|validate\w*Signature|verifyWebhook|validateRequest|twilio\.webhook|subtle\.verify|x-hub-signature|stripe-signature|svix-signature|x-\w+-signature|x-signature/i;

/**
 * A shared secret sent in a header and compared (`authorization !== `Bearer
 * ${SECRET}``) is also a check, but text cannot show how good one is.
 */
const SHARED_SECRET =
  /header\(\s*["'`](?:authorization|x-[\w-]*(?:secret|token|key))["'`]|headers(?:\.|\[\s*["'`])(?:authorization|x-[\w-]*(?:secret|token|key))/i;

/**
 * A webhook route acts on what another service says happened -- a payment
 * went through, a push arrived. Without checking the message's signature,
 * anyone who finds the address can send a fake one.
 *
 * Reported only when nothing anywhere in the project checks a signature: a
 * check can live in middleware or another file, and guessing that it is
 * missing would be a warning on correct code. When some files check and the
 * webhook's own file does not, the item goes back to the user.
 */
const webhookSignatures: ProjectCheck = {
  id: "webhooks:signature-checked",
  itemId: "integrity/webhook-signatures",

  run(snapshot, inventory) {
    const hooks = inventory.doors.filter(
      (door) =>
        door.method === "POST" && WEBHOOK_PATH.test(door.path) &&
        inventory.sources.some((s) => s.doorId === door.id && s.kind === "request-body"),
    );
    if (hooks.length === 0) {
      return { status: "not-applicable", reason: "No webhook route that reads what it is sent was found." };
    }

    const files = sourceFiles(snapshot);
    const fileOf = (path: string): SourceFile | undefined => files.find((f) => f.path === path);
    const unchecked = hooks.filter((door) => !VERIFIES.test(fileOf(door.location.path)?.content ?? ""));
    if (unchecked.length === 0) return { status: "pass" };
    if (anyMatch(files, VERIFIES) || anyMatch(files, SHARED_SECRET)) {
      return {
        status: "not-applicable",
        reason:
          "Some code checks message signatures or a shared secret, but not plainly in the same file as every webhook route, so whether each one is checked could not be confirmed.",
      };
    }

    return {
      status: "risks",
      risks: unchecked.map((door) =>
        risk(
          "integrity/webhook-unsigned",
          "high",
          `${door.method} ${door.path} (${door.location.path} line ${door.location.line}) acts on what it is sent, and nothing in this project checks that a message really came from the service that is meant to send it.`,
          "Anyone who finds this address can send a made-up message -- a payment that never happened, an order marked paid -- and the app will act on it.",
          "Check the signature the service sends with every message before doing anything: for Stripe, `stripe.webhooks.constructEvent(rawBody, signature, secret)`; for GitHub, an HMAC of the raw body compared with `crypto.timingSafeEqual`. Refuse the message if it does not match.",
          door.location,
        )
      ),
    };
  },
};

// --- A03: a lockfile must exist ----------------------------------------------

const lockfilePresent: ProjectCheck = {
  id: "manifest:lockfile-committed",
  itemId: "integrity/lockfile",

  run(snapshot) {
    if (snapshot.manifests.size === 0) {
      return { status: "not-applicable", reason: "No package.json was found in this project." };
    }
    const lock = fileNamed(
      snapshot,
      /(^|\/)(bun\.lock(b)?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/,
    );
    if (lock) return { status: "pass" };

    return {
      status: "risks",
      risks: [
        risk(
          "check/missing-lockfile",
          "medium",
          "No lockfile is committed to this repository.",
          "A lockfile records the exact version of every package your app installs, including the packages your packages depend on. Without one, a build next week can quietly pull different code than the build you tested, and you would have no record of what changed.",
          "Run your package manager's install once and commit the lockfile it produces alongside your code.",
          { path: "package.json", line: 1 },
        ),
      ],
    };
  },
};

// --- A04: password storage ---------------------------------------------------

const passwordStorage: ProjectCheck = {
  id: "auth:slow-password-hash",
  itemId: "crypto/password-storage",

  run(snapshot) {
    const files = sourceFiles(snapshot);
    const handlesPasswords = anyMatch(files, /\bpassword\w*\b/i);

    if (!handlesPasswords) {
      return {
        status: "not-applicable",
        reason: "This application does not appear to handle passwords.",
      };
    }
    if (anyMatch(files, /\b(argon2|bcrypt|scrypt|Bun\.password)\b/i)) return { status: "pass" };

    const fast = /\bcreateHash\s*\(\s*['"`](md5|sha1|sha256|sha512)['"`]/i;
    const offender = files.find((f) => fast.test(f.content));

    if (offender) {
      return {
        status: "risks",
        risks: [
          risk(
            "check/fast-password-hash",
            "high",
            `${offender.path} scrambles passwords with a fast algorithm.`,
            "Fast algorithms are designed to run millions of times a second, which is exactly what someone guessing passwords wants. If your database is ever copied, common passwords are recovered from it in minutes.",
            "Use argon2id or bcrypt instead. They are deliberately slow, which costs you nothing on a single login and makes mass guessing impractical.",
            lineOf(offender, fast),
          ),
        ],
      };
    }

    return {
      status: "risks",
      risks: [
        risk(
          "check/unknown-password-hash",
          "high",
          "Passwords are handled here, but no recognised password-scrambling library is used.",
          "If passwords are stored as they were typed, anyone who obtains a copy of your database has every account immediately -- including on other sites, because people reuse passwords.",
          "Store passwords with argon2id or bcrypt. On Bun, `Bun.password.hash(value, { algorithm: \"argon2id\" })` is built in and needs no extra package.",
        ),
      ],
    };
  },
};

// --- A07: sessions must expire -----------------------------------------------

const sessionExpiry: ProjectCheck = {
  id: "auth:tokens-expire",
  itemId: "auth/session-expiry",

  run(snapshot) {
    const files = sourceFiles(snapshot);
    const signer = files.find((f) => /\b(SignJWT|jwt\.sign|sign\s*\()/.test(f.content));

    if (!signer) {
      return {
        status: "not-applicable",
        reason: "No login tokens are issued by this application.",
      };
    }
    if (/\b(setExpirationTime|expiresIn|exp\s*:)/.test(signer.content)) return { status: "pass" };

    return {
      status: "risks",
      risks: [
        risk(
          "check/tokens-never-expire",
          "high",
          `${signer.path} issues login tokens with no expiry time.`,
          "A token that never expires works forever. If one is ever copied -- from a shared computer, a browser extension, a leaked log -- that person stays logged in as the account indefinitely, and changing the password does not stop them.",
          "Give access tokens a short life (fifteen minutes is typical) and refresh them, so a copied one stops working quickly.",
          lineOf(signer, /SignJWT|jwt\.sign/),
        ),
      ],
    };
  },
};

// --- A06: rate limiting ------------------------------------------------------

const rateLimiting: ProjectCheck = {
  id: "server:rate-limiting-present",
  itemId: "design/rate-limiting",

  run(snapshot, inventory) {
    if (inventory.doors.length === 0) {
      return { status: "not-applicable", reason: "No web routes were found." };
    }
    if (anyMatch(sourceFiles(snapshot), /\b(rateLimit|rate_limit|rateLimiter|throttle|slowDown)\b/i)) {
      return { status: "pass" };
    }

    return {
      status: "risks",
      risks: [
        risk(
          "check/no-rate-limiting",
          "medium",
          `None of the ${inventory.doors.length} route${inventory.doors.length === 1 ? "" : "s"} in this application limits how often it can be called.`,
          "Without a limit, one person can call any address thousands of times a minute -- guessing passwords, running up costs on anything you pay per use, or simply making the site unavailable for everyone else.",
          "Add a rate-limiting middleware to your routes, with a stricter limit on signing in and on anything that costs money to run.",
        ),
      ],
    };
  },
};

// --- A09: logs must not contain secrets --------------------------------------

const SECRET_NAME = /password|passwd|token|secret|apikey|api_key|credential/i;
const LOG_CALL = /^console\.(?:log|info|warn|error|debug)$/;

/**
 * The first log call that passes a secret-named value, judged from the parsed
 * code: the names of the values handed to the call (variables, properties,
 * object keys), never the words inside its message. "AI_REVIEW=on needs
 * ANTHROPIC_API_KEY." names a setting; it does not print one. Reading the line
 * as text could not tell the two apart and warned about correct code.
 */
function secretLogged(file: SourceFile): CodeLocation | null {
  const parsed = parseFile(file);
  if (!parsed) return null;

  let found: CodeLocation | null = null;
  walk(parsed.program, (node) => {
    if (found || node.type !== "CallExpression" || !LOG_CALL.test(dottedName(node.callee) ?? "")) return;
    for (const argument of (node.arguments ?? []) as Node[]) {
      walk(argument, (inner) => {
        if (!found && inner.type === "Identifier" && SECRET_NAME.test(String(inner.name ?? ""))) {
          found = locationOf(parsed, node);
        }
      });
    }
  });
  return found;
}

const logsWithoutSecrets: ProjectCheck = {
  id: "logging:no-secrets-logged",
  itemId: "logging/no-secrets",

  run(snapshot) {
    const files = sourceFiles(snapshot);
    if (files.length === 0) {
      return { status: "not-applicable", reason: "No application code was found." };
    }

    const risks: Risk[] = [];

    for (const file of files) {
      const where = secretLogged(file);
      if (!where) continue;

      risks.push(
        risk(
          "check/secret-in-logs",
          "high",
          `${file.path} writes a password, token, or key into the logs.`,
          "Logs travel further than almost anything else you store -- shipped to other services, copied into support tickets, readable by more people than your database. A secret written into one has to be treated as public.",
          "Remove the value from the log line, or log only a description of it. If it has already run in production, treat that credential as exposed and replace it.",
          where,
        ),
      );
    }
    /**
     * Sequelize writes every query it runs to the console unless told not to --
     * including the values in them, so password hashes and personal details
     * end up in the logs.
     */
    for (const file of files) {
      for (const match of file.content.matchAll(/new\s+Sequelize\s*\(([\s\S]{0,600}?)\)\s*;?/g)) {
        if (/\blogging\s*:/.test(match[1] ?? "")) continue;
        risks.push(
          risk(
            "check/orm-query-logging",
            "medium",
            `${file.path} sets up Sequelize without turning off its query logging, so every database query -- with the values in it -- is written to the logs.`,
            "Queries carry the data they read and write: password hashes, emails, addresses. Logs are copied and shared far more widely than your database, so that data leaks out through them.",
            "Add `logging: false` to the Sequelize options (or send it to a logger that leaves values out).",
            lineOf(file, /new\s+Sequelize/),
          ),
        );
        break;
      }
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- A04: session secrets written into the code -------------------------------

const sessionSecret: ProjectCheck = {
  id: "server:session-secret-from-settings",
  itemId: "crypto/exposed-secrets",

  run(snapshot) {
    const files = sourceFiles(snapshot);
    const risks: Risk[] = [];
    const inline =
      /\b(?:session|expressSession|cookieSession)\s*\(\s*\{[^}]*?\bsecret\s*:\s*(['"`])[^'"`]+\1|\bcookieParser\s*\(\s*(['"`])[^'"`]+\2/;

    for (const file of files) {
      if (!inline.test(file.content)) continue;
      risks.push(
        risk(
          "check/session-secret-in-code",
          "high",
          `${file.path} writes the secret that signs login sessions directly into the code.`,
          "Anyone who has seen the code -- or guesses a common example value like the ones in tutorials -- can forge a login session for any user without a password.",
          "Read the secret from your settings (an environment variable such as SESSION_SECRET), set it to a long random value, and change it now, since the current one has been in the code.",
          lineOf(file, /\bsecret\s*:|cookieParser\s*\(/),
        ),
      );
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- A01: other sites cannot act for a signed-in visitor (CSRF) ----------------

const csrfProtection: ProjectCheck = {
  id: "server:csrf-protection",
  itemId: "access-control/csrf",

  run(snapshot, inventory) {
    const files = sourceFiles(snapshot);
    const changes = inventory.doors.filter((d) => ["POST", "PUT", "PATCH", "DELETE"].includes(d.method));
    if (changes.length === 0) {
      return { status: "not-applicable", reason: "No routes change anything, so there is nothing for another site to trigger." };
    }

    // The browser sends cookies along automatically; that is what makes this possible.
    const cookieLogin = anyMatch(files, /\b(?:express-session|cookie-session)\b|\b(?:session|cookieSession)\s*\(\s*\{|\bsetCookie\s*\(|res\.cookie\s*\(/);
    if (!cookieLogin) {
      return {
        status: "not-applicable",
        reason: "No cookie-based sign-in was found. If this app signs people in with cookies some other way, confirm other sites cannot submit forms to it on their behalf.",
      };
    }

    const protectedBy =
      anyMatch(files, /\b(?:csurf|lusca\.csrf|csrf\s*\(|doubleCsrf|csrfSync)\b|from\s+["']hono\/csrf["']/) ||
      anyMatch(files, /sameSite\s*:\s*["'`](?:strict|lax)["'`]/i);
    if (protectedBy) return { status: "pass" };

    return {
      status: "risks",
      risks: [
        risk(
          "check/no-csrf-protection",
          "medium",
          `This app signs people in with cookies and has ${changes.length} route${changes.length === 1 ? "" : "s"} that change things, but nothing stops another website from sending those requests on a visitor's behalf.`,
          "A page on any other site can quietly submit a form to yours while your visitor is signed in -- changing their email, placing an order, deleting data -- and your server cannot tell it apart from the visitor doing it.",
          "Set your login cookie with `sameSite: \"lax\"` (or \"strict\"), and add CSRF protection middleware -- `csrf()` from hono/csrf, or csrf-csrf for Express -- to routes that change data.",
          lineOf(files.find((f) => /session\s*\(|setCookie|res\.cookie/.test(f.content)) ?? files[0]!, /session\s*\(|setCookie|res\.cookie/),
        ),
      ],
    };
  },
};

// --- A01: admin pages check for an admin ---------------------------------------

/** The code a route runs: its own body, or the named handler it points to. */
function handlerText(snapshot: RepoSnapshot, door: Inventory["doors"][number]): string {
  const at = door.handlerAt ?? { path: door.location.path, range: door.bodyRange };
  const file = snapshot.files.find((f) => f.path === at.path);
  return file ? file.content.slice(at.range[0], at.range[1]) : "";
}

const ROLE_GUARD = /admin|role|permission|authori[sz]e|isStaff|isSuperuser/i;
/** A decision on the role inside the handler -- an `if` that tests it. */
const ROLE_DECISION = /\bif\s*\([^)]*\b(?:role|roles|isAdmin|is_admin|admin|permissions?|isStaff)\b/;

const adminOnly: ProjectCheck = {
  id: "routes:admin-check",
  itemId: "access-control/admin-only",

  run(snapshot, inventory) {
    // A route whose own address says it is for administrators.
    const adminRoutes = inventory.doors.filter((d) => /(?:^|\/)admin(?:\/|$|[-_])/i.test(d.path));
    if (adminRoutes.length === 0) {
      return {
        status: "not-applicable",
        reason: "No pages with \"admin\" in their address were found. If some pages are meant for administrators only, confirm each one checks the visitor's role on the server.",
      };
    }

    const risks: Risk[] = [];
    for (const door of adminRoutes) {
      if (door.guards.some((g) => ROLE_GUARD.test(g))) continue;
      const code = handlerText(snapshot, door);
      if (ROLE_DECISION.test(code)) continue;
      const sendsData = /\.json\s*\(/.test(code);
      risks.push(
        risk(
          "check/admin-without-role-check",
          sendsData ? "high" : "medium",
          `${door.method} ${door.path} (${door.location.path} line ${door.location.line}) is an admin page, but nothing on the server checks that the visitor is an administrator.`,
          sendsData
            ? "Any signed-in user -- or anyone, if signing in is not required -- can call it and get data meant only for administrators. Hiding the admin menu in the browser does not stop them; they only need the address."
            : "Anyone who reaches this page sees what administrators see. A check that only hides links in the browser can be skipped by typing the address.",
          "Add a check on the server that the signed-in user has the admin role -- a middleware such as `requireAdmin` on every admin route, or a test of the role at the top of the handler that refuses everyone else.",
          door.location,
        ),
      );
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- A04: password hashes are never sent to the browser -------------------------

const USER_MODEL = "(?:User|Users|Account|Member|Customer|Admin)\\w*";

const passwordHashesSent: ProjectCheck = {
  id: "routes:no-password-in-responses",
  itemId: "crypto/no-password-hashes-sent",

  run(snapshot, inventory) {
    const files = sourceFiles(snapshot);
    // Only a project whose user records actually carry a password.
    const hasPasswordField = anyMatch(files, /\bpassword\w*\s*:\s*(?:\{|DataTypes|Sequelize|String|text\(|varchar|type\b)/i);
    if (!hasPasswordField) {
      return { status: "not-applicable", reason: "No user records with a password field were found in this code." };
    }
    // Any sign that the password is removed before records leave counts --
    // in the model (a default scope, toJSON) or at the lookup.
    const removedSomewhere = anyMatch(
      files,
      /exclude\s*:\s*\[[^\]]*["'`]password|select\s*\(\s*["'`]-password|password\w*\s*:\s*(?:false|0)\b|delete\s+[\w.]+\.password|toJSON|toSafe\w*|defaultScope|omit\s*\(/i,
    );
    if (removedSomewhere) return { status: "pass" };

    const lookups = [
      new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*=\\s*await\\s+[\\w.]*\\b${USER_MODEL}\\.find\\w*\\(`, "g"),
      new RegExp(`\\b${USER_MODEL}\\.find\\w*\\([^)]*\\)\\s*\\.then\\(\\s*(?:async\\s*)?\\(?\\s*(\\w+)\\s*\\)?\\s*=>`, "g"),
    ];
    const risks: Risk[] = [];
    for (const door of inventory.doors) {
      const code = handlerText(snapshot, door);
      for (const re of lookups) {
        for (const match of code.matchAll(re)) {
          const name = match[1]!;
          const sent = new RegExp(
            `\\.(?:json|send)\\s*\\(\\s*(?:${name}\\s*\\)|\\{[^}]*(?:\\b${name}\\s*[,}]|:\\s*${name}\\s*[,}]))`,
          ).test(code);
          if (!sent) continue;
          risks.push(
            risk(
              "check/password-hash-in-response",
              "high",
              `${door.method} ${door.path} (${door.location.path} line ${door.location.line}) sends whole user records back, password field included.`,
              "Even scrambled, stored passwords can be cracked offline once someone has them -- quickly for common passwords -- and people reuse passwords across sites.",
              "Leave the password out when loading users for a response (for example `attributes: { exclude: [\"password\"] }` in Sequelize, `.select(\"-password\")` in Mongoose), or send only the fields the page needs.",
              door.location,
            ),
          );
        }
      }
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

export const projectChecks: ProjectCheck[] = [
  adminOnly,
  passwordHashesSent,
  sessionSecret,
  csrfProtection,
  exposedServices,
  securityHeaders,
  errorDetail,
  pinnedVersions,
  lockfilePresent,
  massAssignmentTables,
  webhookSignatures,
  ...fileChecks,
  passwordStorage,
  sessionExpiry,
  rateLimiting,
  logsWithoutSecrets,
];

/**
 * Run every check. A check that throws is recorded as unable to run rather than
 * failing the review -- the same reasoning as the rule engine, and it still
 * cannot produce a false pass, because only an explicit `pass` does that.
 */
export function runProjectChecks(
  snapshot: RepoSnapshot,
  inventory: Inventory,
  checks: ProjectCheck[] = projectChecks,
): Map<string, CheckOutcome & { detector: string }> {
  const outcomes = new Map<string, CheckOutcome & { detector: string }>();

  for (const check of checks) {
    try {
      outcomes.set(check.itemId, { ...check.run(snapshot, inventory), detector: check.id });
    } catch (error) {
      outcomes.set(check.itemId, {
        status: "not-applicable",
        reason: `This check could not run: ${
          error instanceof Error ? error.message : String(error)
        }`,
        detector: check.id,
      });
    }
  }
  return outcomes;
}
