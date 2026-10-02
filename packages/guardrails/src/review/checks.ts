import type { Inventory } from "../analysis/inventory.ts";
import type { CodeLocation, RepoSnapshot, SourceFile } from "../types.ts";
import { isSource, isTestPath } from "../util.ts";
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

export type CheckOutcome =
  | { status: "pass" }
  | { status: "risks"; risks: Risk[] }
  | { status: "not-applicable"; reason: string };

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
    ...(index === -1 ? {} : { excerpt: lines[index]!.trim().slice(0, 300) }),
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
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
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

    for (const [path, manifest] of snapshot.manifests) {
      const deps = manifest.dependencies;
      if (typeof deps !== "object" || deps === null) continue;

      const loose = Object.entries(deps as Record<string, unknown>)
        .filter(([, version]) => typeof version === "string" && /^[\^~]|[*x]$|\s-\s/.test(version))
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

const logsWithoutSecrets: ProjectCheck = {
  id: "logging:no-secrets-logged",
  itemId: "logging/no-secrets",

  run(snapshot) {
    const files = sourceFiles(snapshot);
    if (files.length === 0) {
      return { status: "not-applicable", reason: "No application code was found." };
    }

    const logged =
      /console\.(?:log|info|warn|error|debug)\s*\([^)]*\b\w*(?:password|passwd|token|secret|apiKey|api_key|credential)\w*\b/i;
    const risks: Risk[] = [];

    for (const file of files) {
      if (!logged.test(file.content)) continue;

      risks.push(
        risk(
          "check/secret-in-logs",
          "high",
          `${file.path} writes a password, token, or key into the logs.`,
          "Logs travel further than almost anything else you store -- shipped to other services, copied into support tickets, readable by more people than your database. A secret written into one has to be treated as public.",
          "Remove the value from the log line, or log only a description of it. If it has already run in production, treat that credential as exposed and replace it.",
          lineOf(file, logged),
        ),
      );
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

export const projectChecks: ProjectCheck[] = [
  exposedServices,
  securityHeaders,
  errorDetail,
  pinnedVersions,
  lockfilePresent,
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
