import { codeOnly, codeOnlyLines, dottedName, locationOf, parseFile, walk, type Node } from "../analysis/ast.ts";
import type { Inventory } from "../analysis/inventory.ts";
import { modelFields } from "../analysis/schemas.ts";
import { COMPOSE, dependencyNames, fileChecks, outOfSight } from "./project-files.ts";
import type { CodeLocation, RepoSnapshot, SourceFile } from "../types.ts";
import { isSource, isTestPath, redact } from "../util.ts";
import { pageName, upperFirst, type Grade, type Risk } from "./modules.ts";

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
  | {
    status: "not-applicable";
    reason: string;
    notice?: string;
    /**
     * The thing checked is not in this project (no Supabase, no passwords),
     * as opposed to being there but out of the check's sight. The item then
     * shows as "Doesn't apply here" -- still never a pass.
     */
    absent?: boolean;
    /**
     * The check found nothing of its own to judge, so what is left is a
     * general question rather than something about this code: no pages
     * named "admin" leaves "do admin pages check for admins?". The item goes
     * on the user's checklist instead of "Needs your check".
     */
    general?: boolean;
  };

export interface ProjectCheck {
  /** Stable name, shown as the detector on a passing item. */
  id: string;
  /** The action item this check answers. */
  itemId: string;
  run: (snapshot: RepoSnapshot, inventory: Inventory) => CheckOutcome;
}

// --- helpers -----------------------------------------------------------------

/**
 * Any sign that the app signs people in, however it does it. "Doesn't apply"
 * is only said of sign-in questions when nothing at all points to sign-in:
 * the specific detectors know a few libraries, and many others exist.
 */
const SIGN_IN_HINT = /\b(?:password|passwd|login|log_in|signin|sign_in|session|cookies?|auth\w*|jwt|token)\b/i;

/**
 * Any sign of a password, in any language the target users write in, or of
 * the tools that check one. Generous on purpose: a word in a comment keeps
 * the password questions, which is the safe way to be wrong.
 */
/** A cookie being set by writing the header itself: `c.header("Set-Cookie", ...)`. */
const SETS_COOKIE = /\.(?:header|set|append|setHeader|writeHead)\s*\(\s*["'`]set-cookie["'`]\s*,|["'`]set-cookie["'`]\s*:\s*[^\]\s]/i;

/** Where the app sets its sign-in cookie, for pointing at it. */
function cookieLine(files: SourceFile[]): CodeLocation {
  const plain = /session\s*\(|setCookie|res\.cookie/;
  const file = files.find((f) => plain.test(codeOnly(f))) ?? files.find((f) => SETS_COOKIE.test(codeOnly(f))) ?? files[0]!;
  return plain.test(codeOnly(file)) ? codeLineOf(file, plain) : codeLineOf(file, SETS_COOKIE);
}

const PASSWORD_WORD = /pass(?:word|wd|phrase)|\bpass\s*[,}:=)]|passwort|\bpwd\b|\bpw\b|s[iı]fre|contrase|senha|mot.?de.?passe|scrypt|pbkdf2|bcrypt|argon2|type\s*=\s*["']?password/i;
const PASSWORD_PACKAGES = /^(?:bcrypt|bcryptjs|argon2|@node-rs\/(?:argon2|bcrypt)|passport-local|scrypt-js)$/;

/**
 * Whether anything in the project could be handling passwords. Read
 * generously on purpose -- comments, messages and schema files all count --
 * because "doesn't apply" is only said when passwords are clearly absent.
 */
function mentionsPasswords(snapshot: RepoSnapshot): boolean {
  const readable = snapshot.files.filter((f) =>
    !isTestPath(f.path) && (isSource(f.path) || /\.(?:sql|prisma|graphql|gql|html|vue|svelte|ejs|hbs|pug)$/i.test(f.path))
  );
  return readable.some((f) => PASSWORD_WORD.test(f.content)) ||
    dependencyNames(snapshot).some((name) => PASSWORD_PACKAGES.test(name)) ||
    // What could not be read could hold one.
    outOfSight(snapshot) !== undefined;
}

/**
 * Any sign the app tells people or callers apart: sign-in, sessions, API
 * keys, a current user, tenants. Broader than SIGN_IN_HINT, because "no
 * accounts at all" is a stronger thing to say.
 */
const ACCOUNT_HINT = /\b(?:password|passwd|login|log_?in|sign_?in\w*|session|cookies?|auth\w*|jwt|token|api[-_]?keys?|bearer)\b|SignIn\w*|currentUser|req\.user|user_?id|userId|tenant|clerk|supabase\.auth|getServerSession|x-api-key/i;

const hasAccounts = (snapshot: RepoSnapshot): boolean =>
  outOfSight(snapshot) !== undefined ||
  snapshot.files.some((f) => !isTestPath(f.path) && ACCOUNT_HINT.test(f.content));

const sourceFiles = (snapshot: RepoSnapshot): SourceFile[] =>
  snapshot.files.filter((f) => isSource(f.path) && !isTestPath(f.path));

const fileNamed = (snapshot: RepoSnapshot, re: RegExp): SourceFile | undefined =>
  snapshot.files.find((f) => re.test(f.path));

const anyMatch = (files: SourceFile[], re: RegExp): boolean =>
  files.some((f) => re.test(f.content));

/**
 * Like `anyMatch`, but only real code counts: not comments, and not sentences
 * or sample code inside quotes (see `codeOnly`). For patterns that look for a
 * danger. Patterns that look for a protection keep using `anyMatch`, so a
 * protection mentioned anywhere still counts, as it always has.
 */
const anyCodeMatch = (files: SourceFile[], re: RegExp): boolean =>
  files.some((f) => re.test(codeOnly(f)));

/** `lineOf` for a danger: the first line where the pattern matches real code. */
const codeLineOf = (file: SourceFile, re: RegExp): CodeLocation => lineOf(file, re, codeOnlyLines(file));

function lineOf(file: SourceFile, re: RegExp, searched?: string[]): CodeLocation {
  const lines = file.content.split(/\r?\n/);
  const index = (searched ?? lines).findIndex((line) => re.test(line));

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
  /** The exact, code-level fix for an AI assistant; `fix` stays plain. */
  detail?: string,
): Risk {
  return {
    id: `${id}@${location?.path ?? "-"}:${location?.line ?? 0}`,
    grade,
    what,
    impact,
    fix,
    ...(detail ? { fixDetail: detail } : {}),
    ...(location ? { location } : {}),
    confirmedBy: "rule",
  };
}

// --- A02: the database must not be reachable from outside --------------------

/** The image's own name, without registry, owner or tag: `bitnami/postgresql:16` is `postgresql`. */
const DATABASE_NAME =
  /^(?:postgres(?:ql)?|pgvector|postgis|timescaledb(?:-ha)?|mysql(?:-server)?|mariadb|percona(?:-server(?:-mongodb)?)?|mongo(?:db)?(?:-(?:community|enterprise)-server)?|redis(?:-stack(?:-server)?)?|valkey|keydb|dragonfly|memcached|cockroach|clickhouse(?:-server)?|elasticsearch|opensearch|couchdb|cassandra|scylla|neo4j|influxdb|oracle-(?:free|xe)|arangodb|rethinkdb|surrealdb|questdb)$/i;

function isDatabaseImage(image: string): boolean {
  // `${DB_IMAGE:-postgres:16}`: the default is what runs unless set otherwise.
  const chosen = /^\$\{[^}:]*:-([^}]+)\}/.exec(image)?.[1] ?? image;
  const path = chosen.replace(/[:@][^/]*$/, "").toLowerCase();
  // SQL Server's image is `mcr.microsoft.com/mssql/server`.
  return DATABASE_NAME.test(path.split("/").at(-1) ?? "") || /(?:^|\/)mssql\/server$/.test(path);
}
/** A port opened only on the machine itself, which the internet cannot reach. */
const LOOPBACK_ONLY = /^["']?(?:127\.0\.0\.1|localhost|\[::1\]):/;
/** Files meant for a developer's own machine; they matter only if used on a server. */
const DEV_COMPOSE = /(?:^|\/)(?:docker-)?compose\.(?:dev|development|local|test|testing|ci)(?:\.[\w-]+)?\.ya?ml$/i;

interface ComposeService {
  file: SourceFile;
  name: string;
  image: string;
  /** Line index of the first port open to the outside, or -1. */
  openAt: number;
  /** The entry that opened it, for the suggested fix. */
  openEntry: string;
  /** Line index of `network_mode: host` -- every port the database listens on is open -- or -1. */
  hostNetwork: number;
  /** Settings pulled in from elsewhere (`<<:`, `extends:`, `ports: *x`), out of this reader's sight. */
  indirect: boolean;
  /** Built from the project's own Dockerfile rather than a named image. */
  built: boolean;
}

/**
 * Shared blocks (`x-base: &base`) that could change how a service is reached.
 * A block that sets only things like restart rules or memory limits cannot
 * open a port, so merging it in (`<<: *base`) hides nothing.
 */
function riskyAnchors(lines: string[]): Set<string> {
  const risky = new Set<string>();
  for (const [index, line] of lines.entries()) {
    const anchor = /^(\s*)[\w.-]+:\s*&([\w-]+)\s*$/.exec(line);
    if (!anchor) continue;
    const depth = anchor[1]!.length;
    for (const next of lines.slice(index + 1)) {
      if (next.trim() === "" || next.trim().startsWith("#")) continue;
      if (next.length - next.trimStart().length <= depth) break;
      if (/^\s*(?:ports|image|network_mode|<<|extends):/.test(next)) risky.add(anchor[2]!);
    }
  }
  return risky;
}

/**
 * Reads one compose file by indentation rather than with a YAML parser, which
 * this package deliberately has no dependency on. It assumes the usual shape:
 * services two spaces in under `services:`, their keys four. A file shaped
 * otherwise is reported as unreadable rather than guessed at.
 */
function composeServices(file: SourceFile): { services: ComposeService[]; unreadable: boolean } {
  const lines = file.content.split(/\r?\n/);
  const risky = riskyAnchors(lines);
  const services: ComposeService[] = [];
  let section = "";
  let current: ComposeService | null = null;
  let inPorts = false;
  let longEntry: { at: number; text: string; loopback: boolean } | null = null;
  let sawServiceContent = false;
  let shapeUnread = false;

  const open = (at: number, entry: string) => {
    if (current && current.openAt === -1) {
      current.openAt = at;
      current.openEntry = entry;
    }
  };
  const endLongEntry = () => {
    if (longEntry && !longEntry.loopback) open(longEntry.at, longEntry.text);
    longEntry = null;
  };

  for (const [index, line] of lines.entries()) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    const text = line.trim().replace(/\s+#.*$/, "");

    if (indent === 0) {
      endLongEntry();
      inPorts = false;
      current = null;
      section = /^([\w.-]+):/.exec(text)?.[1] ?? "";
      // Other compose files pulled in by name, which may not be read here.
      if (section === "include") shapeUnread = true;
      continue;
    }
    if (section !== "services") continue;
    sawServiceContent = true;

    if (indent === 2) {
      endLongEntry();
      inPorts = false;
      // `db:`, `"db":`, or `db: &db` (an anchor, to reuse the service).
      const name = /^["']?([A-Za-z0-9_.-]+)["']?:(?:\s*&[\w-]+)?$/.exec(text)?.[1];
      // Anything else here (`db: {image: ..., ports: [...]}`) is not read.
      if (!name) shapeUnread = true;
      current = name
        ? { file, name, image: "", openAt: -1, openEntry: "", hostNetwork: -1, indirect: false, built: false }
        : null;
      if (current) services.push(current);
      continue;
    }
    if (!current) continue;

    if (inPorts && indent >= 4 && text.startsWith("-")) {
      endLongEntry();
      const entry = text.replace(/^-\s*/, "");
      if (/^[\w-]+:\s/.test(entry)) longEntry = { at: index, text: entry, loopback: false };
      else if (!LOOPBACK_ONLY.test(entry)) open(index, entry);
      continue;
    }
    if (inPorts && indent > 4) {
      // A line inside a long-form entry: only `host_ip` changes where it opens.
      if (longEntry && /^host_ip:\s*["']?(?:127\.0\.0\.1|localhost|::1)["']?$/.test(text)) longEntry.loopback = true;
      continue;
    }
    if (indent === 4) {
      endLongEntry();
      inPorts = false;
      const image = /^image:\s*["']?([^\s"']+)/.exec(text);
      if (image) current.image = image[1]!;
      if (/^network_mode:\s*["']?host\b/.test(text)) current.hostNetwork = index;
      // Sharing another service's network: its ports are this one's.
      if (/^network_mode:\s*["']?(?:service|container):/.test(text)) current.indirect = true;
      if (/^build:/.test(text)) current.built = true;
      const merged = /^<<:\s*(.*)$/.exec(text);
      if (merged) {
        // `<<: *base` or `<<: [*a, *b]`: only blocks that touch ports or images matter.
        const names = [...merged[1]!.matchAll(/\*([\w-]+)/g)].map((m) => m[1]!);
        if (names.length === 0 || names.some((n) => risky.has(n) || !lines.some((l) => new RegExp(`&${n}\\s*$`).test(l)))) current.indirect = true;
      }
      if (/^extends:/.test(text) || /^ports:\s*\*/.test(text)) current.indirect = true;
      if (/^ports:$/.test(text)) inPorts = true;
      const inline = /^ports:\s*\[(.*)\]$/.exec(text);
      if (inline) {
        const entries = inline[1]!.split(",").map((e) => e.trim()).filter(Boolean);
        const public_ = entries.find((e) => !LOOPBACK_ONLY.test(e));
        if (public_) open(index, public_);
      } else if (/^ports:\s*\[/.test(text)) {
        current.indirect = true; // A one-line list spread over several lines.
      }
    }
  }
  endLongEntry();
  // `services:` with content but no service two spaces in: not the shape read here.
  const oldFormat = !/^services:/m.test(file.content) && /^ {2}image:/m.test(file.content);
  return { services, unreadable: oldFormat || shapeUnread || (sawServiceContent && services.length === 0) };
}

/**
 * A database service in a compose file that publishes a port is reachable
 * from outside the server (on Linux, Docker opens it past the firewall).
 *
 * Every compose file is read, because Docker merges them: an override can
 * open a port on a database whose image is named only in the main file of the
 * same folder.
 */
const exposedServices: ProjectCheck = {
  id: "compose:no-public-database",
  itemId: "config/exposed-services",

  run(snapshot) {
    const files = snapshot.files.filter((f) => COMPOSE.test(f.path) && !isTestPath(f.path));
    const unreadCompose = snapshot.incomplete || (snapshot.unread ?? []).some((p) => COMPOSE.test(p));
    if (files.length === 0) {
      return {
        status: "not-applicable",
        reason: unreadCompose
          ? "This project's Docker Compose setup files could not be read, so how the database is reached could not be seen. Check that none of them opens a database to the outside world, and that a hosted database only lets your app connect."
          : "This project has no Docker Compose setup file (compose.yaml or docker-compose.yml), so how the database is reached could not be seen. If your database is hosted somewhere, check in its settings that only your app can connect to it.",
      };
    }

    const read = files.map(composeServices);
    const services = read.flatMap((r) => r.services);
    const folder = (path: string) => path.replace(/[^/]*$/, "");
    // Docker merges files in one folder; a service of the same name elsewhere is another project.
    const imageOf = (s: ComposeService) =>
      s.image || services.find((o) => o.name === s.name && o.image && folder(o.file.path) === folder(s.file.path))?.image || "";

    const risks: Risk[] = [];
    let indirect: ComposeService | undefined;
    for (const s of services) {
      const image = imageOf(s);
      if (s.indirect && (isDatabaseImage(image) || (!image && !s.built))) indirect ??= s;
      if (!isDatabaseImage(image) || (s.openAt === -1 && s.hostNetwork === -1)) continue;
      const dev = DEV_COMPOSE.test(s.file.path);
      const lines = s.file.content.split(/\r?\n/);
      const at = s.openAt !== -1 ? s.openAt : s.hostNetwork;
      const entry = s.openEntry.replace(/^["']?(?:\d{1,3}(?:\.\d{1,3}){3}|\[[^\]]*\]):/, "").replace(/["']/g, "");
      // A bare container port (`"5432"`) needs the host port written out too.
      const bound = /^[^:]+$/.test(entry) ? `127.0.0.1:${entry}:${entry}` : `127.0.0.1:${entry}`;
      const longForm = /^[\w-]+:\s/.test(s.openEntry);
      risks.push(
        risk(
          "check/exposed-database",
          dev ? "medium" : "high",
          `Your setup file (${s.file.path}) opens the "${s.name}" database to the outside world.${dev ? " It looks like a file for development, so this matters if it is ever used on a server." : ""}`,
          "Your database can be reached from outside your app. Databases are constantly searched for on the internet, and a weak or default password is enough to lose everything in it. Nothing outside your own app needs to reach it.",
          "Remove the line that opens the database to the outside. Your app can still reach it; only the rest of the internet loses access.",
          { path: s.file.path, line: at + 1, excerpt: redact(lines[at]?.trim() ?? "") },
          s.openAt === -1
            ? `Remove \`network_mode: host\` from the "${s.name}" service in ${s.file.path}; other services in the same compose setup reach it by name.`
            : longForm
            ? `Delete the "ports:" entry from the "${s.name}" service in ${s.file.path}, or add \`host_ip: 127.0.0.1\` to it so it opens on this machine only. Other services in the same compose setup still reach it by name.`
            : `Delete the "ports:" entry from the "${s.name}" service in ${s.file.path}, or bind it to this machine only ("${bound}"). Other services in the same compose setup still reach it by name.`,
        ),
      );
    }
    if (risks.length > 0) return { status: "risks", risks };

    const unreadable = read.findIndex((r) => r.unreadable);
    if (unreadable !== -1 || indirect || unreadCompose) {
      const where = indirect ? indirect.file.path : unreadable !== -1 ? files[unreadable]!.path : "some of its compose files";
      return {
        status: "not-applicable",
        reason: `The database settings in ${where} are written in a way this check can't follow (settings pulled in from elsewhere, an unusual layout, or a file that could not be read). Confirm none of them opens a database to the outside world.`,
      };
    }
    return { status: "pass" };
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
        reason: "No pages were found in this code, so there was nothing to check. If your app does have pages, confirm it switches on the browser's built-in protections.",
      };
    }
    if (anyMatch(files, /\b(secureHeaders|helmet|Content-Security-Policy)\b/)) {
      return { status: "pass" };
    }

    const entry = files.find((f) => /\b(new Hono|express\(\))/.test(codeOnly(f))) ?? files[0]!;
    // The advice names the tool for the framework this app actually uses.
    const hono = /\bnew Hono\b/.test(codeOnly(entry));

    return {
      status: "risks",
      risks: [
        risk(
          "check/missing-security-headers",
          "medium",
          "Your site doesn't ask visitors' browsers to switch on their built-in protections (security headers).",
          "Browsers can refuse to show your site inside someone else's page, or to run code from places you did not approve, but only when your site asks. Without that, a small problem elsewhere becomes a much bigger one.",
          "Add the one standard line that switches these protections on. It needs no setup to be useful.",
          codeLineOf(entry, /new Hono|express\(\)/),
          hono
            ? `Add \`app.use(secureHeaders())\` (from "hono/secure-headers") near the top of ${entry.path}.`
            : `Install helmet and add \`app.use(helmet())\` right after the app is created in ${entry.path}.`,
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
      return { status: "not-applicable", reason: "No pages were found in this code, so there was nothing to check. If your app does have pages, confirm its error messages stay short." };
    }

    const leak = /\.(?:json|text|send)\s*\([^)]*\b(?:err|error|e)\s*\.\s*(?:stack|message)\b/;
    const risks: Risk[] = [];

    for (const file of sourceFiles(snapshot)) {
      if (!leak.test(codeOnly(file))) continue;

      risks.push(
        risk(
          "check/error-detail-leak",
          "medium",
          `${file.path} shows visitors the technical details of errors.`,
          "Those details describe how your site is built -- file names, database layout, package versions. Showing them to whoever caused the error tells an attacker exactly where to push next.",
          "Show visitors a short, fixed message, and write the details into your private records instead.",
          codeLineOf(file, leak),
          "Replace the `err.message`/`err.stack` in the response with a fixed message, and log the error server-side.",
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
    const usesExpress = anyCodeMatch(files, /\bexpress\s*\(\s*\)/);
    const ownHandler = anyMatch(files, /\.use\s*\(\s*(?:async\s*)?(?:function\s*\w*\s*)?\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/);
    if (usesExpress && !ownHandler) {
      return {
        status: "not-applicable",
        reason:
          "Your app uses Express's default error page, which shows visitors the full technical error unless the live site runs in production mode (NODE_ENV=production). Confirm it does, or add your own short error page.",
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
      return { status: "not-applicable", reason: "No package list (package.json) was found, so this could not be checked.", absent: true };
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
          `${loose.length} package${loose.length === 1 ? " is" : "s are"} allowed to update to newer versions on their own (${loose.slice(0, 3).map((d) => d.replace(/@[^@]*$/, "")).join(", ")}${loose.length > 3 ? ", …" : ""}).`,
          "Two installs of the same code can then pull different versions of somebody else's code. The version you tested and the version your visitors get are no longer guaranteed to match.",
          "Set each package to one exact version, and update packages on purpose when you choose to.",
          { path, line: 1 },
          `In ${path}, replace each version range with the exact installed version (remove the leading ^ or ~; replace "latest" or "*"): ${loose.slice(0, 8).join(", ")}${loose.length > 8 ? ", …" : ""}.`,
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
          "We couldn't find where your app describes what its saved records contain (Prisma, SQL, Mongoose, Sequelize or Drizzle), so this could not be checked. Confirm no form saves everything a visitor sends straight into a record.",
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
      return {
        status: "not-applicable",
        reason: "We didn't find an address where other services send this app updates (a webhook). If it has one, confirm each message's signature is checked before the app acts on it.",
      };
    }

    const files = sourceFiles(snapshot);
    const fileOf = (path: string): SourceFile | undefined => files.find((f) => f.path === path);
    const unchecked = hooks.filter((door) => !VERIFIES.test(fileOf(door.location.path)?.content ?? ""));
    if (unchecked.length === 0) return { status: "pass" };
    if (anyMatch(files, VERIFIES) || anyMatch(files, SHARED_SECRET)) {
      return {
        status: "not-applicable",
        reason:
          "Some of your code checks that messages from other services are genuine, but not next to every address that receives them, so we couldn't confirm each one is covered. Check each webhook verifies its messages.",
      };
    }

    return {
      status: "risks",
      risks: unchecked.map((door) =>
        risk(
          "integrity/webhook-unsigned",
          "high",
          `The address ${door.path}, where another service sends your app updates, believes any message it gets. Nothing checks that the message really came from that service.`,
          "Anyone who finds this address can send a made-up message -- a payment that never happened, an order marked paid -- and the app will act on it.",
          "Check the signature the service attaches to every message before doing anything, and ignore messages without a valid one.",
          door.location,
          `In ${door.method} ${door.path} (${door.location.path} line ${door.location.line}), verify the signature before acting: for Stripe, \`stripe.webhooks.constructEvent(rawBody, signature, secret)\`; for GitHub, an HMAC-SHA256 of the raw body compared with \`crypto.timingSafeEqual\`. Return 400 if it does not match.`,
        )
      ),
    };
  },
};

// --- XML: only libxmljs is followed ------------------------------------------

/** XML tools that can pull in outside files but whose settings this check cannot read. */
const OTHER_XML = /^(?:libxml2-wasm|libxslt|libxml-xsd|xmllint|xmllint-wasm|node-libxml|libxmljs-mt)$/;

/**
 * The XML check follows libxmljs only. A project using another tool that can
 * follow outside references gets the item handed back, so a real hole in a
 * library the check cannot read never shows as a pass.
 */
const xmlLibraries: ProjectCheck = {
  id: "taint:xml-entities",
  itemId: "injection/xml-entities",

  run(snapshot) {
    const others = [...snapshot.manifests.values()].flatMap((m) =>
      Object.keys({ ...(m.dependencies as object | undefined), ...(m.devDependencies as object | undefined) })
        .filter((name) => OTHER_XML.test(name))
    );
    if (others.length === 0) return { status: "pass" };
    return {
      status: "not-applicable",
      reason:
        `This app uses ${[...new Set(others)].join(", ")} to read XML, which this check cannot follow. Confirm it never reads a visitor's XML with the setting that pulls in other files (entity loading) switched on.`,
    };
  },
};

// --- AI features: only judged when a known AI library is used -----------------

const AI_LIBRARY = /^(?:@anthropic-ai\/sdk|openai|ai|@ai-sdk\/[\w-]+|@google\/generative-ai|@google\/genai|langchain|@langchain\/[\w-]+)$/;

/**
 * The prompt-to-action rule recognises a handful of AI libraries. A project
 * that uses none of them has nothing it can judge, so the item goes back to
 * the user rather than passing.
 */
const aiLibraries: ProjectCheck = {
  id: "rules:prompt-to-action",
  itemId: "injection/ai-instructions",

  run(snapshot) {
    const uses = [...snapshot.manifests.values()].some((m) =>
      Object.keys({ ...(m.dependencies as object | undefined), ...(m.devDependencies as object | undefined) })
        .some((name) => AI_LIBRARY.test(name))
    );
    if (uses) return { status: "pass" };
    // An app can call an AI service directly over the web. Only when nothing
    // in the code names one is the item said not to apply.
    // Any AI provider, by package name or by text in the code. Absence is only
    // claimed when none of them shows up anywhere.
    const AI_HINT = /openai|anthropic|claude|gemini|generativelanguage|mistral|groq|cohere|bedrock|ollama|replicate|huggingface|openrouter|together-ai|deepseek|langchain|llamaindex|ai-sdk|\bllm\b|chat\/completions|messages\.create|generateText|streamText/i;
    const mentionsAi =
      [...snapshot.manifests.values()].some((m) =>
        Object.keys({ ...(m.dependencies as object | undefined), ...(m.devDependencies as object | undefined) })
          .some((name) => AI_HINT.test(name))
      ) || anyMatch(sourceFiles(snapshot), AI_HINT);
    return mentionsAi
      ? {
        status: "not-applicable",
        reason:
          "This app seems to use an AI service in a way this check can't follow. Confirm a visitor's text can't make the AI's answer change data, run commands or send messages.",
      }
      : {
        status: "not-applicable",
        reason:
          "This app doesn't seem to use an AI service. If it does send visitors' text to an AI in some way, confirm the AI's answer is checked before it is used to do anything.",
        absent: true,
      };
  },
};

// --- A03: a lockfile must exist ----------------------------------------------

const lockfilePresent: ProjectCheck = {
  id: "manifest:lockfile-committed",
  itemId: "integrity/lockfile",

  run(snapshot) {
    if (snapshot.manifests.size === 0) {
      return { status: "not-applicable", reason: "No package list (package.json) was found, so there are no package versions to record.", absent: true };
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
          "Your code is saved without a lockfile (a record of every package version your app installs).",
          "Without one, an install next week can quietly pull different code than the one you tested. You would have no record of what changed.",
          "Ask your AI assistant to create the lockfile and save it with your code.",
          { path: "package.json", line: 1 },
          "Run `npm install` (or your package manager's install) and commit the resulting package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock.",
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
    const passwordWord = /\bpassword\w*\b/i;

    if (!mentionsPasswords(snapshot)) {
      return { status: "not-applicable", reason: NO_PASSWORDS, absent: true };
    }
    // Only in messages or comments: could be anything, so it goes back to the
    // user rather than becoming an alarm about how passwords are stored.
    if (!anyCodeMatch(files, passwordWord)) {
      return {
        status: "not-applicable",
        reason: "Passwords are only mentioned in this app's text, not in code we could follow. If it does store passwords, confirm they are scrambled with argon2id or bcrypt.",
      };
    }
    if (anyMatch(files, /\b(argon2|bcrypt|scrypt|Bun\.password)\b/i)) return { status: "pass" };
    // Bun's built-in hashing is only worth suggesting to apps that run on Bun.
    const bun = snapshot.files.some((f) => /(^|\/)bun\.lockb?$/.test(f.path)) || anyMatch(files, /\bBun\./);

    const fast = /\bcreateHash\s*\(\s*['"`](md5|sha1|sha256|sha512)['"`]/i;
    const offender = files.find((f) => fast.test(codeOnly(f)));

    if (offender) {
      return {
        status: "risks",
        risks: [
          risk(
            "check/fast-password-hash",
            "high",
            `${offender.path} scrambles passwords with a quick method that is easy to undo by guessing.`,
            "Quick methods can try millions of guesses a second, which is exactly what someone cracking passwords wants. If your database is ever copied, common passwords are recovered in minutes.",
            "Switch to a scrambling method built for passwords (argon2id or bcrypt). It is slow on purpose, which you won't notice but makes mass guessing impractical.",
            codeLineOf(offender, fast),
            "Replace the `createHash` password hashing with argon2id (the `argon2` package) or bcrypt, and rehash each user's password at their next sign-in.",
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
          "Your app handles passwords, but we couldn't find a password-scrambling tool being used.",
          "If passwords are saved as typed, anyone who gets a copy of your database has every account at once. People reuse passwords, so their accounts on other sites are at risk too.",
          "Save passwords scrambled with a method built for passwords (argon2id or bcrypt).",
          undefined,
          bun
            ? "Hash passwords with `Bun.password.hash(value, { algorithm: \"argon2id\" })` and check them with `Bun.password.verify`."
            : "Hash passwords with argon2id (the `argon2` package) or bcrypt before saving, and compare with its verify function at sign-in.",
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
    const signer = files.find((f) => /\b(SignJWT|jwt\.sign|sign\s*\()/.test(codeOnly(f)));

    if (!signer) {
      // Sessions kept in a cookie are sign-ins too; only their expiry is out of sight.
      const sessions = anyMatch(files, /\b(?:express-session|cookie-session)\b|\b(?:session|cookieSession)\s*\(\s*\{/);
      return sessions
        ? {
          status: "not-applicable",
          reason:
            "Your app keeps people signed in with a session this check can't read the expiry of. Confirm sessions end after a while, and that signing out ends them on your site too.",
        }
        : anyMatch(files, SIGN_IN_HINT)
        ? {
          status: "not-applicable",
          reason:
            "We couldn't see how this app keeps people signed in, so this couldn't be checked. Confirm sign-ins end after a while, and that signing out ends them on your site too.",
        }
        : {
          status: "not-applicable",
          reason: "This app doesn't seem to sign people in, so there are no sign-ins to expire.",
          absent: true,
        };
    }
    if (/\b(setExpirationTime|expiresIn|exp\s*:)/.test(signer.content)) return { status: "pass" };

    return {
      status: "risks",
      risks: [
        risk(
          "check/tokens-never-expire",
          "high",
          `${signer.path} hands out sign-in passes that never expire.`,
          "Anyone who copies one -- from a shared computer, a browser add-on, a leaked log -- stays signed in as that person forever. Changing the password does not stop them.",
          "Make sign-ins expire after a short time (15 minutes is common), renewing them while the person is active.",
          codeLineOf(signer, /SignJWT|jwt\.sign/),
          "Set an expiry when signing tokens (`expiresIn: \"15m\"` for jsonwebtoken, `.setExpirationTime(\"15m\")` for jose) and issue a refresh token to renew them.",
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
      return { status: "not-applicable", reason: "No pages were found in this code, so there was nothing to check. If your app does have pages, confirm sign-in and paid actions have a limit." };
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
          `None of your ${inventory.doors.length} page${inventory.doors.length === 1 ? "" : "s"} and actions limits how often one person can use it.`,
          "One person can then use any of them thousands of times a minute -- guessing passwords, running up costs on anything you pay for per use, or slowing the site down for everyone.",
          "Add a limit on how often one person can use each action, with a stricter one on signing in and on anything that costs you money.",
          undefined,
          "Add rate-limiting middleware (express-rate-limit for Express, hono-rate-limiter for Hono) to all routes, with a tighter limit on sign-in and costly routes.",
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
      return { status: "not-applicable", reason: "No app code was found, so there was nothing to check." };
    }

    const risks: Risk[] = [];

    for (const file of files) {
      const where = secretLogged(file);
      if (!where) continue;

      risks.push(
        risk(
          "check/secret-in-logs",
          "high",
          `${file.path} writes a password, sign-in pass, or key into your app's activity records (logs).`,
          "Activity records travel further than almost anything else you store: they are sent to other services and read by more people than your database. A secret written into one has to be treated as public.",
          "Stop writing the secret into the records. If this has already run on your live site, replace that password or key.",
          where,
          "Remove the secret-named value from this console call (log a description instead), and rotate the credential if this code has run in production.",
        ),
      );
    }
    /**
     * Sequelize writes every query it runs to the console unless told not to --
     * including the values in them, so password hashes and personal details
     * end up in the logs.
     */
    for (const file of files) {
      for (const match of codeOnly(file).matchAll(/new\s+Sequelize\s*\(([\s\S]{0,600}?)\)\s*;?/g)) {
        if (/\blogging\s*:/.test(match[1] ?? "")) continue;
        risks.push(
          risk(
            "check/orm-query-logging",
            "medium",
            `Your database tool (Sequelize, set up in ${file.path}) writes every database request, with the data in it, into your app's activity records.`,
            "Those requests carry scrambled passwords, emails and addresses. Activity records are shared far more widely than your database, so that data leaks out through them.",
            "Turn off that recording in the database tool's settings.",
            codeLineOf(file, /new\s+Sequelize/),
            `Add \`logging: false\` to the options passed to \`new Sequelize(...)\` in ${file.path}.`,
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
      if (!inline.test(codeOnly(file))) continue;
      risks.push(
        risk(
          "check/session-secret-in-code",
          "high",
          `${file.path} has the secret that protects everyone's sign-in written right into the code.`,
          "Anyone who has seen the code -- or guesses a common example value from tutorials -- can pretend to be any user without a password.",
          "Move the secret into your hosting service's secret settings, set it to a long random value, and change it now, because everyone who has seen the code knows the old one.",
          codeLineOf(file, /\bsecret\s*:|cookieParser\s*\(/),
          "Read the secret from an environment variable (`process.env.SESSION_SECRET`), refuse to start if it is unset, and set it to a new long random value.",
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
    if (inventory.doors.length === 0) {
      return {
        status: "not-applicable",
        reason: "No pages or actions were found in this code, so this could not be checked. If your app has actions that change things, confirm other websites can't trigger them for a signed-in visitor.",
      };
    }
    if (changes.length === 0) {
      return { status: "not-applicable", reason: "None of this app's actions change anything, so there is nothing another site could trigger.", absent: true };
    }

    // The browser sends cookies along automatically; that is what makes this possible.
    const cookieLogin = anyCodeMatch(files, /\b(?:express-session|cookie-session)\b|\b(?:session|cookieSession)\s*\(\s*\{|\bsetCookie\s*\(|res\.cookie\s*\(/) ||
      anyCodeMatch(files, SETS_COOKIE);
    if (!cookieLogin) {
      return {
        status: "not-applicable",
        reason: "We couldn't see how this app remembers signed-in visitors. If it uses cookies, confirm other websites can't send actions to it for them.",
        ...(anyMatch(files, SIGN_IN_HINT) ? {} : { absent: true }),
      };
    }

    const protectedBy =
      anyMatch(files, /\b(?:csurf|lusca\.csrf|csrf\s*\(|doubleCsrf|csrfSync)\b|from\s+["']hono\/csrf["']/) ||
      anyMatch(files, /sameSite\s*:\s*["'`](?:strict|lax)["'`]|SameSite=(?:Strict|Lax)\b/i);
    if (protectedBy) return { status: "pass" };

    return {
      status: "risks",
      risks: [
        risk(
          "check/no-csrf-protection",
          "medium",
          `Your site remembers who is signed in, and ${changes.length} of its actions change things (saving, editing, deleting). Nothing stops another website from secretly triggering them for a signed-in visitor.`,
          "A page on any other site can quietly send an action to yours while your visitor is signed in -- changing their email, placing an order, deleting data. Your site can't tell it apart from the visitor doing it.",
          "Turn on protection against this (often called CSRF protection), and make the sign-in cookie only travel with visits from your own site.",
          cookieLine(files),
          "Set the session cookie with `sameSite: \"lax\"` (or \"strict\"), and add CSRF middleware to every route that changes data: `csrf()` from hono/csrf on Hono, or csrf-csrf / csrf-sync on Express.",
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
      if (!hasAccounts(snapshot)) {
        return { status: "not-applicable", reason: NO_SIGN_IN, absent: true };
      }
      return {
        status: "not-applicable",
        reason: "No pages with \"admin\" in their address were found. If some pages are meant for administrators only, confirm each one checks that the visitor is one.",
        // A general reminder only when the app's pages were found at all;
        // otherwise the page finder may simply have missed them.
        ...(inventory.doors.length > 0 ? { general: true } : {}),
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
          `The admin page ${door.path} doesn't check that the visitor is an administrator. Any signed-in user can open it.`,
          sendsData
            ? "It hands out data meant only for administrators. Hiding the admin menu doesn't stop anyone: they only need the address."
            : "Anyone who reaches it sees what administrators see. Hiding the link doesn't help, because the address can be typed.",
          "Make the page check that the signed-in person is an administrator, and turn everyone else away.",
          door.location,
          `Add an admin-role check to ${door.method} ${door.path} (${door.location.path} line ${door.location.line}): a \`requireAdmin\` middleware on every admin route, or a role test at the top of the handler that returns 403 for everyone else.`,
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
    if (!mentionsPasswords(snapshot)) {
      return { status: "not-applicable", reason: NO_PASSWORDS, absent: true };
    }
    // Only a project whose user records actually carry a password.
    const hasPasswordField = anyCodeMatch(files, /\bpassword\w*\s*:\s*(?:\{|DataTypes|Sequelize|String|text\(|varchar|type\b)/i);
    if (!hasPasswordField) {
      // Records can hold passwords without a written description (MongoDB), so
      // not finding one is not proof there are none.
      return {
        status: "not-applicable",
        reason: "We couldn't find a description of user records with a password, so this couldn't be checked. If your app stores passwords, confirm pages that load users leave the password out.",
      };
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
              `${upperFirst(pageName(door))} sends complete user records to the browser, including their scrambled passwords.`,
              "Once someone has them, scrambled passwords can be cracked at leisure -- common ones quickly. People reuse passwords, so other sites are at risk too.",
              "Send only the details the page needs (like name and email), never the password.",
              door.location,
              `In ${door.method} ${door.path} (${door.location.path} line ${door.location.line}), leave the password out of the users sent back: \`attributes: { exclude: ["password"] }\` in Sequelize, \`.select("-password")\` in Mongoose, or map to the fields the page needs.`,
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
  aiLibraries,
  xmlLibraries,
  passwordStorage,
  sessionExpiry,
  rateLimiting,
  logsWithoutSecrets,
];

// --- Questions that do not apply ---------------------------------------------

const NO_PASSWORDS =
  "This app doesn't handle passwords itself: no password fields, password packages or mentions of passwords were found. Sign-in, if any, happens through another service.";
const NO_SIGN_IN = "This app has no sign-in at all, so there are no accounts to keep apart.";

/**
 * Some checklist questions have no automated check, but can be seen not to
 * apply: there is nothing to ask about password resets in an app with no
 * passwords. Each says so only when the code clearly shows it, never on a
 * guess; otherwise the question stays on the user's checklist.
 *
 * Deliberately not here: the private-network and build-steps questions. No
 * list of ways to send a request is ever complete, and a hosting service can
 * build and publish a site with no file in the repository saying so.
 */
export interface Applicability {
  id: string;
  itemId: string;
  /** The reason the question does not apply, or undefined when it might. */
  absentBecause: (snapshot: RepoSnapshot, inventory: Inventory) => string | undefined;
}

export const applicability: Applicability[] = [
  {
    id: "applies:passwords",
    itemId: "auth/brute-force",
    absentBecause: (snapshot) => (mentionsPasswords(snapshot) ? undefined : NO_PASSWORDS),
  },
  {
    id: "applies:passwords",
    itemId: "auth/account-recovery",
    absentBecause: (snapshot) => (mentionsPasswords(snapshot) ? undefined : NO_PASSWORDS),
  },
  {
    id: "applies:sign-in",
    itemId: "access-control/object-ownership",
    absentBecause: (snapshot) => (hasAccounts(snapshot) ? undefined : NO_SIGN_IN),
  },
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
  questions: Applicability[] = applicability,
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
  // A question that cannot be seen not to apply -- or whose test fails --
  // simply stays on the checklist.
  for (const question of questions) {
    if (outcomes.has(question.itemId)) continue;
    try {
      const reason = question.absentBecause(snapshot, inventory);
      if (reason) outcomes.set(question.itemId, { status: "not-applicable", reason, absent: true, detector: question.id });
    } catch {
      // Left on the checklist.
    }
  }
  return outcomes;
}
