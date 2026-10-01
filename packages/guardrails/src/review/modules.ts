import type { CodeLocation, Finding } from "../types.ts";
import type { Inventory } from "../analysis/inventory.ts";
import type { ConfirmedAttack, TaintPath } from "../analysis/oracle.ts";
import type { CheckOutcome } from "./checks.ts";

/**
 * The security review, as ten modules the user works through.
 *
 * The ten are the OWASP Top 10 itself, in OWASP's own order. That mapping is
 * not decoration: it means the ordering reflects measured real-world prevalence
 * rather than our taste, a user can look up any module in an independent
 * standard, and "did we cover everything" has an answer someone else maintains.
 *
 * Every risk carries the same three things, because a non-technical reader
 * needs all three to act and none of them alone is enough:
 *   what   - the specific problem, with the location
 *   impact - what happens if it is exploited, in plain words
 *   fix    - the concrete next step
 */

export type Grade = "high" | "medium" | "low";

export interface Risk {
  id: string;
  grade: Grade;
  /** The specific problem. Names the file and line where one exists. */
  what: string;
  /** Consequence in plain language, assuming no security knowledge. */
  impact: string;
  /** The concrete remedy. */
  fix: string;
  location?: CodeLocation;
  /** How the path was proven, shown in supervise mode. */
  evidence?: string;
  /**
   * `oracle` - a deterministic analyser reproduced the path from the code.
   * `rule`   - a pattern rule matched.
   * Nothing reaches a user with any other provenance; model proposals that the
   * oracle could not confirm are not risks and are not listed here.
   */
  confirmedBy: "oracle" | "rule";
}

export type ItemStatus = "pass" | "action-needed" | "needs-your-review";

export interface ActionItem {
  id: string;
  /** Imperative and plain, e.g. "Check that private pages require signing in". */
  title: string;
  /** Present when the user must answer something automation cannot determine. */
  question?: string;
  /**
   * Name of the detector that checks this item, or null when nothing automated
   * covers it yet.
   *
   * This exists so an unchecked item can never render as "pass". Claiming a
   * check happened when it did not is worse than reporting nothing: it tells
   * the user to stop looking at the one place they still needed to look.
   */
  detector: string | null;
  /**
   * Set when a detector exists but could not run here -- no compose file to
   * read, no passwords to check. The item returns to the user with this as the
   * explanation, because "could not check" and "checked, fine" must never look
   * the same.
   */
  notApplicable?: string;
  status: ItemStatus;
  risks: Risk[];
}

export interface ReviewModule {
  id: string;
  /** e.g. "A01:2021". */
  owasp: string;
  /** 1 is most important, matching OWASP's ranking. */
  rank: number;
  title: string;
  /** What this module protects against, for someone with no background. */
  summary: string;
  items: ActionItem[];
}

export interface SecurityReview {
  modules: ReviewModule[];
  summary: {
    high: number;
    medium: number;
    low: number;
    /** Items the user must judge personally. */
    awaitingReview: number;
    /** Modules with nothing outstanding. */
    clear: number;
  };
  /**
   * Model proposals the oracle could not verify. Shown separately, never as
   * risks, and never counted in the summary.
   */
  unverified: Array<{ door: string; rationale: string; whyNotShown: string }>;
}

/** Where each detection rule belongs in the ten. */
const RULE_TO_MODULE: Record<string, string> = {
  "secrets/hardcoded-credential": "cryptographic-failures",
  "secrets/committed-dotenv": "cryptographic-failures",
  "secrets/client-exposed-env": "cryptographic-failures",
  "auth/default-jwt-secret": "cryptographic-failures",
  "injection/sql-string-building": "injection",
  "injection/shell-string-building": "injection",
  "injection/unescaped-html": "injection",
  "auth/permissive-cors": "misconfiguration",
  "auth/token-in-localstorage": "authentication-failures",
};

const SINK_TO_MODULE: Record<string, string> = {
  sql: "injection",
  shell: "injection",
  html: "injection",
  "dynamic-code": "injection",
  filesystem: "access-control",
  redirect: "access-control",
  "outbound-request": "ssrf",
};

/** Severity of an unsanitised path, by what it reaches. */
const SINK_GRADE: Record<string, Grade> = {
  sql: "high",
  shell: "high",
  "dynamic-code": "high",
  filesystem: "high",
  "outbound-request": "medium",
  html: "medium",
  redirect: "low",
};

/**
 * Plain-language name, consequence, and remedy for each dangerous operation.
 *
 * The remedy is per-operation rather than one shared sentence: telling someone
 * to fix a shell command by using database parameters is worse than saying
 * nothing, because a reader who cannot evaluate the advice will try to follow
 * it and conclude the tool is wrong about everything else too.
 */
const SINK_COPY: Record<string, { operation: string; impact: string; fix: string }> = {
  sql: {
    operation: "a database query",
    impact:
      "Someone could read, change, or delete anything in your database -- including other people's accounts and personal information -- by typing carefully chosen text into your site.",
    fix:
      "Pass the value as a parameter instead of joining it into the query text -- the tagged `sql` template for postgres, or `?` placeholders with an argument array for mysql2. The database then treats it as data that can never be read as a command.",
  },
  shell: {
    operation: "a command run on your server",
    impact:
      "Someone could run their own commands on the machine hosting your site, which usually means full control of it.",
    fix:
      "Pass the command and its arguments as a separate array rather than building one string, so the shell never interprets characters inside the value. Better still, use a library that does the job directly instead of running a command at all.",
  },
  "dynamic-code": {
    operation: "code the application builds and runs on the fly",
    impact:
      "Someone could make your application run instructions they wrote, and do anything your application can do.",
    fix:
      "Stop building code out of values. Whatever this is choosing between can almost always be done with a lookup table or a plain function, neither of which can be talked into running something else.",
  },
  filesystem: {
    operation: "reading or writing a file on the server",
    impact:
      "Someone could open files they were never meant to see -- configuration, keys, other users' uploads -- or overwrite them.",
    fix:
      "Never build a file path straight from a supplied value. Resolve the full path first, then confirm it still sits inside the folder you intended before opening it, and reject it if it does not.",
  },
  "outbound-request": {
    operation: "a request your server makes to another address",
    impact:
      "Someone could make your server fetch addresses of their choosing, including private systems on your own network that the outside world cannot normally reach.",
    fix:
      "Check the address against a list of destinations you allow before fetching it, and refuse anything pointing at a private network address -- including the cloud metadata address, which hands out credentials.",
  },
  html: {
    operation: "content shown on the page",
    impact:
      "Someone could put their own scripts onto your pages, which run in your visitors' browsers and can steal whatever those visitors are logged into.",
    fix:
      "If the content is plain text, render it as text and let React escape it for you. If it genuinely has to be HTML, clean it with a library such as DOMPurify before it reaches the page.",
  },
  redirect: {
    operation: "sending the visitor to another address",
    impact:
      "Someone could craft a link that looks like it goes to your site but sends visitors to theirs -- useful for convincing people to hand over passwords.",
    fix:
      "Only redirect to paths within your own site, or check the destination against a list of addresses you allow. Reject anything else rather than following it.",
  },
};

const SOURCE_COPY: Record<string, string> = {
  "route-param": "a value taken from the web address",
  "query-string": "a value from the part of the address after the question mark",
  "request-body": "data sent by the visitor's browser",
  header: "a piece of metadata the visitor's browser controls",
  cookie: "a cookie the visitor's browser controls",
  "external-response": "the reply from another website",
  "uploaded-file": "a file the visitor uploaded",
  "repo-content": "content from a linked repository",
  environment: "a configuration value",
};

interface ModuleShape {
  id: string;
  owasp: string;
  rank: number;
  title: string;
  summary: string;
  items: Array<Omit<ActionItem, "status" | "risks">>;
}

/**
 * The fixed skeleton.
 *
 * `detector` names the automated check behind an item, and is null where none
 * exists yet. Items without one are handed to the user rather than quietly
 * passed -- the checklist is honest about its own coverage, which is the only
 * way a user can tell which parts they still own.
 */
const MODULES: ModuleShape[] = [
  {
    id: "access-control",
    owasp: "A01:2021",
    rank: 1,
    title: "Who is allowed to do what",
    summary:
      "The most common serious problem in web applications. It means a page or action that should be restricted can be reached by someone who should not reach it -- often just by editing the address bar.",
    items: [
      {
        id: "access-control/unguarded-routes",
        title: "Every private page and action requires signing in",
        detector: "route-guard-check",
      },
      {
        id: "access-control/object-ownership",
        title: "Signed-in users can only see their own records",
        question:
          "If one customer changed a number in the address bar, would they see another customer's data? Automated checks cannot tell whose record is whose -- only you know that.",
        detector: null,
      },
      {
        id: "access-control/file-paths",
        title: "File access cannot be steered outside its intended folder",
        detector: "taint:filesystem",
      },
    ],
  },
  {
    id: "cryptographic-failures",
    owasp: "A02:2021",
    rank: 2,
    title: "Protecting passwords, keys, and personal data",
    summary:
      "Covers secrets that should never be readable -- API keys, signing keys, passwords -- and sensitive data that should be protected in transit and at rest.",
    items: [
      {
        id: "crypto/exposed-secrets",
        title: "No keys or passwords are written into the code",
        detector: "rules:secrets",
      },
      {
        id: "crypto/password-storage",
        title: "Passwords are stored using a slow, modern hash",
        question:
          "Passwords must never be stored as typed, and never with a fast hash like MD5 or SHA-256. Confirm yours use argon2id or bcrypt -- deliberately slow algorithms that make guessing impractical.",
        detector: "auth:slow-password-hash",
      },
      {
        id: "crypto/data-classification",
        title: "You know what personal data this application stores",
        question:
          "List what you collect that would matter if it leaked -- names, emails, payment details, health information. Some of it carries legal obligations.",
        detector: null,
      },
    ],
  },
  {
    id: "injection",
    owasp: "A03:2021",
    rank: 3,
    title: "Visitor input being treated as instructions",
    summary:
      "Happens when something a visitor types is pasted into a command, a database query, or a page, and gets treated as an instruction rather than as text. This is the category the automated attack analysis targets most directly.",
    items: [
      {
        id: "injection/database",
        title: "Database queries keep visitor input as data, not commands",
        detector: "taint:sql",
      },
      {
        id: "injection/system-commands",
        title: "No system command is built from visitor input",
        detector: "taint:shell",
      },
      {
        id: "injection/page-content",
        title: "Visitor-supplied content cannot inject scripts into pages",
        detector: "taint:html",
      },
    ],
  },
  {
    id: "insecure-design",
    owasp: "A04:2021",
    rank: 4,
    title: "Gaps in how the feature was designed",
    summary:
      "Some problems are not mistakes in the code -- the code does exactly what it was asked to. These are gaps in what was asked for, so no automated tool can find them. They need your knowledge of how the product is supposed to work.",
    items: [
      {
        id: "design/abuse-cases",
        title: "You have thought about how someone would deliberately misuse this",
        question:
          "For each thing your app does, ask: what would someone gain by doing this a thousand times, out of order, or with values you did not expect?",
        detector: null,
      },
      {
        id: "design/rate-limiting",
        title: "Expensive or sensitive actions are rate limited",
        question:
          "Anything that costs you money, sends a message, or checks a password should refuse to run thousands of times a minute from one source. Confirm which of your actions have a limit.",
        detector: "server:rate-limiting-present",
      },
      {
        id: "design/business-rules",
        title: "Important rules are enforced on the server, not only in the browser",
        question:
          "Anything checked only in the browser can be bypassed entirely -- the browser is the visitor's, not yours. Prices, limits, and permissions must be re-checked on the server.",
        detector: null,
      },
    ],
  },
  {
    id: "misconfiguration",
    owasp: "A05:2021",
    rank: 5,
    title: "Settings that leave the door open",
    summary:
      "The code can be correct while the settings around it are not -- an overly permissive sharing rule, a debug mode left on, a default password never changed.",
    items: [
      { id: "config/cors", title: "Only your own sites can call your API", detector: "rules:cors" },
      {
        id: "config/security-headers",
        title: "Standard protective headers are switched on",
        question:
          "Confirm your server sets the standard protective headers. They cost nothing and close a whole class of browser-side attacks.",
        detector: "server:protective-headers",
      },
      {
        id: "config/exposed-services",
        title: "The database is not reachable from the internet",
        question:
          "Confirm your database does not publish a port to the outside world. It should be reachable only by your own application.",
        detector: "compose:no-public-database",
      },
      {
        id: "config/error-detail",
        title: "Error messages shown to visitors do not reveal internals",
        question:
          "A stack trace or raw database error tells an attacker how your system is built. Confirm visitors see a short message and the detail goes to your logs instead.",
        detector: "server:no-internal-errors-returned",
      },
    ],
  },
  {
    id: "vulnerable-components",
    owasp: "A06:2021",
    rank: 6,
    title: "Outdated or known-vulnerable building blocks",
    summary:
      "Your application is built on packages written by other people. When a security flaw is found in one of them, every application using it inherits the flaw until it is updated.",
    items: [
      {
        id: "components/known-vulnerabilities",
        title: "No dependency has a known published vulnerability",
        question:
          "This needs a live vulnerability database, which is not wired up yet. Until it is, run your package manager's audit command and review what it reports.",
        detector: null,
      },
      {
        id: "components/abandoned",
        title: "No dependency is unmaintained or pulled from an unofficial source",
        question:
          "A package that has not been updated in years will not be fixed when a flaw is found in it. Check the ones your app depends on most heavily.",
        detector: null,
      },
      {
        id: "components/pinned",
        title: "Versions are pinned so builds are reproducible",
        question:
          "Confirm your dependency versions are exact rather than ranges, so the code you reviewed is the code that ships.",
        detector: "manifest:exact-versions",
      },
    ],
  },
  {
    id: "authentication-failures",
    owasp: "A07:2021",
    rank: 7,
    title: "Proving who someone is",
    summary:
      "Covers logging in, staying logged in, and logging out. Weaknesses here let someone become another user, which makes every other permission check meaningless.",
    items: [
      {
        id: "auth/session-storage",
        title: "Login tokens cannot be read by scripts on the page",
        detector: "rules:token-storage",
      },
      {
        id: "auth/session-expiry",
        title: "Sessions expire and can be revoked",
        question:
          "Confirm a login does not last forever, and that signing out actually invalidates it on the server rather than only in the browser.",
        detector: "auth:tokens-expire",
      },
      {
        id: "auth/brute-force",
        title: "Repeated failed logins are slowed down or blocked",
        question:
          "Without a limit, someone can try millions of passwords against one account. Confirm repeated failures are slowed, locked, or challenged.",
        detector: null,
      },
      {
        id: "auth/account-recovery",
        title: "Password reset cannot be used to take over an account",
        question:
          "Reset links must expire, be single-use, and be sent only to the address already on the account. This is the most commonly abused way into an account.",
        detector: null,
      },
    ],
  },
  {
    id: "integrity-failures",
    owasp: "A08:2021",
    rank: 8,
    title: "Trusting code and data that could have been tampered with",
    summary:
      "Covers where your code comes from and whether anything could alter it on the way -- an unpinned dependency, an unsigned update, data accepted from elsewhere without checking.",
    items: [
      {
        id: "integrity/lockfile",
        title: "A lockfile records exactly which package versions are installed",
        question:
          "Confirm a lockfile is committed. Without one, two installs of the same code can pull different package versions.",
        detector: "manifest:lockfile-committed",
      },
      {
        id: "integrity/ci-permissions",
        title: "Automated build steps cannot be modified by contributors",
        question:
          "Your build pipeline usually holds deployment credentials. Confirm who is able to change what it runs.",
        detector: null,
      },
      {
        id: "integrity/untrusted-deserialization",
        title: "Data from outside is validated before being used",
        question:
          "Data arriving from another system is no more trustworthy than data typed by a visitor. Confirm it is checked against an expected shape before use.",
        detector: null,
      },
    ],
  },
  {
    id: "logging-monitoring",
    owasp: "A09:2021",
    rank: 9,
    title: "Noticing when something goes wrong",
    summary:
      "If an attack succeeds and nobody notices, it continues. The average intrusion goes undetected for months. This module is about being able to tell that something happened, and when.",
    items: [
      {
        id: "logging/auth-events",
        title: "Logins, failures, and permission denials are recorded",
        question:
          "Confirm you record who signed in, what failed, and what was refused. Without it there is no way to reconstruct an incident afterwards.",
        detector: null,
      },
      {
        id: "logging/no-secrets",
        title: "Logs never contain passwords, tokens, or keys",
        question:
          "Logs are copied, shipped to other services, and read by more people than your database. Confirm nothing sensitive is written into them.",
        detector: "logging:no-secrets-logged",
      },
      {
        id: "logging/alerting",
        title: "Someone would actually see an alert",
        question:
          "A log nobody reads is not monitoring. Decide who gets notified, and for what.",
        detector: null,
      },
    ],
  },
  {
    id: "ssrf",
    owasp: "A10:2021",
    rank: 10,
    title: "Your server being tricked into fetching things",
    summary:
      "If your application fetches a web address that a visitor supplies, they can point it at systems only your server can reach -- internal dashboards, cloud configuration services -- and read the reply.",
    items: [
      {
        id: "ssrf/url-allowlist",
        title: "Visitor-supplied addresses are checked against an allowlist",
        detector: "taint:outbound-request",
      },
      {
        id: "ssrf/internal-ranges",
        title: "Requests to private network addresses are blocked",
        question:
          "Confirm your server refuses to fetch addresses on your own private network, including the cloud metadata address that hands out credentials.",
        detector: null,
      },
    ],
  },
];

/** Deterministic id from a location, so the same risk keeps its id across scans. */
function riskId(prefix: string, location?: CodeLocation): string {
  return `${prefix}@${location?.path ?? "-"}:${location?.line ?? 0}`;
}

function gradeFromSeverity(severity: Finding["severity"]): Grade {
  if (severity === "critical" || severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

/**
 * Turn a proven taint path into a risk a non-technical reader can act on.
 *
 * The wording deliberately never uses "taint", "sink", or "sanitizer" -- the
 * reader is being asked to make a decision, not to learn vocabulary.
 */
function riskFromPath(path: TaintPath): Risk {
  const copy = SINK_COPY[path.sink.kind] ?? {
    operation: "a sensitive operation",
    impact: "Someone could make this behave in ways it was not meant to.",
    fix:
      "Check the value before it is used -- confirm it matches the shape you expect, and reject it when it does not.",
  };
  const entry = SOURCE_COPY[path.source.kind] ?? "something a visitor controls";
  const where = path.door ? `${path.door.method} ${path.door.path}` : path.sink.location.path;

  return {
    id: riskId(`taint/${path.sink.kind}`, path.sink.location),
    grade: SINK_GRADE[path.sink.kind] ?? "medium",
    what:
      `On ${where}, ${entry} is used directly in ${copy.operation} at ` +
      `${path.sink.location.path} line ${path.sink.location.line}, with nothing in between ` +
      `checking that the value is what you expect.`,
    impact: copy.impact,
    fix: copy.fix,
    location: path.sink.location,
    evidence: `${path.source.expression} → ${path.via.join(" → ")} → ${path.sink.expression}`,
    confirmedBy: "oracle",
  };
}

function riskFromFinding(finding: Finding): Risk {
  return {
    id: riskId(finding.ruleId, finding.location),
    grade: gradeFromSeverity(finding.severity),
    what: finding.location
      ? `${finding.title} (${finding.location.path} line ${finding.location.line}).`
      : `${finding.title}.`,
    impact: finding.why,
    fix: finding.fix?.description ?? "Open supervise mode to see the affected code.",
    ...(finding.location ? { location: finding.location } : {}),
    confirmedBy: "rule",
  };
}

export interface ReviewInput {
  findings: Finding[];
  paths: TaintPath[];
  inventory: Inventory;
  /** Only oracle-confirmed attacks. Unconfirmed ones go in `unverified`. */
  confirmed?: ConfirmedAttack[];
  unverified?: ConfirmedAttack[];
  /** Project-level check outcomes, keyed by the action item they answer. */
  checks?: Map<string, CheckOutcome & { detector: string }>;
}

/** Which action item a given risk belongs to, within its module. */
const ITEM_FOR_RULE: Record<string, string> = {
  "secrets/hardcoded-credential": "crypto/exposed-secrets",
  "secrets/committed-dotenv": "crypto/exposed-secrets",
  "secrets/client-exposed-env": "crypto/exposed-secrets",
  "auth/default-jwt-secret": "crypto/exposed-secrets",
  "injection/sql-string-building": "injection/database",
  "injection/shell-string-building": "injection/system-commands",
  "injection/unescaped-html": "injection/page-content",
  "auth/permissive-cors": "config/cors",
  "auth/token-in-localstorage": "auth/session-storage",
};

const ITEM_FOR_SINK: Record<string, string> = {
  sql: "injection/database",
  shell: "injection/system-commands",
  html: "injection/page-content",
  "dynamic-code": "injection/system-commands",
  filesystem: "access-control/file-paths",
  redirect: "access-control/file-paths",
  "outbound-request": "ssrf/url-allowlist",
};

export function buildReview(input: ReviewInput): SecurityReview {
  const risksByItem = new Map<string, Risk[]>();

  /**
   * Two detectors reaching the same line have found one problem, not two. The
   * oracle's version wins: it names the route and carries the traced path,
   * where the pattern rule only knows the line. Reporting both would make the
   * user think there are two things to fix.
   */
  const attach = (itemId: string, risk: Risk): void => {
    const existing = risksByItem.get(itemId) ?? [];
    const sameSpot = existing.findIndex(
      (r) =>
        r.location?.path === risk.location?.path && r.location?.line === risk.location?.line,
    );

    if (sameSpot !== -1) {
      const incumbent = existing[sameSpot]!;
      if (incumbent.confirmedBy === "rule" && risk.confirmedBy === "oracle") {
        existing[sameSpot] = risk;
        risksByItem.set(itemId, existing);
      }
      return;
    }
    existing.push(risk);
    risksByItem.set(itemId, existing);
  };

  for (const path of input.paths) {
    if (path.verdict !== "exploitable") continue;
    const itemId = ITEM_FOR_SINK[path.sink.kind];
    if (itemId) attach(itemId, riskFromPath(path));
  }

  for (const finding of input.findings) {
    const itemId = ITEM_FOR_RULE[finding.ruleId];
    if (itemId) attach(itemId, riskFromFinding(finding));
  }

  for (const [itemId, outcome] of input.checks ?? []) {
    if (outcome.status !== "risks") continue;
    for (const checkRisk of outcome.risks) attach(itemId, checkRisk);
  }

  // Routes with no authentication middleware are an access-control risk the
  // taint analysis cannot express -- there is no dangerous sink, the problem is
  // that the door has no lock at all.
  for (const door of input.inventory.doors) {
    if (door.guards.length > 0 || isPublicByDesign(door.path)) continue;

    attach("access-control/unguarded-routes", {
      id: riskId("access-control/unguarded", door.location),
      grade: door.method === "GET" ? "medium" : "high",
      what:
        `${door.method} ${door.path} (${door.location.path} line ${door.location.line}) has no ` +
        `sign-in check applied to it.`,
      impact:
        `Anyone on the internet can call this address without an account. If it returns or ` +
        `changes anything that belongs to a particular person, they do not need to be that ` +
        `person to use it.`,
      fix:
        `If this is meant to be public, mark it reviewed and move on. If not, apply your ` +
        `sign-in middleware to it -- ideally to the whole route prefix, so routes added later ` +
        `are protected automatically.`,
      location: door.location,
      confirmedBy: "oracle",
    });
  }

  const modules = MODULES.map((shape): ReviewModule => ({
    id: shape.id,
    owasp: shape.owasp,
    rank: shape.rank,
    title: shape.title,
    summary: shape.summary,
    items: shape.items.map((item): ActionItem => {
      const risks = (risksByItem.get(item.id) ?? []).sort(byGrade);
      const outcome = input.checks?.get(item.id);
      const blocked = outcome?.status === "not-applicable" ? outcome.reason : undefined;

      return {
        ...item,
        ...(blocked ? { notApplicable: blocked } : {}),
        risks,
        // "pass" needs a detector that actually ran and found nothing. A
        // detector that could not run here is not a pass, and neither is the
        // absence of one -- both hand the item back to the user.
        status: risks.length > 0
          ? "action-needed"
          : blocked || !item.detector
          ? "needs-your-review"
          : "pass",
      };
    }),
  }));

  return { modules, summary: summarise(modules), unverified: explainUnverified(input.unverified) };
}

/** Routes that are public on purpose; flagging them is noise, not safety. */
function isPublicByDesign(path: string): boolean {
  return /\/(health|healthz|ready|metrics|login|register|signup|refresh|logout|public)(\/|$)/.test(
    path,
  );
}

const GRADE_ORDER: Record<Grade, number> = { high: 0, medium: 1, low: 2 };
const byGrade = (a: Risk, b: Risk): number => GRADE_ORDER[a.grade] - GRADE_ORDER[b.grade];

function summarise(modules: ReviewModule[]): SecurityReview["summary"] {
  const summary = { high: 0, medium: 0, low: 0, awaitingReview: 0, clear: 0 };

  for (const module of modules) {
    let outstanding = 0;

    for (const item of module.items) {
      if (item.status === "needs-your-review") {
        summary.awaitingReview++;
        outstanding++;
      }
      for (const risk of item.risks) {
        summary[risk.grade]++;
        outstanding++;
      }
    }
    if (outstanding === 0) summary.clear++;
  }
  return summary;
}

/**
 * Unverified proposals are shown, but framed as what they are. Hiding them
 * entirely would discard a lead; presenting them as risks would hand the user a
 * claim nothing stands behind.
 */
function explainUnverified(unverified: ConfirmedAttack[] = []): SecurityReview["unverified"] {
  return unverified.map((entry) => ({
    door: entry.proposal.door,
    rationale: entry.proposal.rationale,
    whyNotShown: entry.verdict === "sanitized"
      ? "The automated check found this input is already validated before it is used."
      : entry.verdict === "unreachable"
      ? "The automated check could not find any path from that input to that operation."
      : "The automated check could not follow this path far enough to confirm or rule it out. Worth a human look.",
  }));
}

export { MODULES as moduleSkeleton };
