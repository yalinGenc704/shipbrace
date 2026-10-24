import type { CodeLocation, Finding } from "../types.ts";
import type { Door, Inventory, Sink, TaintSource } from "../analysis/inventory.ts";
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
  /** The concrete remedy, in plain words. */
  fix: string;
  /** The same remedy as an exact, code-level instruction for an AI assistant. */
  fixDetail?: string;
  /**
   * Set on risks that can be right as they are -- a page meant to be public,
   * records every signed-in user is meant to see. The dashboard offers "This
   * is intended" on these only.
   */
  mayBeIntended?: boolean;
  location?: CodeLocation;
  /** How the path was proven, shown in supervise mode. */
  evidence?: string;
  /**
   * `oracle`      - a deterministic analyser reproduced the path from the code.
   * `rule`        - a pattern rule matched.
   * `route-check` - the list of pages was checked for a sign-in step.
   * Nothing reaches a user with any other provenance; model proposals that the
   * oracle could not confirm are not risks and are not listed here.
   */
  confirmedBy: "oracle" | "rule" | "route-check";
}

/**
 * A line built in a risky way, where nothing proved a visitor's input reaches it.
 *
 * These come from the pattern check, which looks at how a line is written and
 * not at where its values come from. It catches problems the tracing cannot yet
 * follow, but it also fires on code that is safe -- a query pasting in a fixed
 * table name, or a value already turned into a number. Calling those risks
 * taught users to ignore risks. So they are kept, framed as what they are: a
 * place worth a look, never counted as a risk and never graded.
 */
export interface Unproven {
  id: string;
  /** What about the line looks risky, with its location. */
  what: string;
  /** Why it would matter if a visitor's input does reach it. */
  why: string;
  /** What to check, or change, to settle it. */
  check: string;
  /** The same step as an exact, code-level instruction for an AI assistant. */
  checkDetail?: string;
  location?: CodeLocation;
}

/**
 * `does-not-apply`: the check found the thing it looks at is not in this
 * project (no Supabase, no passwords). It is not a pass -- nothing was
 * checked -- and it is not something the user must decide either, so it is
 * kept out of both counts and shown with its reason.
 */
export type ItemStatus = "pass" | "action-needed" | "needs-your-review" | "does-not-apply";

export interface ActionItem {
  id: string;
  /** Imperative and plain, e.g. "Check that private pages require signing in". */
  title: string;
  /** Present when the user must answer something automation cannot determine. */
  question?: string;
  /**
   * Exactly what the automated check looks at, shown with a pass. A pass is
   * only ever as wide as the check behind it, and saying so stops "Checked"
   * reading as "safe".
   */
  covers?: string;
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
  /**
   * Who was asked and on what terms, for a check that sends anything outside
   * the platform. Shown with the item whatever its status, because telling
   * people what left their system, and crediting the data's source, does not
   * depend on whether anything was found.
   */
  notice?: string;
  status: ItemStatus;
  /** Proven problems only. */
  risks: Risk[];
  /** Places worth a look that nothing proved. Never counted as risks. */
  unproven: Unproven[];
}

export interface ReviewModule {
  id: string;
  /** e.g. "A01:2025". */
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
    /** Places worth a look, counted apart from risks. */
    unproven: number;
  };
  /**
   * Model proposals the oracle could not verify. Shown separately, never as
   * risks, and never counted in the summary.
   */
  unverified: Array<{ door: string; rationale: string; whyNotShown: string }>;
}

/** Severity of an unsanitised path, by what it reaches. */
const SINK_GRADE: Record<string, Grade> = {
  sql: "high",
  shell: "high",
  "dynamic-code": "high",
  filesystem: "high",
  "outbound-request": "medium",
  html: "medium",
  redirect: "low",
  nosql: "high",
  "xml-entities": "high",
  "mass-assignment": "high",
  "unsafe-decoding": "high",
};

/**
 * Plain-language name, consequence, and remedy for each dangerous operation.
 *
 * The remedy is per-operation rather than one shared sentence: telling someone
 * to fix a shell command by using database parameters is worse than saying
 * nothing, because a reader who cannot evaluate the advice will try to follow
 * it and conclude the tool is wrong about everything else too.
 */
const SINK_COPY: Record<string, { operation: string; impact: string; fix: string; detail: string }> = {
  sql: {
    operation: "a database query (a request your app sends to its database)",
    impact:
      "Someone could read, change, or delete anything in your database -- including other people's accounts and personal information -- by typing carefully chosen text into your site.",
    fix:
      "Send the visitor's text to the database separately from the question your app is asking it, so the database always treats it as plain text and never as part of the question.",
    detail:
      "Use query parameters instead of joining the value into the SQL text: the tagged `sql` template for postgres, or `?` placeholders with an argument array for mysql2.",
  },
  shell: {
    operation: "a command run on the computer that hosts your site",
    impact:
      "Someone could run their own commands on the machine hosting your site, which usually means full control of it.",
    fix:
      "Never build a computer command out of a visitor's text. Better still, use a ready-made package that does the job without running a command at all.",
    detail:
      "Pass the program and its arguments as a separate array (`execFile(cmd, [arg])` or `spawn` without `shell: true`) instead of building one string for `exec`, so the shell never interprets characters inside the value.",
  },
  "unsafe-decoding": {
    operation: "unpacking data with a tool that can turn it into working code",
    impact:
      "Someone could send data that, once unpacked, runs their own instructions on your server -- usually full control of it.",
    fix:
      "Unpack data with a tool that only ever produces plain data, never code. Stop using node-serialize or funcster for anything that comes from outside.",
    detail:
      "Decode with `JSON.parse`, or js-yaml 4's `load` (`safeLoad` in js-yaml 3), which only build plain values. Remove `unserialize` from node-serialize and funcster's `deepDeserialize` on outside data.",
  },
  "mass-assignment": {
    operation: "saving a whole record, with every field the visitor sent",
    impact:
      "The visitor can add fields your form never shows -- for example making themselves an administrator, or saving something under someone else's account -- because every field they send is saved.",
    fix:
      "Save only the fields the form is meant to change, picked out by name. Set things like admin status or who owns a record in your own code, never from what the visitor sent.",
    detail:
      "Copy only the allowed fields (`{ name: body.name, email: body.email }`), or validate the body against a schema that rejects unknown keys. Set fields like role or owner on the server.",
  },
  "xml-entities": {
    operation: "reading XML (a data file format) with a setting that lets it pull in other files",
    impact:
      "Someone could upload an XML file that asks your server to open one of its own private files (passwords, keys, settings) or a private internal address, and send the contents back.",
    fix:
      "Turn off the setting that lets XML files pull in other files. If you don't actually need XML, accept a simpler format such as JSON instead.",
    detail:
      "Remove `noent: true` (and `dtdload: true`) from the libxmljs parse options, so external entities are never resolved.",
  },
  "dynamic-code": {
    operation: "code your app builds and runs while it is running",
    impact:
      "Someone could make your application run instructions they wrote, and do anything your application can do.",
    fix:
      "Don't let your app turn text into code it runs. There's almost always a simpler way to do the same thing that can't be tricked into running something else.",
    detail:
      "Replace `eval`/`new Function`/`vm.run*` on this value with a lookup table or a plain function.",
  },
  filesystem: {
    operation: "choosing which file on your server to open or change",
    impact:
      "Someone could open files they were never meant to see -- settings, keys, other people's uploads -- or overwrite them.",
    fix:
      "Never let a visitor's text decide which file is opened. If it has to, check that the final file location is still inside the folder you meant, and refuse anything else.",
    detail:
      "Resolve the full path with `path.resolve(base, value)` and reject it unless it starts with the intended base folder plus a separator; better, map visitor input to a fixed list of allowed file names.",
  },
  "outbound-request": {
    operation: "choosing a web address your server then opens",
    impact:
      "Someone could make your server open addresses of their choosing, including private systems on your own network that the outside world cannot normally reach.",
    fix:
      "Only let your server open addresses from a list you approve, and refuse anything pointing inside your own private network -- including the special internal address hosting companies use to hand your site its passwords.",
    detail:
      "Check the URL's host against an allowlist before fetching, and refuse private and link-local ranges (10/8, 172.16/12, 192.168/16, 127/8, 169.254.169.254, ::1, fc00::/7).",
  },
  html: {
    operation: "what is shown on the page",
    impact:
      "Someone could put their own code onto your pages, which runs in your visitors' browsers and can steal whatever those visitors are signed in to.",
    fix:
      "Show visitors' text as plain text. If it really has to include formatting, clean it with a trusted cleaning package first.",
    detail:
      "Render the value escaped (`{value}` in React, `<%= %>` not `<%- %>` in EJS, `{{ }}` not `{{{ }}}` in Handlebars). If it must be HTML, pass it through DOMPurify first.",
  },
  nosql: {
    operation: "a database query (a request your app sends to its database)",
    impact:
      "Someone could send a specially shaped value instead of plain text -- for a password, \"anything except empty\" -- and get past a sign-in or read records that are not theirs, without knowing any password.",
    fix:
      "Make sure what the visitor sent is plain text before it reaches the database, and refuse anything else.",
    detail:
      "Convert the value with `String(req.body.name)` or validate its type with a schema so objects are refused. Never build a `$where` from visitor input.",
  },
  redirect: {
    operation: "choosing where the visitor is sent next",
    impact:
      "Someone could craft a link that looks like it goes to your site but sends visitors to theirs -- useful for convincing people to hand over passwords.",
    fix:
      "Only send visitors to pages on your own site, or to addresses on a list you approve. Refuse anything else.",
    detail:
      "Accept only relative paths starting with a single `/` (not `//`), or check the destination host against an allowlist before calling `res.redirect`.",
  },
};

/** Where a visitor's input comes from, written to start a sentence. */
const SOURCE_COPY: Record<string, string> = {
  "route-param": "Part of the web address",
  "query-string": "Text in the web address (after the question mark)",
  "request-body": "Something the visitor sends from their browser",
  header: "Information the visitor's browser sends with each request",
  cookie: "A cookie (a small note the visitor's browser stores and sends back)",
  "external-response": "The reply from another website",
  "uploaded-file": "A file the visitor uploaded",
  "repo-content": "Content from a linked GitHub repository",
  // Only settings an outsider fills in are treated as inputs at all.
  environment: "Text anyone can write in a GitHub pull request or issue",
  "stored-data": "Text another visitor saved earlier (for example a comment or a profile), read back from your database",
};

const lowerFirst = (text: string): string => text.charAt(0).toLowerCase() + text.slice(1);

/**
 * A page in words a reader without web background follows: "the page /x" for
 * something you open, "the action /x" for something that saves or changes.
 * The method (GET, POST) stays in the detailed view, with the file and line.
 */
export function pageName(door: { method: string; path: string }): string {
  return door.method === "GET" ? `the page ${door.path}` : `the action ${door.path}`;
}

export const upperFirst = (text: string): string => text.charAt(0).toUpperCase() + text.slice(1);

interface ModuleShape {
  id: string;
  owasp: string;
  rank: number;
  title: string;
  summary: string;
  items: Array<Omit<ActionItem, "status" | "risks" | "unproven" | "notice">>;
}

/**
 * The fixed skeleton.
 *
 * `detector` names the automated check behind an item, and is null where none
 * exists yet. Items without one are handed to the user rather than quietly
 * passed -- the checklist is honest about its own coverage, which is the only
 * way a user can tell which parts they still own.
 */
/**
 * The ten modules: the OWASP Top 10:2025, in OWASP's order.
 *
 * Item ids are stable across editions. When 2025 folded server-side request
 * forgery into access control and split supply-chain problems out of integrity,
 * the items moved module but kept their ids, so a user's "I've checked this"
 * ticks survive the move.
 */
const MODULES: ModuleShape[] = [
  {
    id: "access-control",
    owasp: "A01:2025",
    rank: 1,
    title: "Who is allowed to do what",
    summary:
      "The most common serious problem in web applications. It means a page or action that should be restricted can be reached by someone who should not reach it -- often just by editing the web address. It also covers a visitor tricking your site into opening web addresses they choose, which can reach private systems they could never reach themselves.",
    items: [
      {
        id: "access-control/unguarded-routes",
        covers: "every page and action asks visitors to sign in, or is a kind of page that is meant to be public (sign-in, health checks, webhooks)",
        title: "Every private page and action requires signing in",
        detector: "route-guard-check",
      },
      {
        id: "access-control/object-ownership",
        title: "Signed-in users can only see their own records",
        question:
          "If one customer changed a number in the web address, would they see another customer's data? Automated checks cannot tell whose record is whose -- only you know that.",
        detector: null,
      },
      {
        id: "access-control/file-paths",
        covers: "no visitor input was followed into choosing which file on your server is opened",
        title: "Visitors cannot trick your site into opening files it shouldn't",
        detector: "taint:filesystem",
      },
      {
        id: "access-control/redirects",
        covers: "no visitor input was followed into choosing where a visitor is sent next",
        title: "Links on your site cannot be used to send visitors to someone else's site",
        detector: "taint:redirect",
      },
      {
        id: "access-control/mass-assignment",
        covers:
          "no form saves everything a visitor sends straight into records that hold things like admin status, account balance or who owns what; records whose fields could not be found were not checked",
        title: "Visitors cannot give themselves extra powers by adding hidden form fields",
        detector: "taint:mass-assignment",
      },
      {
        id: "access-control/database-rules",
        covers: "every table set up in this project's Supabase files locks each row to the people allowed to see it; tables made by hand in the Supabase dashboard were not checked",
        title: "Visitors cannot read or change other people's data straight from the browser",
        detector: "supabase:row-level-security",
      },
      {
        id: "access-control/admin-only",
        covers: "every page with admin in its address checks that the visitor is an administrator",
        title: "Admin pages check that the visitor is an administrator",
        question:
          "Being signed in is not the same as being an administrator. Confirm every page and action meant for administrators checks that the visitor is one, and doesn't just hide the links.",
        detector: "routes:admin-check",
      },
      {
        id: "access-control/csrf",
        covers: "the way your site remembers signed-in visitors is protected against actions started from other websites",
        title: "Other websites cannot make signed-in visitors do things",
        question:
          "If your site remembers who is signed in with a cookie (a small note the browser keeps), a page on another site can secretly send actions to yours while they are signed in. Confirm your site turns on protection against this (often called CSRF protection).",
        detector: "server:csrf-protection",
      },
      {
        id: "ssrf/url-allowlist",
        covers: "no visitor input was followed into a web address your server opens",
        title: "Visitors cannot make your site open web addresses they choose",
        detector: "taint:outbound-request",
      },
      {
        id: "ssrf/internal-ranges",
        title: "Your site refuses to open addresses inside your own private network",
        question:
          "Confirm your site refuses to open addresses inside your own private network, including the special internal address hosting companies use to hand your site its passwords.",
        detector: null,
      },
    ],
  },
  {
    id: "misconfiguration",
    owasp: "A02:2025",
    rank: 2,
    title: "Settings that leave the door open",
    summary:
      "The code can be correct while the settings around it are not -- a setting that lets any website talk to yours, a test mode left on, a default password never changed.",
    items: [
      {
        id: "config/container-user",
        covers: "the setup file (Dockerfile) that packages your app runs it as an ordinary user, not with full administrator rights",
        title: "Your app doesn't run with full control of the computer it's on",
        detector: "docker:non-root-user",
      },
      {
        id: "config/debug-off",
        covers: "the setup files used to start the live app don't switch on test or debug mode; settings in a hosting service's dashboard were not checked",
        title: "Test mode is off where the app runs for real",
        detector: "deploy:debug-off",
      },
      {
        id: "config/cors",
        covers: "your app doesn't accept behind-the-scenes requests from every website",
        title: "Only your own website can talk to your app behind the scenes",
        detector: "rules:cors",
      },
      {
        id: "config/security-headers",
        covers: "your site asks visitors' browsers to switch on their built-in protections",
        title: "Your site turns on the browser's built-in safety features",
        question:
          "Confirm your site asks browsers to switch on their built-in protections (called security headers). It costs nothing and closes a whole group of browser attacks.",
        detector: "server:protective-headers",
      },
      {
        id: "config/exposed-services",
        covers: "your setup file (docker-compose) doesn't open the database to the outside world",
        title: "The database is not reachable from the internet",
        question:
          "Confirm your database can only be reached by your own app, not from the internet.",
        detector: "compose:no-public-database",
      },
    ],
  },
  {
    id: "supply-chain",
    owasp: "A03:2025",
    rank: 3,
    title: "Building blocks you did not write",
    summary:
      "Your application is built from packages (code written by other people), and built and published by automated tools. A flaw or a break-in anywhere along that chain ends up inside your application, even if your own code is perfect.",
    items: [
      {
        id: "components/known-vulnerabilities",
        covers: "every public package your app installs, against OSV.dev's list of known security flaws",
        title: "None of the packages your app uses has a publicly known security flaw",
        question:
          "If this could not be checked automatically, ask your AI assistant to run `npm audit` and fix what it reports.",
        detector: "osv:known-vulnerabilities",
      },
      {
        id: "components/suspicious-packages",
        covers: "no package is named one letter away from one of about 100 popular packages",
        title: "No package looks like a misspelled copy of a popular one",
        detector: "manifest:package-names",
      },
      {
        id: "components/abandoned",
        title: "None of your packages is abandoned or comes from an unofficial place",
        question:
          "A package that has not been updated in years will not be fixed when a flaw is found in it. Check the ones your app relies on most.",
        detector: null,
      },
      {
        id: "components/pinned",
        covers: "every package in package.json is set to one exact version",
        title: "Your app always installs the exact package versions you tested",
        question:
          "Confirm each package is set to one exact version rather than \"this version or newer\", so the code you tested is the code that goes live.",
        detector: "manifest:exact-versions",
      },
      {
        id: "integrity/lockfile",
        covers: "a lockfile is saved with your code",
        title: "Your app keeps a record of every package version it installs (a lockfile)",
        question:
          "Confirm a lockfile is saved with your code. Without one, two installs of the same code can pull different package versions.",
        detector: "manifest:lockfile-committed",
      },
      {
        id: "integrity/ci-permissions",
        title: "Only people you trust can change the automatic steps that build and publish your site",
        question:
          "These automatic steps (for example GitHub Actions) usually hold the passwords to your live site. Check who on GitHub can change them.",
        detector: null,
      },
    ],
  },
  {
    id: "cryptographic-failures",
    owasp: "A04:2025",
    rank: 4,
    title: "Protecting passwords, keys, and personal data",
    summary:
      "Covers secrets that should never be readable -- passwords, and the keys that give access to other services -- and private data, both while it is being sent and while it is stored.",
    items: [
      {
        id: "crypto/exposed-secrets",
        covers: "no keys, passwords, or sign-in secrets are written into your code",
        title: "No keys or passwords are written into the code",
        detector: "rules:secrets",
      },
      {
        id: "crypto/password-storage",
        covers: "passwords are scrambled with bcrypt or argon2, methods built for passwords",
        title: "Passwords are scrambled in a way that's hard to undo",
        question:
          "Passwords must never be saved as typed, or scrambled with a quick method like MD5 or SHA-256. Confirm yours use argon2id or bcrypt, which are slow on purpose so guessing takes too long to be worth it.",
        detector: "auth:slow-password-hash",
      },
      {
        id: "crypto/no-password-hashes-sent",
        covers: "no page sends complete user records, scrambled passwords included, to the browser",
        title: "Stored passwords are never sent back to the browser",
        question:
          "When a page loads user records, confirm the stored password is left out of what is sent -- even scrambled, it can be cracked.",
        detector: "routes:no-password-in-responses",
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
    owasp: "A05:2025",
    rank: 5,
    title: "Visitor input being treated as instructions",
    summary:
      "Happens when something a visitor types is pasted into a command, a database request, or a page, and gets treated as an instruction rather than as text. This is what ShipBrace checks most thoroughly.",
    items: [
      {
        id: "injection/database",
        covers: "no visitor input was followed into a database request",
        title: "Visitors can't change what your database does by typing special text",
        detector: "taint:sql",
      },
      {
        id: "injection/system-commands",
        covers: "no visitor input was followed into a computer command or into code your app runs",
        title: "Visitor input is never run as a command or as code",
        detector: "taint:shell",
      },
      {
        id: "injection/page-content",
        covers: "no visitor input was followed into a page without being made safe first",
        title: "Visitors can't sneak their own code into your pages",
        detector: "taint:html",
      },
      {
        id: "injection/ai-instructions",
        covers:
          "in each page's code, a visitor's text never goes to a well-known AI service (Anthropic, OpenAI, Gemini, Vercel AI SDK, LangChain) whose answer is then used to change data, run commands, open addresses or send messages, or that is given tools; AI code in other places was not followed",
        title: "A visitor's text cannot steer what an AI feature does",
        detector: "rules:prompt-to-action",
      },
      {
        id: "injection/xml-entities",
        covers:
          "no uploaded XML was followed into libxmljs with the setting that pulls in other files switched on; other XML tools, and settings written elsewhere, were not checked",
        title: "Uploaded XML files can't make your site reveal its own private files",
        detector: "taint:xml-entities",
      },
    ],
  },
  {
    id: "insecure-design",
    owasp: "A06:2025",
    rank: 6,
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
        covers: "something limits how often one person can use your pages and actions",
        title: "Nobody can repeat an action thousands of times a minute",
        question:
          "Anything that costs you money, sends a message, or checks a password should refuse to run thousands of times a minute for one person. Confirm which of your actions have a limit.",
        detector: "server:rate-limiting-present",
      },
      {
        id: "design/unbounded-lists",
        covers:
          "no page sends back every row of a table at once, with no filter or limit (Express or Hono pages using Mongoose, Sequelize, Prisma or plain SQL; Drizzle and Next.js pages were not checked)",
        title: "Lists sent to visitors have a maximum size",
        detector: "rules:unbounded-list",
      },
      {
        id: "design/upload-limits",
        covers: "every upload feature built with multer sets a size limit; other upload tools were not checked",
        title: "Uploads have a size limit",
        detector: "uploads:size-limit",
      },
      {
        id: "design/business-rules",
        title: "Important rules are checked by your site, not just in the visitor's browser",
        question:
          "Anything checked only in the browser can be skipped entirely -- the browser belongs to the visitor, not to you. Prices, limits, and permissions must be checked again by your site.",
        detector: null,
      },
    ],
  },
  {
    id: "authentication-failures",
    owasp: "A07:2025",
    rank: 7,
    title: "Proving who someone is",
    summary:
      "Covers signing in, staying signed in, and signing out. Weaknesses here let someone become another user, which makes every other permission check meaningless.",
    items: [
      {
        id: "auth/session-storage",
        covers: "the visitor's sign-in pass is never kept where code running on the page can read it",
        title: "Your sign-in pass can't be stolen by code running on the page",
        detector: "rules:token-storage",
      },
      {
        id: "auth/session-expiry",
        covers: "sign-in passes are given an expiry time",
        title: "Sign-ins expire, and signing out really signs you out",
        question:
          "Confirm a sign-in does not last forever, and that signing out really ends it on your site rather than only in the browser.",
        detector: "auth:tokens-expire",
      },
      {
        id: "auth/brute-force",
        title: "Repeated failed sign-ins are slowed down or blocked",
        question:
          "Without a limit, someone can try millions of passwords against one account. Confirm repeated failures are slowed down, locked, or challenged.",
        detector: null,
      },
      {
        id: "auth/account-recovery",
        title: "Password reset cannot be used to take over an account",
        question:
          "Reset links must expire, work only once, and be sent only to the email already on the account. This is the most commonly abused way into an account.",
        detector: null,
      },
    ],
  },
  {
    id: "integrity-failures",
    owasp: "A08:2025",
    rank: 8,
    title: "Trusting data that could have been tampered with",
    summary:
      "Covers data and code your application accepts as genuine without checking -- a script loaded from someone else's site, a cookie the visitor could edit, data arriving from another system.",
    items: [
      {
        id: "integrity/untrusted-deserialization",
        title: "Data from other services is checked before your app uses it",
        question:
          "Data arriving from another system is no more trustworthy than something a visitor typed. Confirm it is checked to be what you expect before your app uses it.",
        detector: null,
      },
      {
        id: "integrity/unsafe-decoding",
        covers:
          "no visitor input was followed into node-serialize, funcster, or js-yaml's unsafe loading, tools that can turn data into code; other tools were not checked",
        title: "Data from outside can't turn into code your app runs",
        detector: "taint:unsafe-decoding",
      },
      {
        id: "integrity/webhook-signatures",
        covers: "every address where another service sends you updates (a webhook) sits in code that checks each message's signature",
        title: "Messages from other services are checked to be genuine",
        detector: "webhooks:signature-checked",
      },
      {
        id: "integrity/third-party-scripts",
        title: "Code loaded from other websites can't be swapped without you noticing",
        question:
          "If your pages load code straight from another website, whoever runs that site can change what runs on yours. Confirm each one is locked to an exact version with a safety check (called subresource integrity), or hosted on your own site.",
        detector: null,
      },
      {
        id: "integrity/client-data",
        title: "Anything that comes back from the visitor's browser is double-checked",
        question:
          "Cookies, hidden form fields, and saved settings pass through the visitor's browser, where they can be edited. Confirm anything you rely on -- a role, a price, an account number -- is either signed so changes are noticed, or looked up again by your site.",
        detector: null,
      },
    ],
  },
  {
    id: "logging-monitoring",
    owasp: "A09:2025",
    rank: 9,
    title: "Noticing when something goes wrong",
    summary:
      "If an attack succeeds and nobody notices, it continues. The average break-in goes unnoticed for months. This module is about being able to tell that something happened, and when -- and making sure someone is told.",
    items: [
      {
        id: "logging/auth-events",
        title: "Sign-ins, failed sign-ins, and refused actions are written down",
        question:
          "Confirm your app records who signed in, what failed, and what was refused. Without it there is no way to work out what happened after an incident.",
        detector: null,
      },
      {
        id: "logging/no-secrets",
        covers: "no password, sign-in pass, or key is written into your app's activity records, and the database tool doesn't record every request",
        title: "Your app's activity records (logs) never contain passwords or keys",
        question:
          "Activity records are copied, sent to other services, and read by more people than your database. Confirm nothing sensitive is written into them.",
        detector: "logging:no-secrets-logged",
      },
      {
        id: "logging/alerting",
        title: "Someone would actually see an alert",
        question:
          "Records nobody reads aren't monitoring. Decide who gets told when something goes wrong, and for what.",
        detector: null,
      },
    ],
  },
  {
    id: "exceptional-conditions",
    owasp: "A10:2025",
    rank: 10,
    title: "When something unexpected happens",
    summary:
      "Errors are where applications behave least predictably. A check that crashes might let everyone through, an error message might reveal how the system is built, and one malformed request might bring the whole thing down.",
    items: [
      {
        id: "config/error-detail",
        covers: "your own code never sends error details to visitors, and you have your own error page",
        title: "Error messages don't show visitors how your site is built",
        question:
          "The technical details of an error (file names, code, database messages) tell an attacker how your site is built. Confirm visitors see a short message, and the detail goes into your private records instead.",
        detector: "server:no-internal-errors-returned",
      },
      {
        id: "errors/fail-closed",
        title: "When a check breaks, the answer is no",
        question:
          "If a permission check, a payment, or a sign-in lookup fails with an error, the safe outcome is to refuse. Confirm none of your error handling quietly carries on as if the check had passed.",
        detector: null,
      },
      {
        id: "errors/unhandled",
        title: "One unexpected request cannot crash or freeze the application",
        question:
          "Confirm unexpected errors are caught and answered with a short message, and that oversized or broken requests are refused early instead of using up memory or hanging.",
        detector: null,
      },
    ],
  },
];

/**
 * Review text quotes the reviewed repository -- page addresses, file names,
 * package names -- and anyone who can push there chooses them. The exact fix
 * is meant to be pasted into an AI assistant, so invisible characters (which
 * can hide instructions), line breaks and runaway length are removed from
 * everything a reader sees or copies.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\u2028\u2029]+/gu;
const MAX_TEXT = 800;

export function cleanText(text: string): string {
  const flat = text.replace(INVISIBLE, " ").replace(/ {2,}/g, " ").trim();
  return flat.length > MAX_TEXT ? `${flat.slice(0, MAX_TEXT - 1)}…` : flat;
}

function cleanRisk(risk: Risk): Risk {
  return {
    ...risk,
    what: cleanText(risk.what),
    impact: cleanText(risk.impact),
    fix: cleanText(risk.fix),
    ...(risk.fixDetail ? { fixDetail: cleanText(risk.fixDetail) } : {}),
  };
}

function cleanLead(lead: Unproven): Unproven {
  return {
    ...lead,
    what: cleanText(lead.what),
    why: cleanText(lead.why),
    check: cleanText(lead.check),
    ...(lead.checkDetail ? { checkDetail: cleanText(lead.checkDetail) } : {}),
  };
}

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
    operation: "something your app does with it",
    impact: "Someone could make this behave in ways it was not meant to.",
    fix: "Check the value before it is used: confirm it is what you expect, and refuse it when it is not.",
    detail: "Validate the value against the expected type and format before this line, and reject anything else.",
  };
  const entry = SOURCE_COPY[path.source.kind] ?? "Something a visitor controls";
  // The file and line are in the detailed view; the sentence names the page,
  // or the file when the page that leads here is not known.

  return {
    id: riskId(`taint/${path.sink.kind}`, path.sink.location),
    grade: SINK_GRADE[path.sink.kind] ?? "medium",
    what: path.door
      ? `${entry} on ${pageName(path.door)} is used directly in ${copy.operation}, and nothing checks it first.`
      : `In ${path.sink.location.path}, ${lowerFirst(entry)} is used directly in ${copy.operation}, and nothing checks it first.`,
    impact: copy.impact,
    fix: copy.fix,
    fixDetail: copy.detail,
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
    fix: finding.fix?.description ?? "Choose \"Show me the code\" at the top to see the code this is about.",
    ...(finding.fix?.detail ? { fixDetail: finding.fix.detail } : {}),
    ...(finding.location ? { location: finding.location } : {}),
    confirmedBy: "rule",
  };
}

/** A route where a visitor's input picks a record and nothing ties it to its owner. */
export interface OwnershipGap {
  door: Door;
  source: TaintSource;
  sink: Sink;
  via: string[];
}

function riskFromOwnership(gap: OwnershipGap): Risk {
  const entry = lowerFirst(SOURCE_COPY[gap.source.kind] ?? "something a visitor controls");
  const page = pageName(gap.door);

  return {
    id: riskId("access-control/ownership", gap.sink.location),
    grade: "high",
    what:
      `${upperFirst(page)} finds a saved record using ${entry}, and never ` +
      `checks that the record belongs to the person who is signed in.`,
    impact:
      "If these records belong to individual people -- invoices, messages, orders, profiles -- " +
      "anyone with an account can read or change someone else's just by changing that value. " +
      "This is the most common serious flaw in web applications.",
    fix:
      "When the page looks up the record, make it also check that the record belongs to the signed-in " +
      "person, and refuse if it does not. If every signed-in user is meant to see these records, this " +
      "is fine as it is: choose \"This is intended\".",
    fixDetail:
      "Add the signed-in user's id to the lookup (for example `WHERE id = $1 AND owner_id = $2` with " +
      "the session's user id), or load the record and return 403 unless its owner is the signed-in user.",
    mayBeIntended: true,
    location: gap.sink.location,
    evidence: `${gap.source.expression} → ${gap.via.join(" → ")} → ${gap.sink.expression}`,
    confirmedBy: "oracle",
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
  checks?: Map<string, CheckOutcome & { detector: string; notice?: string }>;
  /** Ownership gaps a suggestion pointed at and the rules confirmed. */
  ownership?: OwnershipGap[];
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
  "integrity/unsafe-decoding": "integrity/unsafe-decoding",
  "ai/prompt-to-action": "injection/ai-instructions",
  "design/unbounded-list": "design/unbounded-lists",
  "auth/permissive-cors": "config/cors",
  "auth/token-in-localstorage": "auth/session-storage",
  "auth/cookie-readable-by-scripts": "auth/session-storage",
};

const ITEM_FOR_SINK: Record<string, string> = {
  sql: "injection/database",
  shell: "injection/system-commands",
  html: "injection/page-content",
  "dynamic-code": "injection/system-commands",
  filesystem: "access-control/file-paths",
  redirect: "access-control/redirects",
  nosql: "injection/database",
  "outbound-request": "ssrf/url-allowlist",
  "xml-entities": "injection/xml-entities",
  "mass-assignment": "access-control/mass-assignment",
  "unsafe-decoding": "integrity/unsafe-decoding",
};

/**
 * Pattern rules that judge a line by how it is written, not by where its values
 * come from. Their findings are leads, not proof: see `Unproven`.
 *
 * Rules outside this set stay risks. A key written into the code is the
 * problem itself; there is no path left to prove.
 */
const UNPROVEN_RULES = new Set([
  "injection/sql-string-building",
  "injection/shell-string-building",
  "injection/unescaped-html",
  "integrity/unsafe-decoding",
  "ai/prompt-to-action",
  "design/unbounded-list",
]);

function unprovenFromFinding(finding: Finding): Unproven {
  return {
    id: riskId(finding.ruleId, finding.location),
    what: finding.location
      ? `${finding.title} (${finding.location.path} line ${finding.location.line}).`
      : `${finding.title}.`,
    why: finding.why,
    check: finding.fix?.description ?? "Choose \"Show me the code\" at the top to see the code this is about.",
    ...(finding.fix?.detail ? { checkDetail: finding.fix.detail } : {}),
    ...(finding.location ? { location: finding.location } : {}),
  };
}

export function buildReview(input: ReviewInput): SecurityReview {
  const risksByItem = new Map<string, Risk[]>();
  const unprovenByItem = new Map<string, Unproven[]>();

  /**
   * Two detectors reaching the same line have found one problem, not two. The
   * oracle's version wins: it names the route and carries the traced path,
   * where the pattern rule only knows the line. Reporting both would make the
   * user think there are two things to fix.
   */
  const attach = (itemId: string, risk: Risk): void => {
    const existing = risksByItem.get(itemId) ?? [];
    // Without a location there is no "same line" to collide on: two flawed
    // packages are two problems. Comparing missing locations as equal dropped
    // every one after the first.
    const sameSpot = risk.location
      ? existing.findIndex(
        (r) =>
          r.location?.path === risk.location?.path && r.location?.line === risk.location?.line,
      )
      : existing.findIndex((r) => r.id === risk.id);

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
    if (!itemId) continue;
    if (!UNPROVEN_RULES.has(finding.ruleId)) {
      attach(itemId, riskFromFinding(finding));
      continue;
    }
    // Traced to the same line already: the proven risk says it all.
    const proven = (risksByItem.get(itemId) ?? []).some(
      (r) =>
        r.location?.path === finding.location?.path && r.location?.line === finding.location?.line,
    );
    if (proven) continue;
    const leads = unprovenByItem.get(itemId) ?? [];
    leads.push(unprovenFromFinding(finding));
    unprovenByItem.set(itemId, leads);
  }

  for (const gap of input.ownership ?? []) {
    attach("access-control/object-ownership", riskFromOwnership(gap));
  }

  for (const [itemId, outcome] of input.checks ?? []) {
    if (outcome.status !== "risks") continue;
    for (const checkRisk of outcome.risks) attach(itemId, checkRisk);
  }

  // Routes with no authentication middleware are an access-control risk the
  // taint analysis cannot express -- there is no dangerous sink, the problem is
  // that the door has no lock at all.
  for (const door of input.inventory.doors) {
    if (door.guards.length > 0 || isPublicByDesign(door.path) || door.answersOnlyFixed) continue;

    attach("access-control/unguarded-routes", {
      id: riskId("access-control/unguarded", door.location),
      grade: door.method === "GET" ? "medium" : "high",
      what: door.method === "GET"
        ? `The page ${door.path} can be opened by anyone, without signing in.`
        : `The action ${door.path} can be used by anyone, without signing in.`,
      impact:
        `Anyone on the internet can use this address without an account. If it shows or ` +
        `changes anything that belongs to a particular person, they do not need to be that ` +
        `person to use it.`,
      fix:
        `If this is meant to be public, nothing needs fixing: choose "This is intended". If not, ` +
        `make it require signing in. Best: protect the whole section of the site it belongs to, ` +
        `so pages added there later are protected too.`,
      fixDetail:
        `Apply the app's sign-in middleware to ${door.method} ${door.path} ` +
        `(${door.location.path} line ${door.location.line}), ideally once on the router or path prefix ` +
        `it sits under rather than route by route.`,
      mayBeIntended: true,
      location: door.location,
      confirmedBy: "route-check",
    });
  }

  const modules = MODULES.map((shape): ReviewModule => ({
    id: shape.id,
    owasp: shape.owasp,
    rank: shape.rank,
    title: shape.title,
    summary: shape.summary,
    items: shape.items.map((item): ActionItem => {
      const risks = (risksByItem.get(item.id) ?? []).sort(byGrade).map(cleanRisk);
      const unproven = (unprovenByItem.get(item.id) ?? []).map(cleanLead);
      const outcome = input.checks?.get(item.id);
      const blocked = outcome?.status === "not-applicable" ? outcome.reason : undefined;
      const absent = outcome?.status === "not-applicable" && outcome.absent === true;
      const notice = outcome?.notice;

      return {
        ...item,
        ...(blocked ? { notApplicable: cleanText(blocked) } : {}),
        ...(notice ? { notice } : {}),
        risks,
        unproven,
        // "pass" needs a detector that actually ran and found nothing. A
        // detector that could not run here is not a pass, and neither is the
        // absence of one -- both hand the item back to the user.
        // An unproven lead is not a pass either: someone has to look at it.
        // "Doesn't apply" is not a pass either: it only says the thing this
        // item is about was not found in the project, with the reason shown.
        status: risks.length > 0
          ? "action-needed"
          : absent && unproven.length === 0
          ? "does-not-apply"
          : blocked || !item.detector || unproven.length > 0
          ? "needs-your-review"
          : "pass",
      };
    }),
  }));

  return { modules, summary: summarise(modules), unverified: explainUnverified(input.unverified) };
}

/**
 * Routes that are public on purpose; flagging them is noise, not safety.
 * Webhooks and sign-in callbacks are called by other services or by people
 * not yet signed in -- they are protected by signatures and state checks, not
 * by a session, and requiring one would break them.
 */
function isPublicByDesign(path: string): boolean {
  return /\/(health|healthz|ready|metrics|login|register|signup|refresh|logout|public|forgot\w*|reset\w*|webhooks?|callback|oauth)(\/|$)/.test(
    path,
  );
}

const GRADE_ORDER: Record<Grade, number> = { high: 0, medium: 1, low: 2 };
const byGrade = (a: Risk, b: Risk): number => GRADE_ORDER[a.grade] - GRADE_ORDER[b.grade];

function summarise(modules: ReviewModule[]): SecurityReview["summary"] {
  const summary = { high: 0, medium: 0, low: 0, awaitingReview: 0, clear: 0, unproven: 0 };

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
      summary.unproven += item.unproven.length;
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
