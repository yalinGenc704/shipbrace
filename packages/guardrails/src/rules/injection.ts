import { findSinksInFile } from "../analysis/inventory-ast.ts";
import type { SinkKind } from "../analysis/inventory.ts";
import type { Confidence, Finding, Rule, Severity } from "../types.ts";
import { isSource, isTestPath } from "../util.ts";

/**
 * Dangerous operations, found by parsing rather than by matching text.
 *
 * These rules are the safety net beneath the oracle. The oracle reports
 * operations it can prove untrusted input reaches; these report operations that
 * are built unsafely at all, whether or not a path could be proven.
 *
 * They share the oracle's sink detection deliberately. When they had their own
 * regular expressions the two disagreed, and the rules reported sample code
 * held inside string literals -- a generator that emits a query was read as a
 * generator that runs one. A parser cannot make that mistake, so both sides now
 * ask the same question of the same syntax tree.
 *
 * All three are emitted by one rule so the file is parsed once rather than
 * three times; the findings keep their separate ids so each still lands in the
 * right place on the checklist.
 */

interface SinkCopy {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  why: string;
  fix: string;
  learnMore: string;
}

const COPY: Partial<Record<SinkKind, SinkCopy>> = {
  sql: {
    ruleId: "injection/sql-string-building",
    severity: "critical",
    confidence: "likely",
    title: "A database query is built by pasting values into text",
    why:
      "This query is assembled by joining text together. If any part of it comes from " +
      "something a visitor typed, they can change what the query does -- reading other " +
      "people's records, or deleting the table. Passing values as parameters instead " +
      "keeps them as data that can never be read as commands.",
    fix:
      "Use the driver's parameter syntax -- the tagged template `` sql`...${value}` `` " +
      "for postgres, or `?` placeholders with an argument array for mysql2 -- so the " +
      "value is sent separately from the query text.",
    learnMore: "/explain/sql-injection",
  },
  shell: {
    ruleId: "injection/shell-string-building",
    severity: "critical",
    confidence: "likely",
    title: "A system command is built by pasting values into text",
    why:
      "This runs a command assembled from text. Shells treat characters like `;` and " +
      "`|` as instructions, so a value containing them can run a second, " +
      "attacker-chosen command on your server.",
    fix:
      "Pass the command and its arguments as a separate array rather than one string, " +
      "so the shell never parses the values.",
    learnMore: "/explain/command-injection",
  },
  "dynamic-code": {
    ruleId: "injection/shell-string-building",
    severity: "critical",
    confidence: "likely",
    title: "The application builds and runs code while it is running",
    why:
      "This turns a value into code and runs it. If any part of that value comes from " +
      "outside, whoever supplied it chooses what your application does next.",
    fix:
      "Replace it with a lookup table or a plain function. Almost anything built this " +
      "way can be expressed without turning data into instructions.",
    learnMore: "/explain/dynamic-code",
  },
  html: {
    ruleId: "injection/unescaped-html",
    severity: "high",
    confidence: "possible",
    title: "Raw HTML is inserted into the page without escaping",
    why:
      "Pages normally turn special characters in your data into plain text, so text stays " +
      "text. This line skips that protection for a value. If that value ever contains " +
      "something a user supplied, their markup -- including scripts that read logged-in " +
      "sessions -- will run in your visitors' browsers.",
    fix:
      "Let the page escape the value for you: in React render it as `{value}` instead of " +
      "using dangerouslySetInnerHTML; on a Hono server use the html`` helper instead of a " +
      "plain template. If it genuinely must be HTML, clean it with a library such as " +
      "DOMPurify first.",
    learnMore: "/explain/xss",
  },
};

export const unsafeSinks: Rule = {
  id: "injection/unsafe-sink",
  category: "injection",
  severity: "critical",
  appliesTo: (path) => isSource(path) && !isTestPath(path),

  check(file) {
    const findings: Finding[] = [];

    for (const sink of findSinksInFile(file)) {
      // A tagged query template parameterises every value it interpolates.
      if (sink.inherentlySafe) continue;

      const copy = COPY[sink.kind];
      if (!copy) continue;

      findings.push({
        ruleId: copy.ruleId,
        category: "injection",
        severity: copy.severity,
        confidence: copy.confidence,
        title: copy.title,
        why: copy.why,
        location: sink.location,
        fix: { kind: "manual", description: copy.fix },
        learnMore: copy.learnMore,
      });
    }
    return findings;
  },
};

export const injectionRules: Rule[] = [unsafeSinks];
