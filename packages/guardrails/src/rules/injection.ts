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
  detail: string;
  learnMore: string;
}

const COPY: Partial<Record<SinkKind, SinkCopy>> = {
  sql: {
    ruleId: "injection/sql-string-building",
    severity: "critical",
    confidence: "likely",
    title: "A database request is put together by pasting in text",
    why:
      "If any of that text comes from a visitor, they can change what the request does -- " +
      "reading other people's records, or deleting the table.",
    fix:
      "Send values to the database separately from the request itself, so they are always " +
      "treated as plain text.",
    detail:
      "Use the driver's parameter syntax instead of joining text: the tagged template " +
      "`` sql`...${value}` `` for postgres, or `?` placeholders with an argument array for mysql2.",
    learnMore: "/explain/sql-injection",
  },
  shell: {
    ruleId: "injection/shell-string-building",
    severity: "critical",
    confidence: "likely",
    title: "A computer command is put together by pasting in text",
    why:
      "Some characters (like ; and |) tell the computer to start another command. If the text " +
      "comes from a visitor, they can run commands of their own on your server.",
    fix: "Don't build commands out of text. Use a ready-made package that does the job instead, if you can.",
    detail:
      "Pass the program and its arguments as a separate array (`execFile(cmd, [arg])`, or `spawn` " +
      "without `shell: true`) instead of one string, so the shell never parses the values.",
    learnMore: "/explain/command-injection",
  },
  "dynamic-code": {
    ruleId: "injection/shell-string-building",
    severity: "critical",
    confidence: "likely",
    title: "Your app turns text into code and runs it",
    why:
      "If any of that text comes from outside, whoever supplied it chooses what your app does next.",
    fix: "Do the same job without turning text into code. There is almost always a simpler way.",
    detail: "Replace `eval`/`new Function`/`vm.run*` with a lookup table or a plain function.",
    learnMore: "/explain/dynamic-code",
  },
  "unsafe-decoding": {
    ruleId: "integrity/unsafe-decoding",
    severity: "critical",
    confidence: "likely",
    title: "Data is unpacked with a tool that can turn it into working code",
    why:
      "If that data ever comes from outside, whoever wrote it chooses what your app runs.",
    fix: "Unpack data with a tool that only ever produces plain data, never code.",
    detail:
      "Use `JSON.parse` for data, or js-yaml 4's `load` (`safeLoad` in js-yaml 3), which only build plain values.",
    learnMore: "/explain/unsafe-decoding",
  },
  html: {
    ruleId: "injection/unescaped-html",
    severity: "high",
    confidence: "possible",
    title: "Text is put into the page without being made safe first",
    why:
      "Pages normally show text as plain text, but this line switches that off. If the text " +
      "ever comes from a visitor, their code runs in other visitors' browsers and can take over their accounts.",
    fix:
      "Show the value as plain text. If it really has to include formatting, clean it with a trusted cleaning package first.",
    detail:
      "Render it escaped: `{value}` in React instead of dangerouslySetInnerHTML; Hono's html`` helper " +
      "instead of a plain template; `<%= %>` not `<%- %>` in EJS. If it must be HTML, run it through DOMPurify first.",
    learnMore: "/explain/xss",
  },
};

const unsafeSinks: Rule = {
  id: "injection/unsafe-sink",
  category: "injection",
  severity: "critical",
  appliesTo: (path) => isSource(path) && !isTestPath(path),

  check(file) {
    const findings: Finding[] = [];

    for (const sink of findSinksInFile(file)) {
      // A tagged query template parameterises every value it interpolates, and
      // a query built only from fixed text has nothing a visitor can change.
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
        fix: { kind: "manual", description: copy.fix, detail: copy.detail },
        learnMore: copy.learnMore,
      });
    }
    return findings;
  },
};

export const injectionRules: Rule[] = [unsafeSinks];
