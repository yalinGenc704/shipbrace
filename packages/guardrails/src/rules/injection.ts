import type { Finding, Rule } from "../types.ts";
import { isSource, isTestPath, locate, scanLines } from "../util.ts";

/**
 * The `postgres` and `mysql2` drivers both support parameterised queries, but an
 * LLM asked to "filter by the search box" will reach for template interpolation
 * because it reads more naturally. That is SQL injection.
 */
export const sqlInterpolation: Rule = {
  id: "injection/sql-string-building",
  category: "injection",
  severity: "critical",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    /**
     * A single keyword is not enough to call something SQL.
     *
     * Matching a bare `WHERE` case-insensitively flags every template literal
     * containing a variable named `where` -- which is how this rule fired on
     * ordinary prose in this very package. Requiring the paired keywords that
     * make a statement (SELECT…FROM, UPDATE…SET) keeps real queries and drops
     * identifiers that merely share a name.
     *
     * The character classes exclude newlines so a match cannot span from one
     * backtick near the top of a file to another hundreds of lines below.
     */
    const STATEMENT = String.raw`(?:SELECT[^\n]*?\bFROM|INSERT\s+INTO[^\n]*?\bVALUES|UPDATE[^\n]*?\bSET|DELETE\s+FROM)`;

    // A template literal containing ${...} that also reads as SQL.
    const templated = new RegExp("`[^`\\n]*\\b" + STATEMENT + "\\b[^`\\n]*\\$\\{", "i");
    // Old-fashioned "SELECT ..." + variable concatenation.
    const concatenated = new RegExp("[\"'][^\"'\\n]*\\b" + STATEMENT + "\\b[^\"'\\n]*[\"']\\s*\\+", "i");

    const findings: Finding[] = [];

    for (const re of [templated, concatenated]) {
      for (const hit of scanLines(file, re)) {
        // `postgres` (porsager) tags templates and parameterises them safely:
        //   sql`select * from users where id = ${id}`
        // Only an *untagged* template is dangerous, so require no tag before the
        // backtick. The optional backslash matters because code generators write
        // the tag escaped inside their own template -- sql\` -- and without it a
        // generator emitting safe queries is reported as emitting unsafe ones.
        if (/\b(sql|db)\s*\\?`/.test(hit.text)) continue;

        findings.push({
          ruleId: sqlInterpolation.id,
          category: "injection",
          severity: "critical",
          confidence: "likely",
          title: "A database query is built by pasting values into text",
          why:
            `This query is assembled by joining strings together. If any part of it comes ` +
            `from something a visitor typed, they can change what the query does -- reading ` +
            `other people's records, or deleting the table. Passing values as parameters ` +
            `instead keeps them as data that can never be read as commands.`,
          location: locate(file, hit),
          fix: {
            kind: "manual",
            description:
              "Use the driver's parameter syntax -- the tagged template `` sql`...${value}` `` " +
              "for postgres, or `?` placeholders with an argument array for mysql2 -- so the " +
              "value is sent separately from the query text.",
          },
          learnMore: "/explain/sql-injection",
        });
      }
    }
    return findings;
  },
};

/** React escapes by default; this prop is the one documented way to switch that off. */
export const rawHtmlInjection: Rule = {
  id: "injection/unescaped-html",
  category: "injection",
  severity: "high",
  appliesTo: (p) => /\.[jt]sx$/.test(p) && !isTestPath(p),

  check(file) {
    return scanLines(file, /dangerouslySetInnerHTML/).map((hit): Finding => ({
      ruleId: rawHtmlInjection.id,
      category: "injection",
      severity: "high",
      confidence: "possible",
      title: "Raw HTML is inserted into the page without escaping",
      why:
        `React normally neutralises HTML in your data so that text stays text. This line ` +
        `turns that protection off for one value. If that value ever contains something a ` +
        `user supplied, their markup -- including scripts that read logged-in sessions -- ` +
        `will run in your visitors' browsers.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "If the content is plain text, render it as `{value}` and delete this prop. If it " +
          "genuinely must be HTML, sanitise it with a library such as DOMPurify first.",
      },
      learnMore: "/explain/xss",
    }));
  },
};

/** Shell execution with interpolated input is command injection. */
export const shellInterpolation: Rule = {
  id: "injection/shell-string-building",
  category: "injection",
  severity: "critical",
  appliesTo: (p) => isSource(p) && !isTestPath(p),

  check(file) {
    const re = /\b(execSync|exec|spawnSync|\$)\s*\(?\s*[`"'][^`"']*\$\{/;

    return scanLines(file, re).map((hit): Finding => ({
      ruleId: shellInterpolation.id,
      category: "injection",
      severity: "critical",
      confidence: "likely",
      title: "A system command is built by pasting values into text",
      why:
        `This runs a shell command assembled from strings. Shells treat characters like ` +
        `\`;\` and \`|\` as instructions, so a value containing them can run a second, ` +
        `attacker-chosen command on your server.`,
      location: locate(file, hit),
      fix: {
        kind: "manual",
        description:
          "Pass the command and its arguments as a separate array rather than one string, " +
          "so the shell never parses the values.",
      },
      learnMore: "/explain/command-injection",
    }));
  },
};

export const injectionRules: Rule[] = [sqlInterpolation, rawHtmlInjection, shellInterpolation];
