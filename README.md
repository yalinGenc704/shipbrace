# Aegis

**A safety net for people building websites with AI.**

More and more people build web apps by describing what they want to an AI
coding assistant, without reading the code themselves. Aegis is meant to sit
next to whichever assistant they use and quietly take care of the parts that
need an expert: **security, how the app is put together, and putting it
online**, so the builder can stay focused on what the app should do.

> **Where it stands today (October 2026):** the **security review** is built
> and works end to end with GitHub. Generating a solid starting structure for
> new apps exists as a building block but is not yet offered to users.
> **Putting users' apps online is not started.** See [What is built](#what-is-built-and-what-is-not).

---

## What it does today, in one minute

1. You connect your GitHub repository (where your code lives) to the Aegis
   GitHub App.
2. Every time you, or your AI assistant, save changes there (a "push"), GitHub
   tells Aegis.
3. Aegis reads the code and checks it against a security checklist.
4. Usually within a minute, a mark appears next to the change on GitHub:
   - ❌ **at least one serious problem was proven**
   - ⚠️ **problems were proven, none serious**
   - ✅ **no problems were proven**
5. Clicking it opens a plain-language report: what is wrong, why it matters,
   what to do, and exactly which line. Past reviews of the repository are
   kept, so you can see how things changed over time.

Even a ✅ always lists what is still **"your call"**: things no automatic check
can decide for you. Aegis never says an app is "secure". No tool can honestly
promise that.

---

## How Aegis finds problems

### The one rule everything follows

> **An AI may suggest where a problem might be. Only rules may decide that it is real.**

AI models are good at imagining where to look, and bad at being certain. They
can sound just as confident when they are wrong. Someone who cannot read code
cannot tell the difference, so Aegis never shows them an AI's guess as a fact.

**Rules** are the opposite: fixed, written-down checks that follow the code
step by step. Given the same code, a rule always gives the same answer, and it
can show exactly how it reached it. A rule can miss things, but it does not make
things up.

So Aegis works like a newsroom: the AI is a tipster, and the rules are the
fact-checkers. A tip is only printed once it has been checked and confirmed.
The review also works **with no AI at all**: no account, no key, no cost.

### The steps

```
1. Take stock      Find every web address the app answers (its "routes"),
                   every place a visitor can put something in, and every
                   dangerous thing the code does.                       rules
2. Connect         Follow each visitor input through the code to see
                   whether it reaches a dangerous action unprotected.   rules
3. Pair up         Try every input against every kind of dangerous
                   action, in case step 2 missed a connection.          rules
4. Ask (optional)  Ask an AI which records in the app are private,
                   such as invoices or messages.                        AI
5. Verify          Check each suggestion from steps 3 and 4 by
                   following the code itself. Only a confirmed one
                   becomes a finding.                                   rules
6. Report          Sort everything into the ten areas of the checklist.
```

Steps 1-3 always run before the AI is asked anything. So the rules' own
findings exist on their own, and a repository written to trick the AI cannot
use it to hide a real problem.

### An example

Suppose an app has the address `/reports/:id`, and the code does this:

```js
const id = c.req.param("id");                                  // a visitor types this
db.query(`SELECT * FROM reports WHERE id = ${id}`);            // pasted straight into a database command
```

Aegis sees that `id` comes from the visitor, follows it to the next line, and
sees it pasted directly into a database command. A visitor could type database
instructions instead of a number. Nothing in between checks it. That is
**proven**, so it is reported as a high risk on that exact line.

If the code had instead used the database's safe form (`` sql`... ${id}` ``,
which keeps the value as data rather than instructions), Aegis would follow the
same path, see the protection, and report nothing.

### Four possible results

| Result | What it means |
| --- | --- |
| **Needs fixing** (a risk) | A rule proved it, by tracing the path or by finding the problem itself (for example, a password written into the code). |
| **Worth a look, not proven** | A line is written in a risky way, but Aegis could not show that a visitor's input reaches it. Never counted as a risk. |
| **Your call** | Nothing automatic can decide this one, or the check could not run here. Aegis says so and hands it to you with a plain question. |
| **Checked** | A check actually ran and found nothing. Aegis says exactly what it checked. Nothing is marked "checked" just because no check exists for it. |

---

## The rules

"The rules" are all the fixed checks Aegis runs. None of them use AI. They
come in three kinds.

### 1. Following visitor input (the core)

Aegis reads the code the way a compiler does (as a structured tree, not as
plain text), so it can tell real code from code that only appears inside a
piece of text. It then follows values from where a **visitor controls them**
to where they **do something dangerous**.

**Where visitors control values:** the web address and its parts, form and API
data, headers, cookies, uploaded files, replies from other websites, content
read from GitHub repositories, and settings an outsider can influence (such as
a pull request's title). Ordinary settings, like the database address, are
trusted on purpose.

**Dangerous actions it watches:**

| Action | What can go wrong |
| --- | --- |
| Database commands (SQL) | A visitor rewrites the command and reads or deletes data |
| MongoDB-style queries | A visitor turns a lookup into "match everything" |
| System commands | A visitor runs their own commands on your server |
| File access | A visitor reads files outside the intended folder |
| Page content (HTML) | A visitor injects scripts that run in other people's browsers |
| Redirects | Your site sends people on to a fake site |
| Requests to other servers | Your server is tricked into fetching internal addresses |
| Running code built at runtime | A visitor's text gets run as code |

**What counts as protection on the way:** checking the input against a schema,
the database's safe "parameterised" form, proper escaping, and similar. It
follows values through helper functions, including into other files.

When it is unsure (unfamiliar code, a function defined twice, and so on), it
says "could not decide". **It never guesses "safe".**

### 2. Line-by-line checks

These look for problems that are the problem by themselves:

- passwords, API keys and tokens written directly into the code
- an environment file with real secrets committed to the repository
- secret settings that end up in code sent to the browser
- an API that accepts calls from any website
- login tokens stored where any script on the page can read them
- login tokens signed with a key written in the code
- risky ways of building database queries, commands, code or HTML (shown as
  "worth a look" unless a visitor's input is traced to them)

### 3. Whole-project checks

These look at how the app is set up as a whole:

- every private page has a sign-in check, and admin pages check the role
- signed-in users are protected from other websites acting on their behalf (CSRF)
- passwords are stored with a slow, modern hash, and are never sent back to the browser
- login sessions expire
- standard protective browser headers are switched on
- error pages do not reveal the app's internals
- the database is not exposed to the internet
- sensitive actions are rate-limited (limited in how often they can be repeated)
- logs do not contain passwords or keys
- package versions are pinned and recorded in a lockfile
- installed packages have no publicly known security flaws (looked up on
  OSV.dev, a free public database run by Google; only package names and
  versions are sent)

### The checklist

Findings are grouped by the **OWASP Top 10 (2025 edition)**, the industry's
standard list of the ten most common kinds of web-app security problems, in
order of how often they occur:

1. Who is allowed to do what
2. Settings that leave the door open
3. Building blocks you did not write
4. Protecting passwords, keys and personal data
5. Visitor input being treated as instructions
6. Gaps in how the feature was designed
7. Proving who someone is
8. Trusting data that could have been tampered with
9. Noticing when something goes wrong
10. When something unexpected happens

There are **38 items**. **22 are checked automatically; 16 are handed to you**
with a plain question, because no rule can answer them. Examples: what personal
data you store, how someone might deliberately misuse a feature, and whether
anyone would actually notice an alert.

### What the optional AI step does

Rules cannot know which records in an app are private: whether an invoice
belongs to one customer, or a message to one person. An AI can make a good
guess. Aegis asks it, then the rules check the guess. If a private record can be
looked up by its number by someone signed in, and nothing on the way checks
*who* is signed in, that is a proven problem. Otherwise the guess is dropped.

The AI step is **off unless switched on**. When it is on, short excerpts of
code files are sent to the AI provider (Anthropic), with recognised secrets
removed first.

---

## How well it works (honest numbers)

**The test set:** 56 small sample apps with a known answer key: 31 real
problems and 26 deliberately safe "decoys" built to look dangerous.

| | Real problems proven | False alarms |
| --- | --- | --- |
| Rules alone | 27 of 31 | 0 |
| With a perfect AI suggester | 30 of 31 | 0 |

With a real AI (Claude) on the earlier, 31-app version of this test set, Aegis
matched the perfect suggester exactly, with no false alarms and no refusals.
It has not been re-run on the current 56 apps.

The one problem never found yet: a comment saved by one visitor and later shown
to others as raw page code.

**On real outside apps** (deliberately insecure practice apps used for
training: DVNA, OWASP NodeGoat, OWASP Juice Shop): Aegis found 5 of DVNA's
19 documented holes automatically. It does not yet detect XML upload attacks
(XXE), some MongoDB-style attacks, a session secret left at its default, or
sign-in checks written inside a page's own code. Testing on these apps also
uncovered false alarms the sample apps never had. Those were fixed, and the
sample set grew.

The guiding principle: **missing a problem is a gap; inventing one is a
defect.** Aegis is tuned to say less rather than to be wrong. Warnings about
correct code teach people to ignore the tool, so each one is treated as a bug.

---

## Keeping users' code safe

Everything Aegis reviews is someone else's code, and has to be treated as
possibly hostile.

- **It is never run.** Aegis only reads it.
- **It is read in a sealed-off process.** Each review runs separately, with
  no passwords or keys, no network, no access to other files, and a time and
  memory limit. A booby-trapped file can stop one review, but not reach
  anything else.
- **Secrets are blanked out** before a finding is created, so a leaked key is
  never copied into reports or logs.
- **Kept reviews are reached only by unguessable links** shown on the GitHub
  check, until sign-in exists.

What leaves the platform, and what users must be told, is written down in
[docs/legal/third-party-services.md](docs/legal/third-party-services.md).

---

## What is built and what is not

| Part of the vision | Status |
| --- | --- |
| **Security review** of an app's code | ✅ Built. Works with no AI; the AI step is optional |
| **GitHub App:** review every push and show a mark on GitHub | ✅ Built and tested live |
| **Report pages and review history** | ✅ Built |
| **Starting structure for new apps** (a solid, safe skeleton: database, logins, charts, spreadsheets, build setup) | 🟡 The generator exists and its apps pass Aegis's own review (the one exception, a missing lockfile, goes away on first install), but users cannot reach it yet |
| **Aegis running online all the time** | ⏳ Next. Today it runs on a laptop |
| **Sign-up, accounts, privacy notices** | ⏳ Needed before anyone else uses it |
| **Putting users' apps online** (the "handles deployment" part) | ❌ Not started |
| **Guiding how the app is put together** while it is being built | ❌ Not started, beyond the starting structure |

---

## For developers

The full working notes, commands and current gaps are in
[CLAUDE.md](CLAUDE.md). The reasoning behind the design is in
[docs/architecture.md](docs/architecture.md).

| Folder | What it is |
| --- | --- |
| `packages/guardrails/` | The review engine: reading code, the rules, the verifier, the checklist, and the benchmark (`bench/`) |
| `packages/scaffold/` | The generator for new apps' starting structure |
| `server/` | The review server: GitHub App, review history (PostgreSQL), the sealed review process |
| `app/` | The dashboard (React) |
| `scripts/` | Benchmark and comparison tools |

```bash
npm ci
node --experimental-strip-types --test packages/guardrails/test/*.test.ts packages/scaffold/test/*.test.ts server/test/*.test.ts
node --experimental-strip-types scripts/bench.ts
```
