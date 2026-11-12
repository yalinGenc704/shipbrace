# Claude Code setup and outside tools

## This project's setup (2026-10-18)

Moved from CLAUDE.md on 2026-11-12. The rules that always apply (the
secret hook, which reviewer runs before a commit, agents in a session
opened from the parent folder, outside tools) stay in CLAUDE.md.

- **Hooks** (`.claude/settings.json`, scripts in `.claude/hooks/`):
  `protect-secrets.sh` blocks Read/Edit/Write of `.env`, `.env.*`,
  `.dev.vars*` and `*.pem` (not `*.example`); `lint-edited.sh` runs
  `oxlint --deny-warnings` on each edited `.ts/.tsx/.js/.mjs` file and hands
  problems back. Shell commands are not covered by the secret hook; the rule
  "never print secret values" still applies there.
- **Skill** `/ship` (`.claude/skills/ship/`): user-only. Checks a clean,
  pushed tree, runs typecheck, lint, tests and the benchmark, applies pending
  D1 migrations, deploys, then checks the live site (health, sign-in, CSP,
  robots, unsigned webhook refused, no folder review).
- **Sub-agent** `security-auditor` (`.claude/agents/`, added 2026-10-18):
  a read-only (Read, Grep, Glob) audit of ShipBrace itself, adapted from
  Osmani's agent-skills (MIT) with ShipBrace's own risky areas: webhook,
  sign-in, hostile repositories, the reviewer's internet wall, D1. It skips
  the benchmark's deliberately vulnerable apps. Its findings are leads that
  the main session verifies. It cannot run `npm audit`, so the main session
  does. First run 2026-10-18.
- **Sub-agent** `conventions-reviewer` (`.claude/agents/`, added 2026-10-20):
  checks a finished change against the load-bearing conventions in CLAUDE.md and
  runs typecheck, lint, tests and the benchmark (never with `--model`). It
  reads and runs checks only; use it before committing checker changes.
- **Planned:** the Cloudflare Observability MCP server, when live debugging
  is needed.

## Outside tools evaluated (2026-10-18)

**Tools evaluated (2026-10-18), for reference.** *Claude Code Setup*
(Anthropic, official) is installed; its read-only scan recommended the hooks,
`/ship` and the reviewer (now `conventions-reviewer`). *Fallow* (MIT, fallow-rs) is run on
demand with `npx fallow@3.34.1`, not installed: its first scan found a circular
import and an unlisted dependency (both fixed) plus `findAssignments` (removed
2026-10-20 with the other legacy code); its other findings are false positives (the
separate redirect and wall-check Workers, scripts run by hand, test fixtures
loaded by path, and `Reviewer.claim`, which is called over Cloudflare's RPC and
enforces "each outside step once" -- never remove it), so never use its
auto-fix. *NVIDIA SkillSpector* is a real open-source scanner for agent
skills; not installed, but worth running on any skill from outside the
Anthropic Directory before installing it. Not adopted: *Claude-Mem* (duplicates
CLAUDE.md, CLAUDE.local.md and built-in memory, and records every action,
secret-touching ones included); *Agent Reach* (acts through logged-in social
accounts via unofficial routes, and pulls text that can carry prompt
injection into a session holding Cloudflare and GitHub access); *Obsidian +
Graphify*-style code graphs (independent measurements show 13-34% savings on
medium projects, and a stale map misleads; Obsidian alone is a fine personal
notes app); *Everything Claude Code* (hundreds of generic skills, agents and
third-party hooks crowd the context and run code nobody chose; borrow single
pieces only); *Liner Model API* (checked 2026-10-18: a router that picks an
undisclosed model per request; "half price" is measured against OpenRouter's
cheapest model in a tier and the benchmarks are Liner's own, against Sonnet,
not Opus; OpenAI-style API only, so Claude Code cannot use it. ShipBrace makes
one optional AI call per review, so there is little to save, and sending code
excerpts to unnamed models would break the disclosure in
docs/legal/third-party-services.md. If cost matters later, try a cheaper
Claude model through `options.model` in `proposer.ts` and keep it only if
`scripts/bench.ts --model` still matches the perfect suggester with no
refusals); *Agent Skills* (addyosmani/agent-skills, MIT, checked 2026-10-18:
25 skills, 7 commands, 4 sub-agents; text only, its hooks are not wired into
Claude Code. Generic spec-to-ship advice that overlaps CLAUDE.md, `/ship` and
the built-in `/code-review`, `/simplify` and `/security-review`, and 25 skill
descriptions crowd the context. Worth borrowing: the layout of
`agents/code-reviewer.md` as a starting shape for `conventions-reviewer`.
Its `security-auditor` agent is a model judging code by checklist, so it
must never feed the product's findings. It is useful for auditing ShipBrace
itself: the built-in `/security-review` only covers pending changes, while
the auditor can review the whole system. Its checklist is also worth
reading as a list of detector ideas for the 16 items with none);
*Ponytail* (DietrichGebert/ponytail, MIT, v5.3.2, checked 2026-10-18: the
"-53% code" is the author's own benchmark; an independent JetBrains test is
reported at about 15% less code and 10% lower cost, and an earlier 80-94%
claim was withdrawn. The plugin runs its own Node scripts on every session
start and prompt, logs per-turn costs to `~/.config/ponytail/`, and can send
them to a webhook. Its useful idea fits in two lines of CLAUDE.md and needs
no plugin; any "less code" pressure must never trim a detector, a test or an
`undecidable` branch; the user declined adding it, 2026-10-18); *MiroFish*
(666ghj/MiroFish, AGPL-3.0, ~80k stars, checked 2026-10-18: a separate
Python app, not a Claude Code tool, that simulates a crowd of AI personas
reacting to your material. Its predictions are not validated anywhere we
found, and it sends the material to an OpenAI-style model (Alibaba's Qwen by
default) and to Zep Cloud for agent memory. Not useful before launch;
before opening up, a handful of real AI-app builders beat simulated ones).
Rule of thumb: prefer the Anthropic Directory, check viral
claims against the source, and read any outside skill before installing it.
