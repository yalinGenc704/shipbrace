import type { RepoSnapshot } from "../types.ts";
import type { Grade, Risk } from "./modules.ts";
import type { CheckOutcome } from "./checks.ts";

/**
 * Known published flaws in the packages an application installs (OWASP A03).
 *
 * The list of flaws lives in a public database, so this is the one check that
 * sends anything outside the platform. What is sent is deliberately narrow:
 *
 *  - Only package names and exact versions, read from the lockfile. Never code,
 *    file names, or anything else from the repository.
 *  - Only packages installed from the public npm registry. A private package's
 *    name can itself be confidential ("@acme/merger-billing"), and a flaw
 *    database cannot know about it anyway, so it is never sent.
 *  - Nothing at all without a lockfile. Version ranges in package.json do not
 *    say what is actually installed, and guessing would mean reporting flaws in
 *    versions the app may not use.
 *
 * Every result shown to the user names the source and its licence. Much of the
 * data comes from the GitHub Advisory Database under CC-BY 4.0, which requires
 * attribution wherever it is displayed.
 */

export interface Dependency {
  name: string;
  version: string;
  /** Listed in a package.json, as opposed to pulled in by another package. */
  direct: boolean;
}

export interface Advisory {
  id: string;
  /** Third-party text. Shown only in the detailed view, with attribution. */
  summary: string;
  grade: Grade;
  /** Lowest version that fixes it, when the advisory says. */
  fixedIn?: string;
  /** True when its details were not fetched (past the per-review cap): grade and fix unknown. */
  unchecked?: true;
}

export interface VulnerabilitySource {
  /** Shown to the user: who was asked, and under what terms the data is used. */
  readonly notice: string;
  lookup(dependencies: Dependency[]): Promise<Map<string, Advisory[]>>;
}

export const OSV_NOTICE =
  "Checked against OSV.dev, a free public database of known flaws run by Google's " +
  "open-source security team. Only the names and versions of public packages were " +
  "sent -- never your code or any private package names. Flaw data comes from the " +
  "GitHub Advisory Database and other sources, used under the CC-BY 4.0 licence.";

const keyOf = (d: Pick<Dependency, "name" | "version">) => `${d.name}@${d.version}`;
const PUBLIC_REGISTRY = /^https:\/\/registry\.npmjs\.org\//;
const EXACT = /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;

// --- reading what is installed -------------------------------------------------

/** Names listed directly in any package.json, so a fix can say who to update. */
function directNames(snapshot: RepoSnapshot): Set<string> {
  const names = new Set<string>();
  for (const manifest of snapshot.manifests.values()) {
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const deps = manifest[field];
      if (deps && typeof deps === "object") for (const name of Object.keys(deps)) names.add(name);
    }
  }
  return names;
}

/** npm's package-lock.json, versions 2 and 3. */
function fromPackageLock(content: string, direct: Set<string>): Dependency[] {
  const lock = JSON.parse(content) as { packages?: Record<string, { version?: string; resolved?: string; link?: boolean }> };
  const found: Dependency[] = [];

  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    const at = path.lastIndexOf("node_modules/");
    if (at === -1 || entry.link || !entry.version || !entry.resolved) continue;
    if (!PUBLIC_REGISTRY.test(entry.resolved) || !EXACT.test(entry.version)) continue;

    const name = path.slice(at + "node_modules/".length);
    found.push({ name, version: entry.version, direct: direct.has(name) });
  }
  return found;
}

/**
 * Bun's text lockfile. It is JSONC: trailing commas are allowed, so they are
 * removed before parsing. An entry is used only when it is unmistakably a
 * public-registry package: `["name@1.2.3", "", ...]`, where the empty string is
 * the default registry. Workspace, git, file, and private-registry entries do
 * not have that shape and are skipped, so anything unrecognised is left out
 * rather than sent.
 */
function fromBunLock(content: string, direct: Set<string>): Dependency[] {
  const lock = JSON.parse(content.replace(/,(\s*[}\]])/g, "$1")) as { packages?: Record<string, unknown> };
  const found: Dependency[] = [];

  for (const entry of Object.values(lock.packages ?? {})) {
    if (!Array.isArray(entry) || typeof entry[0] !== "string" || typeof entry[1] !== "string") continue;
    const registry = entry[1];
    if (registry !== "" && !PUBLIC_REGISTRY.test(registry)) continue;

    const at = entry[0].lastIndexOf("@");
    if (at <= 0) continue;
    const name = entry[0].slice(0, at);
    const version = entry[0].slice(at + 1);
    if (!EXACT.test(version)) continue;

    found.push({ name, version, direct: direct.has(name) });
  }
  return found;
}

export function installedDependencies(
  snapshot: RepoSnapshot,
): { dependencies: Dependency[] } | { reason: string } {
  const locks = snapshot.files.filter((f) => /(^|\/)(package-lock\.json|bun\.lock)$/.test(f.path));
  if (locks.length === 0) {
    const other = snapshot.files.some((f) => /(^|\/)(bun\.lockb|pnpm-lock\.yaml|yarn\.lock)$/.test(f.path));
    return {
      reason: other
        ? "Your lockfile's format can't be read yet (only package-lock.json and bun.lock can). Ask your AI assistant to run your package manager's audit command instead."
        : "Without a lockfile there's no exact record of which package versions your app installs, so they couldn't be checked. Save one with your code and this check can run.",
    };
  }

  const direct = directNames(snapshot);
  const seen = new Map<string, Dependency>();
  for (const lock of locks) {
    try {
      const parsed = lock.path.endsWith("bun.lock")
        ? fromBunLock(lock.content, direct)
        : fromPackageLock(lock.content, direct);
      for (const d of parsed) {
        const existing = seen.get(keyOf(d));
        seen.set(keyOf(d), existing ? { ...existing, direct: existing.direct || d.direct } : d);
      }
    } catch {
      return { reason: `${lock.path} could not be read, so the installed versions are unknown.` };
    }
  }
  return { dependencies: [...seen.values()] };
}

// --- turning advisories into risks ---------------------------------------------

const GRADE_RANK: Record<Grade, number> = { high: 0, medium: 1, low: 2 };

function riskFor(dep: Dependency, advisories: Advisory[], notice: string): Risk {
  const worst = advisories.reduce<Grade>(
    (grade, a) => (GRADE_RANK[a.grade] < GRADE_RANK[grade] ? a.grade : grade),
    "low",
  );
  const fixes = advisories.map((a) => a.fixedIn).filter((v): v is string => Boolean(v));
  const notLookedUp = advisories.some((a) => a.unchecked);
  const target = fixes.sort(compareVersions).at(-1);
  const ids = advisories.map((a) => a.id);
  const listed = ids.length > 3 ? `${ids.slice(0, 3).join(", ")} and ${ids.length - 3} more` : ids.join(", ");
  const count = advisories.length === 1 ? "a publicly known security flaw" : `${advisories.length} publicly known security flaws`;

  return {
    id: `components/known-vulnerability@${dep.name}@${dep.version}`,
    grade: worst,
    what:
      `The package ${dep.name} (version ${dep.version}) has ${count}.` +
      (dep.direct ? "" : " Your app doesn't use it directly; another package you use brings it in."),
    impact:
      "Flaws in packages are listed publicly, so anyone looking for weak sites knows exactly what " +
      "to try against apps still using this version. You inherit the flaw even though your own code is fine.",
    fix: notLookedUp && !target
      ? `A fixed version isn't known here. Ask your AI assistant to run your package manager's audit command for ${dep.name}.`
      : dep.direct
      ? target
        ? `Update ${dep.name} to version ${target} or later, then check your app still works.`
        : `No fixed version exists yet. See whether you can stop using ${dep.name}, or watch for an update.`
      : target
      ? `Update the package that brings in ${dep.name}, so it uses version ${target} or later.`
      : `No fixed version of ${dep.name} exists yet. See whether the package that brings it in has an alternative.`,
    ...(target
      ? {
        fixDetail: dep.direct
          ? `Set ${dep.name} to ${target} (or later) in package.json, reinstall, and commit the lockfile. Advisories: ${listed}.`
          : `Upgrade the dependency that pulls in ${dep.name} so it resolves to ${target} or later; if none exists, add "overrides": { "${dep.name}": "${target}" } to package.json. Advisories: ${listed}.`,
      }
      : { fixDetail: `Advisories: ${listed}.` }),
    evidence: `${advisories.map((a) => `${a.id}: ${a.summary}`).join(" | ")} | ${notice}`,
    confirmedBy: "rule",
  };
}

/** Numeric comparison of dotted versions; prerelease tags sort before the release. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core = "", pre] = v.split(/[-+]/, 2);
    return { parts: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length); i++) {
    const d = (x.parts[i] ?? 0) - (y.parts[i] ?? 0);
    if (d !== 0) return d;
  }
  if (x.pre && !y.pre) return -1;
  if (!x.pre && y.pre) return 1;
  return 0;
}

/**
 * Run the check. Every way it can fail to run hands the item back to the user
 * with the reason; none of them is a pass.
 */
export async function checkKnownVulnerabilities(
  snapshot: RepoSnapshot,
  source: VulnerabilitySource | undefined,
): Promise<CheckOutcome & { notice?: string }> {
  if (!source) {
    return {
      status: "not-applicable",
      reason:
        "Checking packages against the public list of known flaws is switched off. Ask your AI assistant to run your package manager's audit command instead.",
    };
  }
  const installed = installedDependencies(snapshot);
  if ("reason" in installed) return { status: "not-applicable", reason: installed.reason };
  if (installed.dependencies.length === 0) {
    return { status: "not-applicable", reason: "Your lockfile lists no public packages to check.", absent: true };
  }

  let found: Map<string, Advisory[]>;
  try {
    found = await source.lookup(installed.dependencies);
  } catch {
    return {
      status: "not-applicable",
      reason: "The public database of known flaws could not be reached, so nothing was checked this time.",
    };
  }

  const risks = installed.dependencies.flatMap((dep) => {
    const advisories = found.get(keyOf(dep)) ?? [];
    return advisories.length > 0 ? [riskFor(dep, advisories, source.notice)] : [];
  });
  return risks.length > 0
    ? { status: "risks", risks, notice: source.notice }
    : { status: "pass", notice: source.notice };
}

// --- OSV.dev -------------------------------------------------------------------

interface OsvVuln {
  id: string;
  summary?: string;
  withdrawn?: string;
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }>;
    database_specific?: { severity?: string };
  }>;
}

const OSV = "https://api.osv.dev/v1";
const BATCH = 1000;
// OSV.dev answers in well under a second; a call that hangs fails the lookup instead.
const TIMEOUT_MS = 20_000;
const DETAIL_CONCURRENCY = 8;
/**
 * At most this many advisories are fetched in full for one review, so a huge
 * or deliberately padded lockfile cannot turn one review into thousands of
 * requests. Advisories past it are still reported, with their id only.
 */
const MAX_ADVISORY_DETAILS = 300;

function gradeOf(vuln: OsvVuln): Grade {
  const label = (vuln.database_specific?.severity ?? vuln.affected?.[0]?.database_specific?.severity ?? "")
    .toUpperCase();
  if (label === "CRITICAL" || label === "HIGH") return "high";
  if (label === "LOW") return "low";
  // MODERATE, or no rating at all: a known flaw with no rating is not "low".
  return "medium";
}

/** The fix that applies to this version: the first `fixed` above it, in a range that contains it. */
function fixedFor(vuln: OsvVuln, dep: Dependency): string | undefined {
  const candidates: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== dep.name || affected.package?.ecosystem !== "npm") continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== "SEMVER") continue;
      for (const event of range.events ?? []) {
        if (event.fixed && compareVersions(event.fixed, dep.version) > 0) candidates.push(event.fixed);
      }
    }
  }
  return candidates.sort(compareVersions)[0];
}

/**
 * The OSV.dev source. `fetchImpl` is injectable so tests never touch the
 * network.
 */
export function createOsvSource(fetchImpl: typeof fetch = fetch): VulnerabilitySource {
  const post = async (url: string, body: unknown) => {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`OSV answered ${response.status}`);
    return response.json() as Promise<unknown>;
  };

  return {
    notice: OSV_NOTICE,

    async lookup(dependencies) {
      // 1. Which advisory ids apply to which package versions.
      const idsFor = new Map<string, Set<string>>();
      for (let i = 0; i < dependencies.length; i += BATCH) {
        const chunk = dependencies.slice(i, i + BATCH);
        const reply = (await post(`${OSV}/querybatch`, {
          queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })),
        })) as { results?: Array<{ vulns?: Array<{ id: string }> }> };

        (reply.results ?? []).forEach((result, index) => {
          const dep = chunk[index];
          if (!dep || !result.vulns?.length) return;
          idsFor.set(keyOf(dep), new Set(result.vulns.map((v) => v.id)));
        });
      }

      // 2. Details for each distinct advisory, a few at a time.
      const all = [...new Set([...idsFor.values()].flatMap((s) => [...s]))];
      const ids = all.slice(0, MAX_ADVISORY_DETAILS);
      const details = new Map<string, OsvVuln>();
      const unchecked = new Set(all.slice(MAX_ADVISORY_DETAILS));
      for (let i = 0; i < ids.length; i += DETAIL_CONCURRENCY) {
        await Promise.all(
          ids.slice(i, i + DETAIL_CONCURRENCY).map(async (id) => {
            const response = await fetchImpl(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
            if (!response.ok) throw new Error(`OSV answered ${response.status}`);
            details.set(id, (await response.json()) as OsvVuln);
          }),
        );
      }

      const out = new Map<string, Advisory[]>();
      for (const dep of dependencies) {
        const advisories = [...(idsFor.get(keyOf(dep)) ?? [])]
          .map((id) => details.get(id) ?? (unchecked.has(id) ? ({ id } as OsvVuln) : undefined))
          .filter((v): v is OsvVuln => Boolean(v) && !v!.withdrawn)
          .map((v): Advisory => {
            // Not looked up: assume the worst rather than let padding hide it.
            if (unchecked.has(v.id)) {
              return { id: v.id, summary: "Details were not looked up: this project has more advisories than one review fetches.", grade: "high", unchecked: true };
            }
            const fixedIn = fixedFor(v, dep);
            return {
              id: v.id,
              summary: (v.summary ?? "No summary published.").slice(0, 300),
              grade: gradeOf(v),
              ...(fixedIn ? { fixedIn } : {}),
            };
          });
        if (advisories.length > 0) out.set(keyOf(dep), advisories);
      }
      return out;
    },
  };
}
