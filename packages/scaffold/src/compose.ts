import type { ComposeResult, EnvVar, GeneratedFile, Module, ScaffoldSpec } from "./types.ts";

/** Placeholder that cannot work by accident, so a copied .env fails at startup. */
const SECRET_PLACEHOLDER = "CHANGE_ME__generate_with_openssl_rand_base64_32";

export function compose(spec: ScaffoldSpec, modules: Module[]): ComposeResult {
  const warnings: string[] = [];
  const active = modules.filter((m) => !m.when || m.when(spec));

  const appDeps = mergeDeps(active, "appDeps", warnings);
  const serverDeps = mergeDeps(active, "serverDeps", warnings);
  const env = mergeEnv(active, warnings);

  const byPath = new Map<string, GeneratedFile>();
  const owner = new Map<string, string>();

  for (const module of active) {
    for (const file of module.files(spec)) {
      const previous = owner.get(file.path);
      if (previous && previous !== module.id) {
        // Last write wins, but silently shadowing another module's file is how a
        // scaffold quietly loses a security default. Always say so.
        warnings.push(`${module.id} overwrites ${file.path} previously written by ${previous}`);
      }
      byPath.set(file.path, file);
      owner.set(file.path, module.id);
    }
  }

  // Generated last so they reflect the fully merged dependency and env sets.
  for (const file of [
    rootPackageJson(spec),
    appPackageJson(spec, appDeps),
    serverPackageJson(spec, serverDeps),
    envExample(env),
  ]) {
    byPath.set(file.path, file);
  }

  const files = [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
  return { files, warnings };
}

/**
 * Two modules asking for different versions of the same package is a real
 * conflict -- resolving it silently would produce a lockfile nobody chose.
 */
function mergeDeps(
  modules: Module[],
  key: "appDeps" | "serverDeps",
  warnings: string[],
): Record<string, string> {
  const merged: Record<string, string> = {};
  const from: Record<string, string> = {};

  for (const module of modules) {
    for (const [name, version] of Object.entries(module[key] ?? {})) {
      const existing = merged[name];
      if (existing && existing !== version) {
        warnings.push(
          `${key}: ${module.id} wants ${name}@${version} but ${from[name]} wants ${existing}; keeping ${existing}`,
        );
        continue;
      }
      merged[name] = version;
      from[name] = module.id;
    }
  }
  return Object.fromEntries(Object.entries(merged).sort(([a], [b]) => a.localeCompare(b)));
}

function mergeEnv(modules: Module[], warnings: string[]): EnvVar[] {
  const byName = new Map<string, EnvVar>();

  for (const module of modules) {
    for (const variable of module.env ?? []) {
      const existing = byName.get(variable.name);
      if (existing && existing.secret !== variable.secret) {
        warnings.push(`env: ${variable.name} declared with conflicting secrecy; treating as secret`);
        byName.set(variable.name, { ...variable, secret: true });
        continue;
      }
      byName.set(variable.name, existing ?? variable);
    }
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function envExample(env: EnvVar[]): GeneratedFile {
  const body = env
    .map((v) => {
      const value = v.secret ? SECRET_PLACEHOLDER : v.example ?? "";
      return `# ${v.description}\n${v.name}=${value}`;
    })
    .join("\n\n");

  return {
    path: ".env.example",
    contents:
      `# Copy to .env and fill in. .env is git-ignored and must stay that way.\n` +
      `# Values marked CHANGE_ME are secrets -- generate a fresh one per environment.\n\n` +
      `${body}\n`,
  };
}

/**
 * The workspace root.
 *
 * Without this the two sub-manifests are unrelated folders: `bun install` at the
 * root installs nothing, `bun run --filter` has no workspaces to filter, and the
 * Dockerfile's `COPY package.json` fails on a missing file before the build
 * starts. It carries no dependencies of its own -- only the tooling every
 * generated project is checked with.
 */
function rootPackageJson(spec: ScaffoldSpec): GeneratedFile {
  return {
    path: "package.json",
    contents: json({
      name: spec.name,
      private: true,
      type: "module",
      workspaces: ["app", "server"],
      scripts: {
        dev: "bun run --filter '*' dev",
        build: "bun run --filter './app' build",
        start: "bun run server/src/index.ts",
        check: "tsc --noEmit && oxlint . && oxfmt --check .",
      },
      devDependencies: {
        oxlint: "1.80.0",
        oxfmt: "0.65.0",
        typescript: "7.0.2",
      },
    }),
  };
}

function appPackageJson(spec: ScaffoldSpec, deps: Record<string, string>): GeneratedFile {
  return {
    path: "app/package.json",
    contents: json({
      name: `${spec.name}-app`,
      private: true,
      type: "module",
      scripts: {
        dev: "vite",
        build: "tsc --noEmit && vite build",
        preview: "vite preview",
      },
      dependencies: deps,
      devDependencies: {
        "@vitejs/plugin-react": "6.1.1",
        "@tailwindcss/vite": "4.3.3",
        vite: "8.2.2",
        typescript: "7.0.2",
      },
    }),
  };
}

function serverPackageJson(spec: ScaffoldSpec, deps: Record<string, string>): GeneratedFile {
  return {
    path: "server/package.json",
    contents: json({
      name: `${spec.name}-server`,
      private: true,
      type: "module",
      scripts: { dev: "bun run --hot src/index.ts", start: "bun run src/index.ts" },
      dependencies: deps,
      devDependencies: { "@types/bun": "latest", typescript: "7.0.2" },
    }),
  };
}

const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
