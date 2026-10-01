import { compose } from "./compose.ts";
import { authModule } from "./modules/auth.ts";
import { baseModule } from "./modules/base.ts";
import type { ComposeResult, Module, ScaffoldSpec } from "./types.ts";

export * from "./types.ts";
export { compose } from "./compose.ts";

export const defaultModules: Module[] = [baseModule, authModule];

/**
 * Whether a generated app ships with accounts is a per-app setting, not a
 * property of the generator. `generate` simply honours the spec.
 */
export function generate(spec: ScaffoldSpec, modules = defaultModules): ComposeResult {
  return compose(spec, modules);
}
