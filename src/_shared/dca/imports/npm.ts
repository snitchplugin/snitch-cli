// Extract bare-specifier package imports from JS/TS source.
// Regex-based, not AST. Catches the 95% case: ESM imports, CJS require,
// dynamic import(), re-exports. Strips relative / absolute / node:builtins.
import type { ImportExtractor } from "../types.js";

const ESM_IMPORT = /(?:^|[\s;])(?:import|export)\b[\s\S]*?from\s*['"]([^'"]+)['"]/g;
const ESM_BARE_IMPORT = /(?:^|[\s;])import\s*['"]([^'"]+)['"]/g;
const DYNAMIC_IMPORT = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const REQUIRE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

function isExternal(spec: string): boolean {
  if (!spec) return false;
  if (spec.startsWith(".")) return false; // relative
  if (spec.startsWith("/")) return false; // absolute
  if (spec.startsWith("node:")) return false; // builtin
  if (/^[a-z]+:/i.test(spec)) return false; // protocol (file:, http:, data:)
  return true;
}

function normalize(spec: string): string {
  // @scope/pkg/sub → @scope/pkg ; pkg/sub → pkg
  if (spec.startsWith("@")) {
    const parts = spec.split("/");
    return (parts[0] + "/" + (parts[1] ?? "")).toLowerCase();
  }
  return (spec.split("/")[0] ?? "").toLowerCase();
}

export const npmExtractor: ImportExtractor = {
  extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
  extract(content) {
    const out = new Set<string>();
    for (const re of [ESM_IMPORT, ESM_BARE_IMPORT, DYNAMIC_IMPORT, REQUIRE]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        const spec = m[1];
        if (spec && isExternal(spec)) {
          const n = normalize(spec);
          if (n) out.add(n);
        }
      }
    }
    return out;
  },
};
