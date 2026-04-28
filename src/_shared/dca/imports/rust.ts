// Extract Rust crate imports. Returns the first `use` segment, lowercased.
// Skips std/core/alloc/crate/super/self (built-in / intra-crate paths).
import type { ImportExtractor } from "../types.js";

const USE_STMT = /^\s*(?:pub\s+)?use\s+([A-Za-z_]\w*)/gm;
const EXTERN_CRATE = /^\s*extern\s+crate\s+([A-Za-z_]\w*)/gm;

const SKIP = new Set(["std", "core", "alloc", "crate", "super", "self"]);

export const rustExtractor: ImportExtractor = {
  extensions: [".rs"],
  extract(content) {
    const out = new Set<string>();
    for (const re of [USE_STMT, EXTERN_CRATE]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        const name = (m[1] ?? "").toLowerCase();
        if (name && !SKIP.has(name)) out.add(name);
      }
    }
    return out;
  },
};
