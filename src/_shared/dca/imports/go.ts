// Extract Go imports. Handles single-line `import "x"`, aliased
// `import alias "x"`, and parenthesized blocks of either.
import type { ImportExtractor } from "../types.js";

const IMPORT_BLOCK = /import\s*\(([^)]*)\)/gs;
const SINGLE_IMPORT = /^\s*import\s+(?:[A-Za-z_]\w*\s+)?"([^"]+)"/gm;
const QUOTED = /(?:[A-Za-z_]\w*|\.|_)?\s*"([^"]+)"/g;

export const goExtractor: ImportExtractor = {
  extensions: [".go"],
  extract(content) {
    const out = new Set<string>();

    let m: RegExpExecArray | null;
    IMPORT_BLOCK.lastIndex = 0;
    while ((m = IMPORT_BLOCK.exec(content)) !== null) {
      const body = m[1] ?? "";
      QUOTED.lastIndex = 0;
      let q: RegExpExecArray | null;
      while ((q = QUOTED.exec(body)) !== null) {
        if (q[1]) out.add(q[1]);
      }
    }

    SINGLE_IMPORT.lastIndex = 0;
    while ((m = SINGLE_IMPORT.exec(content)) !== null) {
      if (m[1]) out.add(m[1]);
    }

    return out;
  },
};
