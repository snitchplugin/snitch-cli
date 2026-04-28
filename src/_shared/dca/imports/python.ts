// Extract Python package imports from .py source. Returns the raw top-level
// segment so dead-file analysis can match local module names; the unused-deps
// analyzer normalizes (PEP 503) before comparing to declared deps.
import type { ImportExtractor } from "../types.js";

// `import foo` / `import foo.bar as baz` / `import foo, bar`
const IMPORT_LINE = /^\s*import\s+([^\n#]+)/gm;
// `from foo import x` / `from foo.bar import x`  (skip relative `from .`)
const FROM_IMPORT = /^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+/gm;

export const pythonExtractor: ImportExtractor = {
  extensions: [".py"],
  extract(content) {
    const out = new Set<string>();

    let m: RegExpExecArray | null;
    IMPORT_LINE.lastIndex = 0;
    while ((m = IMPORT_LINE.exec(content)) !== null) {
      // strip "as alias" suffixes, then split commas
      for (const raw of (m[1] ?? "").split(",")) {
        const name = raw.trim().split(/\s+as\s+/)[0]?.split(".")[0];
        if (name && /^[A-Za-z_]/.test(name)) out.add(name.toLowerCase());
      }
    }

    FROM_IMPORT.lastIndex = 0;
    while ((m = FROM_IMPORT.exec(content)) !== null) {
      const top = (m[1] ?? "").split(".")[0];
      if (top && /^[A-Za-z_]/.test(top)) out.add(top.toLowerCase());
    }

    return out;
  },
};
