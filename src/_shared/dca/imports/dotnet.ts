// Extract C# `using` directives at the top of a .cs file. Skips the BCL
// (`System` and `System.*`) and ignores `using static` / `using alias = ...`
// / inline-scoped `using` blocks via line anchoring.
import type { ImportExtractor } from "../types.js";

const USING = /^\s*using\s+([A-Za-z_][\w.]*)\s*;/gm;

export const dotnetExtractor: ImportExtractor = {
  extensions: [".cs"],
  extract(content) {
    const out = new Set<string>();
    USING.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = USING.exec(content)) !== null) {
      const ns = m[1] ?? "";
      if (!ns) continue;
      if (ns === "System" || ns.startsWith("System.")) continue;
      out.add(ns);
    }
    return out;
  },
};
