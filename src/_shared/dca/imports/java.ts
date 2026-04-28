// Extract Java/Kotlin imports. Returns the dotted namespace WITHOUT the
// trailing class name. The unused-deps analyzer uses loose substring/prefix
// matching against `groupId:artifactId` since Java imports don't share a
// clean prefix with Maven coords.
import type { ImportExtractor } from "../types.js";

const IMPORT = /^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*(?:\.\*)?\s*;?/gm;

function isJdk(ns: string): boolean {
  return ns === "java" || ns === "javax" ||
    ns.startsWith("java.") || ns.startsWith("javax.") ||
    ns.startsWith("kotlin.") || ns === "kotlin";
}

export const javaExtractor: ImportExtractor = {
  extensions: [".java", ".kt"],
  extract(content) {
    const out = new Set<string>();
    IMPORT.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = IMPORT.exec(content)) !== null) {
      const full = m[1] ?? "";
      if (!full || isJdk(full)) continue;
      // Drop the last segment (the class name): com.foo.Bar → com.foo
      const idx = full.lastIndexOf(".");
      const ns = idx === -1 ? full : full.slice(0, idx);
      if (ns) out.add(ns);
    }
    return out;
  },
};
