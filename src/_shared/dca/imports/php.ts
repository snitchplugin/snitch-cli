// Extract PHP `use Vendor\\Namespace\\Class;` statements. Returns the top
// vendor segment lowercased (`Symfony` → `symfony`). The analyzer compares
// against the vendor part of `vendor/package` Composer coords.
import type { ImportExtractor } from "../types.js";

const USE = /^\s*use\s+([A-Z][A-Za-z0-9_]*)(?:\\[A-Za-z0-9_\\]+)?\s*(?:as\s+\w+)?\s*;/gm;

export const phpExtractor: ImportExtractor = {
  extensions: [".php"],
  extract(content) {
    const out = new Set<string>();
    USE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = USE.exec(content)) !== null) {
      const vendor = (m[1] ?? "").toLowerCase();
      if (vendor) out.add(vendor);
    }
    return out;
  },
};
