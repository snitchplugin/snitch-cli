// Extract Ruby gem imports. `require 'rails/all'` → `rails`.
// Skips `require_relative` and stdlib gems (small list).
import type { ImportExtractor } from "../types.js";

const REQUIRE = /^\s*require\s+['"]([^'"]+)['"]/gm;

const STDLIB = new Set([
  "json",
  "yaml",
  "uri",
  "net/http",
  "net/https",
  "open-uri",
  "openssl",
  "fileutils",
  "pathname",
  "set",
  "csv",
  "logger",
  "digest",
  "base64",
  "stringio",
  "date",
  "time",
  "tempfile",
]);

export const rubyExtractor: ImportExtractor = {
  extensions: [".rb"],
  extract(content) {
    const out = new Set<string>();
    REQUIRE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REQUIRE.exec(content)) !== null) {
      const spec = (m[1] ?? "").trim();
      if (!spec || STDLIB.has(spec)) continue;
      const top = (spec.split("/")[0] ?? "").toLowerCase();
      if (top) out.add(top);
    }
    return out;
  },
};
