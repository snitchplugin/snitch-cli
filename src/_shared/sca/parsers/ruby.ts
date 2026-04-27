// Handles Gemfile.lock: bundler's custom text format. We scan the GEM section's
// "specs:" block — each gem appears as "    name (version)" (4-space indent),
// and transitive deps appear at deeper indent ("      name (>= 1.0)") which we skip.
import type { DepEntry, ManifestParser } from "../types.js";

function parseGemfileLock(content: string, manifestPath: string): DepEntry[] {
  const out = new Map<string, DepEntry>();
  const lines = content.split(/\r?\n/);
  let inSpecs = false;
  for (const line of lines) {
    // section headers (GEM, GIT, PATH, PLATFORMS, DEPENDENCIES, BUNDLED WITH) start at column 0
    if (/^[A-Z]/.test(line)) {
      inSpecs = false;
      continue;
    }
    if (line === "  specs:") {
      inSpecs = true;
      continue;
    }
    if (!inSpecs) continue;
    // gem entries are indented exactly 4 spaces; their deps are 6+ spaces
    const m = line.match(/^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$/);
    if (!m) continue;
    const name = m[1]!;
    const version = m[2]!;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "RubyGems", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const rubyParser: ManifestParser = {
  filenames: ["Gemfile.lock"],
  parse(content, manifestPath) {
    return parseGemfileLock(content, manifestPath);
  },
};
