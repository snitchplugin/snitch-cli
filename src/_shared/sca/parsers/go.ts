// Handles go.sum: each line is "module version[/go.mod] h1:hash".
// We dedupe so the "/go.mod" companion line doesn't double-count.
import type { DepEntry, ManifestParser } from "../types.js";

function parseGoSum(content: string, manifestPath: string): DepEntry[] {
  const out = new Map<string, DepEntry>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const name = parts[0]!;
    let version = parts[1]!;
    // strip "/go.mod" suffix that marks the go.mod hash line
    if (version.endsWith("/go.mod")) version = version.slice(0, -"/go.mod".length);
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "Go", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const goParser: ManifestParser = {
  filenames: ["go.sum"],
  parse(content, manifestPath) {
    return parseGoSum(content, manifestPath);
  },
};
