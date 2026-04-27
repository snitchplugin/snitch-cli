// Handles composer.lock: JSON with "packages" (runtime) and "packages-dev" arrays.
// Each entry has "name" (vendor/package) and "version" (e.g. "v1.2.3" or "1.2.3").
import type { DepEntry, ManifestParser } from "../types.js";

function parseComposerLock(content: string, manifestPath: string): DepEntry[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const out = new Map<string, DepEntry>();
  for (const section of ["packages", "packages-dev"] as const) {
    const arr = (json as Record<string, unknown>)[section];
    if (!Array.isArray(arr)) continue;
    for (const pkg of arr) {
      if (!pkg || typeof pkg !== "object") continue;
      const p = pkg as { name?: string; version?: string };
      if (typeof p.name !== "string" || typeof p.version !== "string") continue;
      const key = `${p.name}@${p.version}`;
      if (!out.has(key)) {
        out.set(key, {
          ecosystem: "Packagist",
          name: p.name,
          version: p.version,
          manifestPath,
        });
      }
    }
  }
  return Array.from(out.values());
}

export const phpParser: ManifestParser = {
  filenames: ["composer.lock"],
  parse(content, manifestPath) {
    return parseComposerLock(content, manifestPath);
  },
};
