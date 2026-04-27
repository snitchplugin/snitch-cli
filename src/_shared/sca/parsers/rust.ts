// Handles Cargo.lock: TOML with a top-level [[package]] array. Each entry has
// name, version, and optional source. We include all packages (workspace + transitive).
import TOML from "@iarna/toml";
import type { DepEntry, ManifestParser } from "../types.js";

function parseCargoLock(content: string, manifestPath: string): DepEntry[] {
  let doc: { package?: Array<{ name?: string; version?: string }> };
  try {
    doc = TOML.parse(content) as typeof doc;
  } catch {
    return [];
  }
  const pkgs = Array.isArray(doc.package) ? doc.package : [];
  const out = new Map<string, DepEntry>();
  for (const pkg of pkgs) {
    if (!pkg || typeof pkg !== "object") continue;
    const name = typeof pkg.name === "string" ? pkg.name : "";
    const version = typeof pkg.version === "string" ? pkg.version : "";
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "crates.io", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const rustParser: ManifestParser = {
  filenames: ["Cargo.lock"],
  parse(content, manifestPath) {
    return parseCargoLock(content, manifestPath);
  },
};
