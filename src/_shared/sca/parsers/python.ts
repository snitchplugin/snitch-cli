// Handles requirements.txt (PEP 508 lines, skip comments, -r/-c includes, VCS),
// poetry.lock + uv.lock (TOML with [[package]] arrays),
// Pipfile.lock (JSON; "default" + "develop" objects, each "package": {version: "==X"}).
import TOML from "@iarna/toml";
import type { DepEntry, ManifestParser } from "../types.js";

function parseRequirementsTxt(content: string, manifestPath: string): DepEntry[] {
  const out: DepEntry[] = [];
  const seen = new Set<string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line) continue;
    if (line.startsWith("#")) continue;
    if (line.startsWith("-")) continue; // -r, -c, -e, --hash etc.
    if (line.includes("://")) continue; // VCS / URL installs
    // strip env markers: "pkg==1.0; python_version<'3.10'"
    const noMarker = line.split(";")[0]?.trim() ?? "";
    if (!noMarker) continue;
    // strip extras: "pkg[extra1,extra2]==1.0"
    const noExtras = noMarker.replace(/\[[^\]]*\]/, "");
    // we only count pinned == specs (other operators = unresolved range)
    const match = noExtras.match(/^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)/);
    if (!match) continue;
    const name = match[1]!;
    const version = match[2]!;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: "PyPI", name, version, manifestPath });
  }
  return out;
}

function parsePoetryOrUvLock(content: string, manifestPath: string): DepEntry[] {
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
      out.set(key, { ecosystem: "PyPI", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

function parsePipfileLock(content: string, manifestPath: string): DepEntry[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const out = new Map<string, DepEntry>();
  for (const section of ["default", "develop"] as const) {
    const group = (json as Record<string, unknown>)[section];
    if (!group || typeof group !== "object") continue;
    for (const [name, info] of Object.entries(group as Record<string, { version?: string }>)) {
      if (!info || typeof info !== "object") continue;
      let version = typeof info.version === "string" ? info.version : "";
      if (version.startsWith("==")) version = version.slice(2);
      if (!name || !version) continue;
      const key = `${name}@${version}`;
      if (!out.has(key)) {
        out.set(key, { ecosystem: "PyPI", name, version, manifestPath });
      }
    }
  }
  return Array.from(out.values());
}

export const pythonParser: ManifestParser = {
  filenames: ["requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock"],
  parse(content, manifestPath) {
    const base = manifestPath.split("/").pop() ?? manifestPath;
    if (base === "requirements.txt") return parseRequirementsTxt(content, manifestPath);
    if (base === "poetry.lock" || base === "uv.lock") {
      return parsePoetryOrUvLock(content, manifestPath);
    }
    if (base === "Pipfile.lock") return parsePipfileLock(content, manifestPath);
    return [];
  },
};
