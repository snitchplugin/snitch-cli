// Handles npm package-lock.json (v1 "dependencies", v2/v3 "packages"),
// yarn.lock (parsed via @yarnpkg/parsers parseSyml — works for v1 + berry),
// and pnpm-lock.yaml (js-yaml; "packages" keyed by "/name@version" or "name@version").
import yaml from "js-yaml";
import { parseSyml } from "@yarnpkg/parsers";
import type { DepEntry, ManifestParser } from "../types.js";

interface PackageLockV1Dep {
  version?: string;
  dependencies?: Record<string, PackageLockV1Dep>;
}

interface PackageLockV2Pkg {
  version?: string;
  name?: string;
}

function parsePackageLock(content: string, manifestPath: string): DepEntry[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const root = json as {
    packages?: Record<string, PackageLockV2Pkg>;
    dependencies?: Record<string, PackageLockV1Dep>;
  };
  const out = new Map<string, DepEntry>();
  const add = (name: string, version: string) => {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "npm", name, version, manifestPath });
    }
  };

  if (root.packages && typeof root.packages === "object") {
    for (const [path, pkg] of Object.entries(root.packages)) {
      if (!pkg || typeof pkg !== "object") continue;
      // root entry has key "" — skip unless name is meaningful
      let name = pkg.name;
      if (!name && path.startsWith("node_modules/")) {
        // last node_modules/ segment is the package name
        const idx = path.lastIndexOf("node_modules/");
        name = path.slice(idx + "node_modules/".length);
      }
      if (!name) continue;
      if (typeof pkg.version === "string") add(name, pkg.version);
    }
  }

  if (root.dependencies && typeof root.dependencies === "object") {
    const walk = (deps: Record<string, PackageLockV1Dep>) => {
      for (const [name, dep] of Object.entries(deps)) {
        if (!dep || typeof dep !== "object") continue;
        if (typeof dep.version === "string") add(name, dep.version);
        if (dep.dependencies) walk(dep.dependencies);
      }
    };
    walk(root.dependencies);
  }

  return Array.from(out.values());
}

function parseYarnLock(content: string, manifestPath: string): DepEntry[] {
  let parsed: Record<string, { version?: string }>;
  try {
    parsed = parseSyml(content) as Record<string, { version?: string }>;
  } catch {
    return [];
  }
  const out = new Map<string, DepEntry>();
  for (const [key, value] of Object.entries(parsed)) {
    if (!value || typeof value !== "object") continue;
    if (key === "__metadata") continue;
    const version = (value as { version?: string }).version;
    if (typeof version !== "string" || !version) continue;
    // key format: "name@spec" or "name@spec, name@spec2" (comma-joined in v1)
    const first = key.split(",")[0]?.trim() ?? "";
    const at = first.lastIndexOf("@");
    if (at <= 0) continue;
    const name = first.slice(0, at);
    const dedupKey = `${name}@${version}`;
    if (!out.has(dedupKey)) {
      out.set(dedupKey, { ecosystem: "npm", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

function parsePnpmLock(content: string, manifestPath: string): DepEntry[] {
  let doc: unknown;
  try {
    doc = yaml.load(content);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];
  const packages = (doc as { packages?: Record<string, unknown> }).packages;
  if (!packages || typeof packages !== "object") return [];
  const out = new Map<string, DepEntry>();
  for (const rawKey of Object.keys(packages)) {
    // pnpm v5/v6: "/name/version" or "/name/version_peer"
    // pnpm v9:    "name@version" or "name@version(peer)"
    let key = rawKey;
    if (key.startsWith("/")) key = key.slice(1);
    // strip peer suffix in parens or _peer
    const parenIdx = key.indexOf("(");
    if (parenIdx !== -1) key = key.slice(0, parenIdx);
    const underIdx = key.indexOf("_");
    if (underIdx !== -1) key = key.slice(0, underIdx);

    let name = "";
    let version = "";
    if (key.includes("@") && !key.startsWith("/")) {
      // v9 format "name@version" — but scoped names are "@scope/name@version"
      const at = key.lastIndexOf("@");
      if (at > 0) {
        name = key.slice(0, at);
        version = key.slice(at + 1);
      }
    }
    if (!name && key.includes("/")) {
      // v5/v6 format "name/version" (after leading slash strip)
      const slash = key.lastIndexOf("/");
      name = key.slice(0, slash);
      version = key.slice(slash + 1);
    }
    if (!name || !version) continue;
    const dedupKey = `${name}@${version}`;
    if (!out.has(dedupKey)) {
      out.set(dedupKey, { ecosystem: "npm", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const npmParser: ManifestParser = {
  filenames: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
  parse(content, manifestPath) {
    const base = manifestPath.split("/").pop() ?? manifestPath;
    if (base === "package-lock.json") return parsePackageLock(content, manifestPath);
    if (base === "yarn.lock") return parseYarnLock(content, manifestPath);
    if (base === "pnpm-lock.yaml") return parsePnpmLock(content, manifestPath);
    return [];
  },
};
