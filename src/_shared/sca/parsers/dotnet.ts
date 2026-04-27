// Handles packages.lock.json (NuGet central package mgmt; "dependencies" keyed by
// target framework, each pkg has "resolved" version) and *.csproj
// (<PackageReference Include="X" Version="Y" />). Conditional file match for csproj
// is handled in discover.ts via regex.
import { XMLParser } from "fast-xml-parser";
import type { DepEntry, ManifestParser } from "../types.js";

const xml = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_", parseTagValue: false });

function parsePackagesLockJson(content: string, manifestPath: string): DepEntry[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const deps = (json as { dependencies?: Record<string, Record<string, { resolved?: string; type?: string }>> }).dependencies;
  if (!deps || typeof deps !== "object") return [];
  const out = new Map<string, DepEntry>();
  for (const tfm of Object.values(deps)) {
    if (!tfm || typeof tfm !== "object") continue;
    for (const [name, info] of Object.entries(tfm)) {
      if (!info || typeof info !== "object") continue;
      const version = typeof info.resolved === "string" ? info.resolved : "";
      if (!name || !version) continue;
      const key = `${name}@${version}`;
      if (!out.has(key)) {
        out.set(key, { ecosystem: "NuGet", name, version, manifestPath });
      }
    }
  }
  return Array.from(out.values());
}

interface PackageRef {
  "@_Include"?: string;
  "@_Version"?: string;
}

function collectPackageRefs(node: unknown, sink: PackageRef[]): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  for (const [key, value] of Object.entries(obj)) {
    if (key === "PackageReference") {
      const arr = Array.isArray(value) ? value : [value];
      for (const item of arr) {
        if (item && typeof item === "object") sink.push(item as PackageRef);
      }
    } else if (value && typeof value === "object") {
      if (Array.isArray(value)) {
        for (const item of value) collectPackageRefs(item, sink);
      } else {
        collectPackageRefs(value, sink);
      }
    }
  }
}

function parseCsproj(content: string, manifestPath: string): DepEntry[] {
  let doc: unknown;
  try {
    doc = xml.parse(content);
  } catch {
    return [];
  }
  const refs: PackageRef[] = [];
  collectPackageRefs(doc, refs);
  const out = new Map<string, DepEntry>();
  for (const ref of refs) {
    const name = ref["@_Include"];
    const version = ref["@_Version"];
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "NuGet", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const dotnetParser: ManifestParser = {
  filenames: ["packages.lock.json"],
  parse(content, manifestPath) {
    const base = manifestPath.split("/").pop() ?? manifestPath;
    if (base === "packages.lock.json") return parsePackagesLockJson(content, manifestPath);
    if (base.endsWith(".csproj")) return parseCsproj(content, manifestPath);
    return [];
  },
};
