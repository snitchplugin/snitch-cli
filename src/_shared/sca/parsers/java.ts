// Handles Maven pom.xml (parsed via fast-xml-parser; collect <dependency> entries
// with groupId:artifactId as the name) and gradle.lockfile (text format —
// each non-comment line is "group:name:version=conf1,conf2").
import { XMLParser } from "fast-xml-parser";
import type { DepEntry, ManifestParser } from "../types.js";

const xml = new XMLParser({ ignoreAttributes: false, parseTagValue: false });

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function collectDeps(node: unknown, sink: Array<{ groupId?: string; artifactId?: string; version?: string }>): void {
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  for (const [key, value] of Object.entries(obj)) {
    if (key === "dependency") {
      for (const d of asArray(value as Record<string, unknown> | Record<string, unknown>[])) {
        if (d && typeof d === "object") {
          sink.push({
            groupId: typeof d.groupId === "string" ? d.groupId : undefined,
            artifactId: typeof d.artifactId === "string" ? d.artifactId : undefined,
            version: typeof d.version === "string" ? d.version : undefined,
          });
        }
      }
    } else if (value && typeof value === "object") {
      if (Array.isArray(value)) {
        for (const item of value) collectDeps(item, sink);
      } else {
        collectDeps(value, sink);
      }
    }
  }
}

function parsePomXml(content: string, manifestPath: string): DepEntry[] {
  let doc: unknown;
  try {
    doc = xml.parse(content);
  } catch {
    return [];
  }
  const deps: Array<{ groupId?: string; artifactId?: string; version?: string }> = [];
  collectDeps(doc, deps);
  const out = new Map<string, DepEntry>();
  for (const d of deps) {
    if (!d.groupId || !d.artifactId || !d.version) continue;
    const name = `${d.groupId}:${d.artifactId}`;
    const version = d.version;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "Maven", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

function parseGradleLockfile(content: string, manifestPath: string): DepEntry[] {
  const out = new Map<string, DepEntry>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    // Format: group:name:version=conf1,conf2
    const eq = line.indexOf("=");
    const coord = eq === -1 ? line : line.slice(0, eq);
    const parts = coord.split(":");
    if (parts.length < 3) continue;
    const group = parts[0]!;
    const artifact = parts[1]!;
    const version = parts.slice(2).join(":");
    if (!group || !artifact || !version) continue;
    const name = `${group}:${artifact}`;
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, { ecosystem: "Maven", name, version, manifestPath });
    }
  }
  return Array.from(out.values());
}

export const javaParser: ManifestParser = {
  filenames: ["pom.xml", "gradle.lockfile"],
  parse(content, manifestPath) {
    const base = manifestPath.split("/").pop() ?? manifestPath;
    if (base === "pom.xml") return parsePomXml(content, manifestPath);
    if (base === "gradle.lockfile") return parseGradleLockfile(content, manifestPath);
    return [];
  },
};
