// Unused-dependency analyzer.
// We re-extract DIRECT deps from higher-level manifests (package.json,
// pyproject.toml, etc.) instead of reusing SCA's lockfile-derived
// DepEntry[] — the lockfile includes transitive deps which the developer
// can't remove independently. The unused-dep finding only makes sense
// for what's directly declared.

import type { DcaFinding, DepEntry, Ecosystem } from "./types.js";
import { parse as parseToml } from "@iarna/toml";

const NPM_PACKAGE_JSON = "package.json";
const PYTHON_PYPROJECT = "pyproject.toml";
const PYTHON_REQUIREMENTS = "requirements.txt";
const RUST_CARGO = "Cargo.toml";
const COMPOSER_JSON = "composer.json";
const RUBY_GEMFILE = "Gemfile";
const GO_MOD = "go.mod";
const MAVEN_POM = "pom.xml";

function basename(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? p : p.slice(i + 1);
}

// ────────────────────────────────────────────────────────────
// Per-manifest direct-dep extractors

function fromPackageJson(content: string, path: string): DepEntry[] {
  try {
    const j = JSON.parse(content) as Record<string, unknown>;
    const out: DepEntry[] = [];
    for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
      const block = j[key] as Record<string, string> | undefined;
      if (!block) continue;
      for (const name of Object.keys(block)) {
        out.push({
          ecosystem: "npm",
          name,
          version: block[name] ?? "*",
          manifestPath: path,
          scope: "direct",
        });
      }
    }
    return out;
  } catch {
    return [];
  }
}

function fromRequirementsTxt(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("-")) continue; // -r, -c, -e
    if (/^https?:|^git\+|^file:/.test(line)) continue;
    // PEP 508 URL specifier: `name @ git+https://...` — name without a real
    // pinned version on PyPI; skip so we don't match against real imports.
    if (/\s@\s/.test(line)) continue;
    // Split on `==`, `>=`, `~=`, `<`, `>`, `;`, `[` (extras), etc.
    const m = line.match(/^([A-Za-z_][\w.\-]*)/);
    if (m && m[1]) {
      out.push({
        ecosystem: "PyPI",
        name: m[1],
        version: "*",
        manifestPath: path,
        scope: "direct",
      });
    }
  }
  return out;
}

function fromPyproject(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = parseToml(content) as Record<string, unknown>;
  } catch {
    return out;
  }
  // PEP 621: project.dependencies = ["requests>=2", ...]
  const project = parsed.project as Record<string, unknown> | undefined;
  if (project) {
    const deps = project.dependencies as string[] | undefined;
    if (Array.isArray(deps)) {
      for (const spec of deps) {
        const name = (spec.match(/^([A-Za-z_][\w.\-]*)/) ?? [])[1];
        if (name) out.push({ ecosystem: "PyPI", name, version: "*", manifestPath: path, scope: "direct" });
      }
    }
    const optDeps = project["optional-dependencies"] as Record<string, string[]> | undefined;
    if (optDeps) {
      for (const group of Object.values(optDeps)) {
        for (const spec of group) {
          const name = (spec.match(/^([A-Za-z_][\w.\-]*)/) ?? [])[1];
          if (name) out.push({ ecosystem: "PyPI", name, version: "*", manifestPath: path, scope: "direct" });
        }
      }
    }
  }
  // tool.poetry.dependencies = { requests = "^2.0", ... }
  const tool = parsed.tool as Record<string, unknown> | undefined;
  const poetry = tool?.poetry as Record<string, unknown> | undefined;
  for (const key of ["dependencies", "dev-dependencies"]) {
    const block = poetry?.[key] as Record<string, unknown> | undefined;
    if (!block) continue;
    for (const name of Object.keys(block)) {
      if (name === "python") continue;
      out.push({ ecosystem: "PyPI", name, version: "*", manifestPath: path, scope: "direct" });
    }
  }
  return out;
}

function fromCargoToml(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = parseToml(content) as Record<string, unknown>;
  } catch {
    return out;
  }
  for (const key of ["dependencies", "dev-dependencies", "build-dependencies"]) {
    const block = parsed[key] as Record<string, unknown> | undefined;
    if (!block) continue;
    for (const name of Object.keys(block)) {
      out.push({ ecosystem: "crates.io", name, version: "*", manifestPath: path, scope: "direct" });
    }
  }
  return out;
}

function fromComposerJson(content: string, path: string): DepEntry[] {
  try {
    const j = JSON.parse(content) as Record<string, unknown>;
    const out: DepEntry[] = [];
    for (const key of ["require", "require-dev"]) {
      const block = j[key] as Record<string, string> | undefined;
      if (!block) continue;
      for (const name of Object.keys(block)) {
        if (name.startsWith("php") || name.startsWith("ext-")) continue; // PHP version pin / extensions
        out.push({ ecosystem: "Packagist", name, version: block[name] ?? "*", manifestPath: path, scope: "direct" });
      }
    }
    return out;
  } catch {
    return [];
  }
}

function fromGemfile(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  const re = /^\s*gem\s+['"]([^'"]+)['"]/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[1]) out.push({ ecosystem: "RubyGems", name: m[1], version: "*", manifestPath: path, scope: "direct" });
  }
  return out;
}

function fromGoMod(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  // Skip indirect lines. Match `module/path v1.2.3` inside `require (...)` block AND single `require module v1.2.3`.
  const lines = content.split(/\r?\n/);
  let inBlock = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("require (")) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    if (line.includes("// indirect")) continue;
    let m = line.match(/^require\s+(\S+)\s+\S+/);
    if (!m && inBlock) m = line.match(/^(\S+)\s+\S+/);
    if (m && m[1] && m[1] !== "(") {
      out.push({ ecosystem: "Go", name: m[1], version: "*", manifestPath: path, scope: "direct" });
    }
  }
  return out;
}

function fromPomXml(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  // Cheap regex pass — accurate enough for direct deps. Skips test/provided
  // scope filtering on purpose; analyzer just needs the name set.
  const depRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = depRe.exec(content)) !== null) {
    const body = m[1] ?? "";
    const g = body.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const a = body.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    if (g && a) out.push({ ecosystem: "Maven", name: `${g}:${a}`, version: "*", manifestPath: path, scope: "direct" });
  }
  return out;
}

function fromCsproj(content: string, path: string): DepEntry[] {
  const out: DepEntry[] = [];
  const re = /<PackageReference\s+Include\s*=\s*"([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[1]) out.push({ ecosystem: "NuGet", name: m[1], version: "*", manifestPath: path, scope: "direct" });
  }
  return out;
}

const CSPROJ_RE = /\.csproj$/i;

export function extractDirectDeps(files: { path: string; content: string }[]): DepEntry[] {
  const out: DepEntry[] = [];
  for (const f of files) {
    const base = basename(f.path);
    if (base === NPM_PACKAGE_JSON) out.push(...fromPackageJson(f.content, f.path));
    else if (base === PYTHON_REQUIREMENTS) out.push(...fromRequirementsTxt(f.content, f.path));
    else if (base === PYTHON_PYPROJECT) out.push(...fromPyproject(f.content, f.path));
    else if (base === RUST_CARGO) out.push(...fromCargoToml(f.content, f.path));
    else if (base === COMPOSER_JSON) out.push(...fromComposerJson(f.content, f.path));
    else if (base === RUBY_GEMFILE) out.push(...fromGemfile(f.content, f.path));
    else if (base === GO_MOD) out.push(...fromGoMod(f.content, f.path));
    else if (base === MAVEN_POM) out.push(...fromPomXml(f.content, f.path));
    else if (CSPROJ_RE.test(base)) out.push(...fromCsproj(f.content, f.path));
  }
  return out;
}

// ────────────────────────────────────────────────────────────
// Per-ecosystem normalization + matching

function normalize(ecosystem: Ecosystem, name: string): string {
  switch (ecosystem) {
    case "npm":
    case "Packagist":
    case "RubyGems":
    case "Go":
      return name.toLowerCase();
    case "PyPI":
      return name.toLowerCase().replace(/_/g, "-");
    case "crates.io":
      return name.toLowerCase().replace(/_/g, "-");
    case "Maven":
      return name.toLowerCase(); // groupId:artifactId
    case "NuGet":
      return name.toLowerCase();
  }
}

function matches(
  ecosystem: Ecosystem,
  depName: string,
  imports: Set<string>,
  importsLower: Set<string>,
): boolean {
  if (importsLower.has(normalize(ecosystem, depName))) return true;

  // Loose matchers per ecosystem.
  if (ecosystem === "npm" && depName.startsWith("@")) {
    if (importsLower.has(depName.toLowerCase())) return true;
  }
  if (ecosystem === "PyPI") {
    // requirements.txt names use `_` and `-` interchangeably; importer
    // sees the underscore form.
    if (importsLower.has(depName.toLowerCase().replace(/-/g, "_"))) return true;
  }
  if (ecosystem === "crates.io") {
    if (importsLower.has(depName.toLowerCase().replace(/-/g, "_"))) return true;
  }
  if (ecosystem === "Maven") {
    // Loose: groupId.artifactId namespace appears as a prefix of any
    // import OR the artifactId substring appears in any import path.
    const [g, a] = depName.split(":");
    const groupDot = (g ?? "").toLowerCase();
    const artId = (a ?? "").toLowerCase();
    for (const imp of imports) {
      const lower = imp.toLowerCase();
      if (groupDot && lower.startsWith(groupDot)) return true;
      if (artId && lower.includes(artId)) return true;
    }
  }
  if (ecosystem === "Packagist") {
    // composer "vendor/pkg" — match the vendor part against the use stmts.
    const [vendor] = depName.toLowerCase().split("/");
    if (vendor && importsLower.has(vendor)) return true;
  }
  if (ecosystem === "Go") {
    // Go imports include the full path; the "name" in go.mod IS that path.
    // Already exact-match-tested above. No further loose match to add.
  }
  if (ecosystem === "NuGet") {
    // NuGet pkg name often equals the namespace. We compared lowercase
    // already; nothing more to do.
  }
  if (ecosystem === "RubyGems") {
    // Some gems require under a different name (e.g. `nokogiri` is fine).
    // Keep exact-match for v1; can extend when we hit notable exceptions.
  }
  return false;
}

// ────────────────────────────────────────────────────────────
// Main analyzer

export function analyzeUnusedDeps(input: {
  deps: DepEntry[];
  importsByEcosystem: Map<Ecosystem, Set<string>>;
}): DcaFinding[] {
  const out: DcaFinding[] = [];
  for (const dep of input.deps) {
    if (dep.scope && dep.scope !== "direct") continue;
    const imports = input.importsByEcosystem.get(dep.ecosystem) ?? new Set<string>();
    const importsLower = new Set<string>();
    for (const i of imports) importsLower.add(i.toLowerCase());
    if (!matches(dep.ecosystem, dep.name, imports, importsLower)) {
      out.push({
        subkind: "unused-dep",
        path: dep.manifestPath,
        ecosystem: dep.ecosystem,
        packageName: dep.name,
      });
    }
  }
  return out;
}
