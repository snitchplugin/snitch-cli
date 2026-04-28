// Dead-file analyzer for JS/TS + Python.
// Build an import graph, BFS from entry points, anything unreached = dead.
//
// False positives we intentionally tolerate to keep this useful:
//   - frameworks that auto-discover files (Next.js pages, Django views)
//     get caught by the entry-point pattern list; if a project uses a
//     custom convention we don't recognize, we'll flag legit files.
//     The 50-finding cap protects against catastrophic false positives.
//   - dynamic imports (`import(varName)`) can't be resolved statically
//     and look like missing references — we drop the import silently.

import type { DcaFinding } from "./types.js";

const JS_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const PY_EXTS = [".py"];

function isJsLike(p: string): boolean {
  return JS_EXTS.some((e) => p.toLowerCase().endsWith(e));
}
function isPython(p: string): boolean {
  return PY_EXTS.some((e) => p.toLowerCase().endsWith(e));
}

function basename(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? p : p.slice(i + 1);
}
function dirname(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? "" : p.slice(0, i);
}

// ────────────────────────────────────────────────────────────
// Entry-point detection

const JS_ENTRY_BASENAMES = new Set([
  "index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs", "index.cjs",
  "main.ts", "main.tsx", "main.js", "main.jsx",
]);
const PY_ENTRY_BASENAMES = new Set([
  "__init__.py", "__main__.py", "main.py", "setup.py", "conftest.py",
]);

const TEST_PATTERNS = [
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /(?:^|\/)tests?\//i,
  /(?:^|\/)__tests__\//i,
  /(?:^|\/)test_[^/]+\.py$/i,
  /[^/]+_test\.py$/i,
];

// Next.js convention: `pages/`, `app/` directories with route files.
// Treat any TS/JS file under those as an entry point.
const FRAMEWORK_ENTRY_PATTERNS = [
  /(?:^|\/)pages\//i,
  /(?:^|\/)app\/.*(?:page|layout|route|loading|error|not-found)\.(?:t|j)sx?$/i,
  /(?:^|\/)src\/routes\//i,        // tanstack/remix
  /(?:^|\/)api\//i,                // next.js api routes / generic api dir
];

function isEntryPoint(path: string): boolean {
  const base = basename(path);
  if (isJsLike(path) && JS_ENTRY_BASENAMES.has(base.toLowerCase())) return true;
  if (isPython(path) && PY_ENTRY_BASENAMES.has(base.toLowerCase())) return true;
  for (const p of TEST_PATTERNS) if (p.test(path)) return true;
  for (const p of FRAMEWORK_ENTRY_PATTERNS) if (p.test(path)) return true;
  return false;
}

// Pull `main` / `bin` / `exports` paths from a package.json (if present)
// and add them to the entry set.
function extraNpmEntries(files: { path: string; content: string }[]): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    if (basename(f.path) !== "package.json") continue;
    try {
      const j = JSON.parse(f.content) as Record<string, unknown>;
      const dir = dirname(f.path);
      const collect = (v: unknown) => {
        if (typeof v === "string") {
          // Strip leading `./`
          const rel = v.replace(/^\.\//, "");
          out.add(dir ? `${dir}/${rel}` : rel);
        } else if (Array.isArray(v)) {
          for (const item of v) collect(item);
        } else if (v && typeof v === "object") {
          for (const inner of Object.values(v as Record<string, unknown>)) collect(inner);
        }
      };
      collect(j.main);
      collect(j.bin);
      collect(j.exports);
    } catch {
      // ignore malformed
    }
  }
  return out;
}

// ────────────────────────────────────────────────────────────
// Intra-repo import extraction (only relatives + project-rooted)

const JS_REL_IMPORT = /(?:^|[\s;])(?:import|export)\b[\s\S]*?from\s*['"](\.[^'"]+)['"]/g;
const JS_REL_BARE = /(?:^|[\s;])import\s*['"](\.[^'"]+)['"]/g;
const JS_REL_DYNAMIC = /\bimport\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g;
const JS_REL_REQUIRE = /\brequire\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g;

const PY_REL_FROM = /^\s*from\s+(\.+)([A-Za-z_][\w.]*)?\s+import/gm;
const PY_REL_FROM_NONE = /^\s*from\s+(\.+)\s+import/gm;

function extractIntraImports(file: { path: string; content: string }): string[] {
  const specs: string[] = [];
  if (isJsLike(file.path)) {
    for (const re of [JS_REL_IMPORT, JS_REL_BARE, JS_REL_DYNAMIC, JS_REL_REQUIRE]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(file.content)) !== null) {
        if (m[1]) specs.push(m[1]);
      }
    }
  } else if (isPython(file.path)) {
    PY_REL_FROM.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PY_REL_FROM.exec(file.content)) !== null) {
      const dots = m[1] ?? ".";
      const mod = m[2] ?? "";
      specs.push(dots + mod);
    }
    PY_REL_FROM_NONE.lastIndex = 0;
    while ((m = PY_REL_FROM_NONE.exec(file.content)) !== null) {
      specs.push(m[1] ?? ".");
    }
  }
  return specs;
}

// ────────────────────────────────────────────────────────────
// Resolver

function resolvePath(parts: string[]): string {
  // Normalize parts ending in `..` / `.`. Returns posix-style path.
  const stack: string[] = [];
  for (const seg of parts) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      stack.pop();
    } else {
      stack.push(seg);
    }
  }
  return stack.join("/");
}

function resolveJsImport(fromFile: string, spec: string, index: Set<string>): string | undefined {
  const fromDir = dirname(fromFile);
  // spec is relative ("./foo", "../bar"). Combine with fromDir.
  const combined = resolvePath((fromDir ? fromDir.split("/") : []).concat(spec.split("/")));
  const candidates: string[] = [];
  // Direct ext
  for (const ext of JS_EXTS) {
    candidates.push(combined + ext);
  }
  // Index inside dir
  for (const ext of JS_EXTS) {
    candidates.push(combined + "/index" + ext);
  }
  // Bare path (already had ext)
  candidates.push(combined);
  for (const c of candidates) {
    if (index.has(c)) return c;
  }
  return undefined;
}

function resolvePyImport(fromFile: string, spec: string, index: Set<string>): string | undefined {
  // spec like ".utils" or "..pkg.foo" or "."
  const dots = (spec.match(/^\.+/) ?? [""])[0]?.length ?? 1;
  const rest = spec.slice(dots);
  const fromDir = dirname(fromFile);
  const baseSegments = fromDir ? fromDir.split("/") : [];
  // Each leading dot beyond the first goes one level up.
  const upN = Math.max(0, dots - 1);
  const baseUp = baseSegments.slice(0, baseSegments.length - upN);
  const moduleSegs = rest ? rest.split(".") : [];
  const combined = resolvePath(baseUp.concat(moduleSegs));
  // Try `combined.py`, `combined/__init__.py`
  for (const candidate of [combined + ".py", combined + "/__init__.py"]) {
    if (index.has(candidate)) return candidate;
  }
  return undefined;
}

// ────────────────────────────────────────────────────────────
// Main analyzer

export function analyzeDeadFiles(input: {
  files: { path: string; content: string }[];
}): DcaFinding[] {
  const sourceFiles = input.files.filter((f) => isJsLike(f.path) || isPython(f.path));
  if (sourceFiles.length === 0) return [];

  const index = new Set<string>(sourceFiles.map((f) => f.path));

  // Build adjacency: file → resolved target paths it imports.
  const adjacency = new Map<string, Set<string>>();
  for (const file of sourceFiles) {
    const targets = new Set<string>();
    for (const spec of extractIntraImports(file)) {
      const resolved = isJsLike(file.path)
        ? resolveJsImport(file.path, spec, index)
        : resolvePyImport(file.path, spec, index);
      if (resolved) targets.add(resolved);
    }
    adjacency.set(file.path, targets);
  }

  // Entry points: convention basenames + framework patterns + npm `main`/`bin`/`exports`.
  const entries = new Set<string>();
  for (const f of sourceFiles) if (isEntryPoint(f.path)) entries.add(f.path);
  for (const e of extraNpmEntries(input.files)) {
    if (index.has(e)) entries.add(e);
  }

  // BFS from entries.
  const reachable = new Set<string>(entries);
  const queue: string[] = [...entries];
  while (queue.length) {
    const node = queue.shift()!;
    const next = adjacency.get(node);
    if (!next) continue;
    for (const t of next) {
      if (!reachable.has(t)) {
        reachable.add(t);
        queue.push(t);
      }
    }
  }

  const dead: string[] = [];
  for (const f of sourceFiles) {
    if (!reachable.has(f.path)) dead.push(f.path);
  }

  if (dead.length > 50) {
    return [
      {
        subkind: "dead-file",
        path: "(repository)",
        packageName: `${dead.length} files`,
      },
    ];
  }

  return dead.map((p) => ({ subkind: "dead-file" as const, path: p }));
}
