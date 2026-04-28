import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";

const SCANNABLE_EXT =
  /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|rb|php|cs|swift|scala|sql|tf|hcl|yml|yaml|sh|ps1|csproj)$/i;

// Manifest files needed by the SCA pass. Picked up alongside SCANNABLE_EXT
// matches; the SCA module filters down to just these, the AI scan filters
// them back out.
const SCA_MANIFEST_FILENAMES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
  "Cargo.lock", "go.sum", "go.mod", "Gemfile.lock",
  "composer.lock", "packages.lock.json", "gradle.lockfile", "pom.xml",
  // Higher-level manifests for DCA's unused-dep analysis (only directs).
  "package.json", "pyproject.toml", "Cargo.toml", "composer.json", "Gemfile",
]);

const DOCKERFILE_VARIANT_RE = /^Dockerfile(\.[\w.-]+)?$|\.dockerfile$/i;

function isScannablePath(p: string): boolean {
  if (SCANNABLE_EXT.test(p)) return true;
  const base = p.includes("/") ? p.slice(p.lastIndexOf("/") + 1) : p;
  if (SCA_MANIFEST_FILENAMES.has(base)) return true;
  if (DOCKERFILE_VARIANT_RE.test(base)) return true;
  return false;
}

const MAX_BYTES = 200_000;

export interface LocalFile {
  path: string;
  content: string;
  patch: string; // unified-diff patch for the prompt, or "" for full-tree mode
}

function runGit(args: string[], cwd: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function repoRoot(cwd: string = process.cwd()): string {
  try {
    // git rev-parse --show-toplevel returns forward slashes on Windows
    // (e.g. "C:/Users/name/repo"), while path.resolve on Windows returns
    // backslashes. Normalize here so downstream code can compare paths
    // with a single separator convention (the OS native one).
    return path.resolve(runGit(["rev-parse", "--show-toplevel"], cwd));
  } catch {
    throw new Error(
      "Not inside a git repository. Run `snitch scan` from a git checkout, or pass --files to scan specific files."
    );
  }
}

/**
 * Resolve the base ref to diff against. Preference order:
 *   1. --base flag if provided
 *   2. origin/main if it exists
 *   3. origin/master if it exists
 *   4. main, master as local fallbacks
 * Throws a clear error if nothing works.
 */
export function resolveBaseRef(explicit: string | undefined, root: string): string {
  if (explicit) {
    try {
      runGit(["rev-parse", "--verify", explicit], root);
      return explicit;
    } catch {
      throw new Error(
        `--base ref "${explicit}" does not exist. Run \`git fetch\` and try again, or pass a valid ref.`
      );
    }
  }

  const candidates = ["origin/main", "origin/master", "main", "master"];
  for (const ref of candidates) {
    try {
      runGit(["rev-parse", "--verify", ref], root);
      return ref;
    } catch {
      // Try next
    }
  }

  throw new Error(
    "Could not resolve a base ref (tried origin/main, origin/master, main, master). Pass --base explicitly."
  );
}

/**
 * Return the list of files changed between `base` and HEAD, filtered by
 * scannable extensions and diff-filter AMR (added/modified/renamed).
 */
export function listChangedPaths(base: string, root: string): string[] {
  const raw = runGit(
    ["diff", "--name-only", "--diff-filter=AMR", `${base}...HEAD`],
    root
  );
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && isScannablePath(s));
}

/**
 * Return scannable paths for a full-tree scan. Uses `git ls-files` so ignored
 * files (node_modules, build artifacts) are excluded.
 */
export function listAllTrackedPaths(root: string): string[] {
  const raw = runGit(["ls-files"], root);
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && isScannablePath(s));
}

/**
 * Load the working-tree content + per-file patch for scanning. Files larger
 * than MAX_BYTES are truncated (not skipped) so at least the head is audited.
 */
export function loadFiles(paths: string[], base: string | null, root: string): LocalFile[] {
  const files: LocalFile[] = [];
  for (const rel of paths) {
    const abs = path.resolve(root, rel);
    // Containment check that is cross-platform safe. path.relative returns
    // "" when abs === root, a ".." prefix when abs is outside root, and an
    // absolute path on Windows if abs is on a different drive. Previous
    // implementation used `abs.startsWith(root + path.sep)`, which silently
    // dropped every file on Windows because git returns forward slashes
    // and path.resolve returns backslashes.
    const relFromRoot = path.relative(root, abs);
    if (
      relFromRoot !== "" &&
      (relFromRoot.startsWith("..") || path.isAbsolute(relFromRoot))
    ) {
      continue;
    }
    if (!existsSync(abs)) continue;
    try {
      const s = statSync(abs);
      if (!s.isFile()) continue;
    } catch {
      continue;
    }

    let content: string;
    try {
      const buf = readFileSync(abs);
      if (buf.length > MAX_BYTES) {
        content = buf.subarray(0, MAX_BYTES).toString("utf-8") + "\n/* ... truncated ... */";
      } else {
        content = buf.toString("utf-8");
      }
    } catch {
      continue;
    }

    let patch = "";
    if (base) {
      try {
        patch = runGit(
          ["diff", "--no-color", "--unified=3", `${base}...HEAD`, "--", rel],
          root
        );
      } catch {
        patch = "";
      }
    }

    files.push({ path: rel, content, patch });
  }
  return files;
}

/**
 * Get the HEAD short SHA, or "uncommitted" if the working tree has no commits.
 */
export function headSha(root: string): string {
  try {
    return runGit(["rev-parse", "--short=12", "HEAD"], root);
  } catch {
    return "uncommitted";
  }
}

/**
 * Best-effort repo identity. Used as scan metadata so /dashboard/github can
 * group local scans by repo. Falls back to directory name if no remote.
 */
export function repoIdentity(root: string): { owner: string; name: string } {
  let remote = "";
  try {
    remote = runGit(["config", "--get", "remote.origin.url"], root);
  } catch {
    remote = "";
  }

  // Parse github.com/org/repo(.git) or git@github.com:org/repo(.git)
  const m = remote.match(/[:/]([^/:]+)\/([^/]+?)(\.git)?$/);
  if (m && m[1] && m[2]) {
    return { owner: m[1], name: m[2] };
  }

  return { owner: "local", name: path.basename(root) };
}
