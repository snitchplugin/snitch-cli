import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export class RemoteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RemoteError";
  }
}

export interface RemoteClone {
  root: string;
  cleanup: () => void;
  url: string;
}

/**
 * Decide whether a --repo value is a URL to clone or a local path to scan.
 *
 * Rules:
 *   - http:// https:// ssh:// git:// → URL
 *   - "user@host:org/repo" (scp-like)  → URL
 *   - Anything else that exists on disk → local path
 *   - file:// is explicitly rejected (footgun for the adversarial-input flow)
 */
export type RepoKind = { kind: "url"; value: string } | { kind: "path"; value: string };

export function classifyRepo(raw: string): RepoKind {
  const v = raw.trim();
  if (v.length === 0) throw new RemoteError("--repo value is empty.");

  if (v.startsWith("file:")) {
    throw new RemoteError("file:// URLs are not supported for --repo.");
  }

  if (
    v.startsWith("http://") ||
    v.startsWith("https://") ||
    v.startsWith("ssh://") ||
    v.startsWith("git://")
  ) {
    return { kind: "url", value: v };
  }

  // scp-like ssh form: user@host:path
  if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[^\s]+$/.test(v)) {
    return { kind: "url", value: v };
  }

  // Otherwise it must be a local path that exists.
  return { kind: "path", value: v };
}

const cleanupTargets = new Set<string>();
let cleanupInstalled = false;

function installGlobalCleanup(): void {
  if (cleanupInstalled) return;
  cleanupInstalled = true;
  const cleanAll = () => {
    for (const dir of cleanupTargets) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Best effort; process is exiting anyway.
      }
    }
    cleanupTargets.clear();
  };
  process.on("exit", cleanAll);
  process.on("SIGINT", () => {
    cleanAll();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    cleanAll();
    process.exit(143);
  });
}

/**
 * Shallow-clone a remote URL into an OS-temp directory.
 *
 * The caller receives a RemoteClone with an explicit cleanup() to delete the
 * clone dir. On process exit (for any reason), we also try to clean up every
 * dir we ever handed out, so a crashing CLI doesn't leave artifacts behind.
 *
 * The caller can opt out of cleanup (pass keepDir=true) when the gate blocks
 * and we want to leave the evidence in place for manual inspection.
 */
export function cloneRemote(url: string, opts: { keepDir?: boolean } = {}): RemoteClone {
  const tmpRoot = realpathSync(os.tmpdir());
  const dir = mkdtempSync(path.join(tmpRoot, "snitch-repo-"));

  if (!dir.startsWith(tmpRoot + path.sep)) {
    // Belt-and-suspenders: mkdtemp should never produce something outside
    // tmpdir, but if a racy symlink tricked us, bail out hard.
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    throw new RemoteError(
      "Refused to clone: resolved temp dir is outside os.tmpdir()."
    );
  }

  installGlobalCleanup();
  if (!opts.keepDir) cleanupTargets.add(dir);

  try {
    execFileSync(
      "git",
      [
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--",
        url,
        dir,
      ],
      { stdio: ["ignore", "pipe", "pipe"], encoding: "utf-8" }
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    cleanupTargets.delete(dir);
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    throw new RemoteError(`git clone failed for ${url}: ${msg}`);
  }

  const cleanup = (): void => {
    cleanupTargets.delete(dir);
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };

  return { root: dir, cleanup, url };
}

/**
 * Mark a previously-returned clone as "keep" (do not auto-clean on exit).
 * Used by the gate when it blocks and wants to leave evidence behind.
 */
export function keepClone(clone: RemoteClone): void {
  cleanupTargets.delete(clone.root);
}

/**
 * Check that a --repo local path actually exists and is readable. Does not
 * verify it is a git repo; the scan code will discover that itself.
 */
export function assertLocalPath(p: string): string {
  if (!existsSync(p)) {
    throw new RemoteError(`--repo path does not exist: ${p}`);
  }
  return path.resolve(p);
}
