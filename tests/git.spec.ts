import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  headSha,
  listAllTrackedPaths,
  listChangedPaths,
  loadFiles,
  repoIdentity,
  repoRoot,
  resolveBaseRef,
} from "../src/git.js";

function git(cwd: string, args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

describe("git helpers (fixture repo)", () => {
  let tmp: string;

  beforeEach(() => {
    // realpath so macOS /var → /private/var symlink resolves before we
    // compare with git's rev-parse --show-toplevel output.
    tmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), "snitch-cli-git-")));
    git(tmp, ["init", "-b", "main", "--quiet"]);
    git(tmp, ["config", "user.name", "Test"]);
    git(tmp, ["config", "user.email", "t@t.test"]);

    // Initial commit on main with two scannable files + one ignored.
    mkdirSync(path.join(tmp, "src"));
    writeFileSync(path.join(tmp, "src/a.ts"), "export const a = 1;\n");
    writeFileSync(path.join(tmp, "src/b.ts"), "export const b = 2;\n");
    writeFileSync(path.join(tmp, "README.md"), "# hi\n");
    git(tmp, ["add", "."]);
    git(tmp, ["commit", "-m", "init", "--quiet"]);

    // Branch off, modify one file + add a new one.
    git(tmp, ["checkout", "-b", "feature", "--quiet"]);
    writeFileSync(path.join(tmp, "src/a.ts"), "export const a = 99;\n");
    writeFileSync(path.join(tmp, "src/c.ts"), "export const c = 3;\n");
    git(tmp, ["add", "."]);
    git(tmp, ["commit", "-m", "change", "--quiet"]);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("repoRoot returns the git toplevel", () => {
    expect(repoRoot(tmp)).toBe(tmp);
  });

  it("resolveBaseRef picks main when origin/* is absent", () => {
    expect(resolveBaseRef(undefined, tmp)).toBe("main");
  });

  it("resolveBaseRef honors explicit ref when it exists", () => {
    expect(resolveBaseRef("main", tmp)).toBe("main");
  });

  it("resolveBaseRef throws on a missing explicit ref", () => {
    expect(() => resolveBaseRef("does-not-exist", tmp)).toThrow();
  });

  it("listChangedPaths returns scannable diff targets only", () => {
    const out = listChangedPaths("main", tmp);
    // src/a.ts modified, src/c.ts added. README.md filtered by ext.
    expect(out.sort()).toEqual(["src/a.ts", "src/c.ts"].sort());
  });

  it("listAllTrackedPaths returns scannable tracked files only", () => {
    const out = listAllTrackedPaths(tmp);
    expect(out.sort()).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"].sort());
    expect(out).not.toContain("README.md");
  });

  it("loadFiles reads content and attaches patch when base is set", () => {
    const files = loadFiles(["src/a.ts", "src/c.ts"], "main", tmp);
    expect(files).toHaveLength(2);
    const a = files.find((f) => f.path === "src/a.ts")!;
    expect(a.content).toContain("const a = 99");
    expect(a.patch).toContain("-export const a = 1;");
    expect(a.patch).toContain("+export const a = 99;");
  });

  it("loadFiles skips missing paths", () => {
    const files = loadFiles(["src/a.ts", "nope.ts"], "main", tmp);
    expect(files.map((f) => f.path)).toEqual(["src/a.ts"]);
  });

  it("headSha returns a short sha", () => {
    const sha = headSha(tmp);
    expect(sha).toMatch(/^[0-9a-f]{12}$/);
  });

  it("repoIdentity falls back to directory when no remote is set", () => {
    const id = repoIdentity(tmp);
    expect(id.owner).toBe("local");
    expect(id.name).toBe(path.basename(tmp));
  });

  it("repoIdentity parses https github remote", () => {
    git(tmp, ["remote", "add", "origin", "https://github.com/acme/widgets.git"]);
    const id = repoIdentity(tmp);
    expect(id).toEqual({ owner: "acme", name: "widgets" });
  });

  it("repoIdentity parses ssh github remote", () => {
    git(tmp, ["remote", "add", "origin", "git@github.com:acme/widgets.git"]);
    const id = repoIdentity(tmp);
    expect(id).toEqual({ owner: "acme", name: "widgets" });
  });
});
