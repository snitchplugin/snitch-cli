import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock child_process BEFORE importing remote so the module binds to our mock.
const execFileSyncMock = vi.fn();
vi.mock("node:child_process", async () => {
  const actual = await vi.importActual<typeof import("node:child_process")>(
    "node:child_process"
  );
  return { ...actual, execFileSync: (...a: unknown[]) => execFileSyncMock(...a) };
});

import {
  assertLocalPath,
  classifyRepo,
  cloneRemote,
  RemoteError,
} from "../src/remote.js";
import { mkdtempSync, rmSync, existsSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

beforeEach(() => {
  execFileSyncMock.mockReset();
});

describe("classifyRepo", () => {
  it("classifies https URLs", () => {
    const r = classifyRepo("https://github.com/x/y.git");
    expect(r).toEqual({ kind: "url", value: "https://github.com/x/y.git" });
  });

  it("classifies http URLs", () => {
    expect(classifyRepo("http://gitlab.example.com/x/y").kind).toBe("url");
  });

  it("classifies ssh:// URLs", () => {
    expect(classifyRepo("ssh://git@github.com/x/y").kind).toBe("url");
  });

  it("classifies git:// URLs", () => {
    expect(classifyRepo("git://github.com/x/y").kind).toBe("url");
  });

  it("classifies scp-like ssh as URL", () => {
    expect(classifyRepo("git@github.com:org/repo.git").kind).toBe("url");
  });

  it("rejects file:// URLs", () => {
    expect(() => classifyRepo("file:///etc/passwd")).toThrow(RemoteError);
  });

  it("treats absolute paths as path", () => {
    expect(classifyRepo("/Users/ian/work/repo")).toEqual({
      kind: "path",
      value: "/Users/ian/work/repo",
    });
  });

  it("treats relative paths as path", () => {
    expect(classifyRepo("./sibling")).toEqual({ kind: "path", value: "./sibling" });
    expect(classifyRepo("../sibling")).toEqual({ kind: "path", value: "../sibling" });
  });

  it("rejects empty strings", () => {
    expect(() => classifyRepo("")).toThrow(RemoteError);
    expect(() => classifyRepo("   ")).toThrow(RemoteError);
  });
});

describe("assertLocalPath", () => {
  it("returns absolute path for an existing dir", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "snitch-test-"));
    try {
      expect(assertLocalPath(tmp)).toBe(path.resolve(tmp));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("throws when the path does not exist", () => {
    expect(() => assertLocalPath("/definitely/does/not/exist/snitch-xyz")).toThrow(
      RemoteError
    );
  });
});

describe("cloneRemote", () => {
  it("invokes git clone with safe flags and returns a temp root", () => {
    execFileSyncMock.mockReturnValue("");
    const clone = cloneRemote("https://github.com/x/y.git");
    try {
      expect(execFileSyncMock).toHaveBeenCalledOnce();
      const [cmd, args] = execFileSyncMock.mock.calls[0] ?? [];
      expect(cmd).toBe("git");
      expect(args).toEqual(
        expect.arrayContaining([
          "clone",
          "--depth",
          "1",
          "--single-branch",
          "--no-tags",
          "--",
          "https://github.com/x/y.git",
        ])
      );
      // realpath on macOS resolves /var → /private/var; cloneRemote uses realpath internally.
      expect(clone.root.startsWith(realpathSync(os.tmpdir()))).toBe(true);
      expect(existsSync(clone.root)).toBe(true);
    } finally {
      clone.cleanup();
    }
  });

  it("cleanup removes the dir", () => {
    execFileSyncMock.mockReturnValue("");
    const clone = cloneRemote("https://github.com/x/y.git");
    expect(existsSync(clone.root)).toBe(true);
    clone.cleanup();
    expect(existsSync(clone.root)).toBe(false);
  });

  it("wraps git failures in RemoteError and cleans up", () => {
    execFileSyncMock.mockImplementation(() => {
      throw new Error("fatal: could not read");
    });
    expect(() => cloneRemote("https://github.com/x/y.git")).toThrow(RemoteError);
  });
});
