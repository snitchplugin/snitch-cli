import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock child_process BEFORE importing the provider so the module binds to our spawn.
const spawnMock = vi.fn();
vi.mock("node:child_process", async () => {
  const actual = await vi.importActual<typeof import("node:child_process")>(
    "node:child_process"
  );
  return { ...actual, spawn: (...a: unknown[]) => spawnMock(...a) };
});

import { analyzeLocalCli, LocalCliError, runSubprocess } from "../src/providers/local-cli.js";

class FakeProcess extends EventEmitter {
  stdin = new PassThrough();
  stdout = new PassThrough();
  stderr = new PassThrough();
  killed = false;
  kill(): void {
    this.killed = true;
  }
}

function buildArgs() {
  return {
    apiKey: "",
    model: "claude",
    methodology: "METHOD",
    files: [{ path: "src/a.ts", content: "const x = 1;", patch: "+const x = 1;" }],
  };
}

beforeEach(() => {
  spawnMock.mockReset();
  delete process.env.LOCAL_AI_CMD;
  delete process.env.LOCAL_AI_ARGS;
});

afterEach(() => {
  spawnMock.mockReset();
});

describe("runSubprocess", () => {
  it("resolves with stdout on exit 0", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = runSubprocess("echo", [], "input");
    fake.stdout.write("hello world");
    fake.stdout.end();
    fake.emit("close", 0);

    await expect(promise).resolves.toBe("hello world");
    expect(spawnMock).toHaveBeenCalledWith(
      "echo",
      [],
      expect.objectContaining({ stdio: ["pipe", "pipe", "pipe"] })
    );
  });

  it("rejects with LocalCliError on non-zero exit", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = runSubprocess("claude", ["-p"], "prompt");
    fake.stderr.write("boom");
    fake.stderr.end();
    fake.emit("close", 2);

    await expect(promise).rejects.toBeInstanceOf(LocalCliError);
    await expect(promise).rejects.toThrow(/exited with code 2/);
    await expect(promise).rejects.toThrow(/boom/);
  });

  it("rejects with a clear error when the binary is missing", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = runSubprocess("not-a-real-binary", [], "prompt");
    const err = Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" });
    fake.emit("error", err);

    await expect(promise).rejects.toBeInstanceOf(LocalCliError);
    await expect(promise).rejects.toThrow(/not found on PATH/);
  });

  it("kills the process and rejects on timeout", async () => {
    vi.useFakeTimers();
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = runSubprocess("claude", ["-p"], "prompt", 50);
    vi.advanceTimersByTime(60);

    await expect(promise).rejects.toThrow(/timed out after/);
    expect(fake.killed).toBe(true);
    vi.useRealTimers();
  });
});

describe("analyzeLocalCli", () => {
  it("parses structured finding JSON from stdout", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const payload = JSON.stringify({
      findings: [
        {
          title: "SQL injection",
          severity: "Critical",
          file: "src/a.ts",
          line: 10,
          evidence: "x",
          risk: "y",
          fix: "z",
          cwe: "CWE-89",
        },
      ],
      summary: "local",
    });

    const promise = analyzeLocalCli(buildArgs());
    fake.stdout.write(payload);
    fake.stdout.end();
    fake.emit("close", 0);

    const result = await promise;
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe("Critical");
    expect(result.summary).toBe("local");
    expect(result.inputTokens).toBe(0);
    expect(result.outputTokens).toBe(0);

    expect(spawnMock).toHaveBeenCalledWith(
      "claude",
      ["-p"],
      expect.objectContaining({ stdio: ["pipe", "pipe", "pipe"] })
    );
  });

  it("returns empty findings when the subprocess prints garbage", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = analyzeLocalCli(buildArgs());
    fake.stdout.write("the model rambled without JSON");
    fake.stdout.end();
    fake.emit("close", 0);

    const result = await promise;
    expect(result.findings).toEqual([]);
  });

  it("honors custom LOCAL_AI_CMD for unknown models", async () => {
    process.env.LOCAL_AI_CMD = "my-llm";
    process.env.LOCAL_AI_ARGS = "--flag  --other";
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = analyzeLocalCli({ ...buildArgs(), model: "my-custom" });
    fake.stdout.write('{"findings":[],"summary":"ok"}');
    fake.stdout.end();
    fake.emit("close", 0);

    await promise;
    expect(spawnMock).toHaveBeenCalledWith(
      "my-llm",
      ["--flag", "--other"],
      expect.anything()
    );
  });

  it("throws a helpful error when the model is unknown and LOCAL_AI_CMD is unset", async () => {
    await expect(
      analyzeLocalCli({ ...buildArgs(), model: "totally-unknown" })
    ).rejects.toThrow(/Unknown model "totally-unknown"/);
  });

  it("uses codex preset when model=codex", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = analyzeLocalCli({ ...buildArgs(), model: "codex" });
    fake.stdout.write('{"findings":[],"summary":"ok"}');
    fake.stdout.end();
    fake.emit("close", 0);

    await promise;
    expect(spawnMock).toHaveBeenCalledWith(
      "codex",
      ["exec", "--skip-git-repo-check", "-"],
      expect.anything()
    );
  });

  it("uses gemini preset when model=gemini", async () => {
    const fake = new FakeProcess();
    spawnMock.mockImplementation(() => fake);

    const promise = analyzeLocalCli({ ...buildArgs(), model: "gemini" });
    fake.stdout.write('{"findings":[],"summary":"ok"}');
    fake.stdout.end();
    fake.emit("close", 0);

    await promise;
    expect(spawnMock).toHaveBeenCalledWith(
      "gemini",
      ["-p", ""],
      expect.anything()
    );
  });
});
