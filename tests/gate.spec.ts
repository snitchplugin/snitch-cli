import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { formatBlockMessage, runGate } from "../src/gate.js";
import type { AnalyzeArgs, AnalyzeResult, Finding } from "../src/_shared/providers/types.js";

// Mock the methodology fetch so the gate can run without hitting the network.
vi.mock("../src/_shared/methodology.js", () => ({
  fetchMethodology: vi.fn(async () => ({
    version: "v7.1.0",
    skill: "test skill",
    categories: [{ id: 68, title: "agent prompt injection", body: "detect injection" }],
  })),
  flattenMethodology: (b: { skill: string; categories: { body: string }[] }) =>
    [b.skill, ...b.categories.map((c) => c.body)].join("\n"),
}));

function git(cwd: string, args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

function makeRepo(): string {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "snitch-gate-")));
  git(root, ["init", "-b", "main", "--quiet"]);
  git(root, ["config", "user.name", "Test"]);
  git(root, ["config", "user.email", "t@t.test"]);
  mkdirSync(path.join(root, "src"));
  writeFileSync(path.join(root, "src/a.ts"), "export const a = 1;\n");
  git(root, ["add", "."]);
  git(root, ["commit", "-m", "init", "--quiet"]);
  return root;
}

function fakeProvider(result: AnalyzeResult) {
  return {
    apiKey: "",
    name: "fake",
    defaultModel: "fake",
    analyze: vi.fn(async (_args: AnalyzeArgs) => result),
  };
}

function finding(severity: Finding["severity"], title = "prompt injection"): Finding {
  return {
    title,
    severity,
    file: "src/a.ts",
    line: 1,
    evidence: "...",
    risk: "hijack",
    fix: "sanitize",
  };
}

describe("runGate", () => {
  let root: string;
  beforeEach(() => {
    root = makeRepo();
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("returns pass=true when no findings", async () => {
    const provider = fakeProvider({
      findings: [],
      summary: "clean",
      inputTokens: 0,
      outputTokens: 0,
    });
    const result = await runGate({
      repoRoot: root,
      licenseKey: "snch_test",
      provider,
      model: "fake",
    });
    expect(result.pass).toBe(true);
    expect(result.findings).toEqual([]);
    expect(provider.analyze).toHaveBeenCalledOnce();
  });

  it("returns pass=false when any Critical finding is present", async () => {
    const provider = fakeProvider({
      findings: [finding("Critical")],
      summary: "found payload",
      inputTokens: 0,
      outputTokens: 0,
    });
    const result = await runGate({
      repoRoot: root,
      licenseKey: "snch_test",
      provider,
      model: "fake",
    });
    expect(result.pass).toBe(false);
    expect(result.findings).toHaveLength(1);
  });

  it("returns pass=false when any High finding is present", async () => {
    const provider = fakeProvider({
      findings: [finding("High")],
      summary: "found payload",
      inputTokens: 0,
      outputTokens: 0,
    });
    const result = await runGate({
      repoRoot: root,
      licenseKey: "snch_test",
      provider,
      model: "fake",
    });
    expect(result.pass).toBe(false);
  });

  it("ignores Medium/Low findings for the block decision", async () => {
    const provider = fakeProvider({
      findings: [finding("Medium"), finding("Low")],
      summary: "minor",
      inputTokens: 0,
      outputTokens: 0,
    });
    const result = await runGate({
      repoRoot: root,
      licenseKey: "snch_test",
      provider,
      model: "fake",
    });
    expect(result.pass).toBe(true);
    expect(result.findings).toHaveLength(2);
  });

  it("passes when the repo has no scannable files", async () => {
    const emptyRoot = realpathSync(mkdtempSync(path.join(os.tmpdir(), "snitch-empty-")));
    try {
      git(emptyRoot, ["init", "-b", "main", "--quiet"]);
      git(emptyRoot, ["config", "user.name", "Test"]);
      git(emptyRoot, ["config", "user.email", "t@t.test"]);
      git(emptyRoot, ["commit", "--allow-empty", "-m", "init", "--quiet"]);

      const provider = fakeProvider({
        findings: [finding("Critical")], // would block, but no files => no call
        summary: "",
        inputTokens: 0,
        outputTokens: 0,
      });
      const result = await runGate({
        repoRoot: emptyRoot,
        licenseKey: "snch_test",
        provider,
        model: "fake",
      });
      expect(result.pass).toBe(true);
      expect(result.fileCount).toBe(0);
      expect(provider.analyze).not.toHaveBeenCalled();
    } finally {
      rmSync(emptyRoot, { recursive: true, force: true });
    }
  });
});

describe("formatBlockMessage", () => {
  it("produces a human-readable block message with per-finding detail", () => {
    const msg = formatBlockMessage(
      {
        pass: false,
        findings: [finding("Critical", "ignore-prev-instructions in README")],
        summary: "found payload",
        fileCount: 3,
      },
      "/tmp/snitch-repo-abc"
    );
    expect(msg).toMatch(/prompt-injection risk detected/i);
    expect(msg).toMatch(/Blocking findings: 1/);
    expect(msg).toMatch(/ignore-prev-instructions in README/);
    expect(msg).toMatch(/\/tmp\/snitch-repo-abc/);
    expect(msg).toMatch(/--force-after-injection/);
  });
});
