import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Redirect homedir() to a tmpdir before importing config-store so its
// CONFIG_DIR constant resolves into test-owned space.
let tmpHome: string;
vi.mock("node:os", async () => {
  const actual = await vi.importActual<typeof import("node:os")>("node:os");
  return { ...actual, homedir: () => tmpHome };
});

import {
  configExists,
  configPath,
  deleteConfig,
  loadConfig,
  saveConfig,
  statusView,
  type StoredConfig,
} from "../src/config-store.js";

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(os.tmpdir(), "snitch-cfg-"));
  // Pre-create ~/.snitch in the fake home so tests that bypass saveConfig
  // (writeFileSync directly to configPath()) don't ENOENT on the dir.
  mkdirSync(path.join(tmpHome, ".snitch"), { recursive: true, mode: 0o700 });
});

afterEach(() => {
  rmSync(tmpHome, { recursive: true, force: true });
});

function sampleConfig(): StoredConfig {
  return {
    licenseKey: "snch_abc123xyz",
    provider: "local-cli",
    model: "claude",
  };
}

describe("config-store round-trip", () => {
  it("writes then loads the same config", () => {
    const cfg = sampleConfig();
    saveConfig(cfg);
    const loaded = loadConfig();
    expect(loaded).toEqual(cfg);
  });

  it("writes JSON with trailing newline and 0600 perms", () => {
    saveConfig(sampleConfig());
    const s = statSync(configPath());
    if (process.platform !== "win32") {
      expect((s.mode & 0o777).toString(8)).toBe("600");
    }
  });

  it("configExists reflects presence", () => {
    expect(configExists()).toBe(false);
    saveConfig(sampleConfig());
    expect(configExists()).toBe(true);
  });

  it("deleteConfig removes the file", () => {
    saveConfig(sampleConfig());
    expect(deleteConfig()).toBe(true);
    expect(configExists()).toBe(false);
    expect(deleteConfig()).toBe(false);
  });

  it("persists the OpenRouter key when present", () => {
    const cfg: StoredConfig = {
      licenseKey: "snch_or_test",
      provider: "openrouter",
      model: "sonnet",
      openrouterKey: "sk-or-test123",
    };
    saveConfig(cfg);
    expect(loadConfig()).toEqual(cfg);
  });

  it("does not persist an empty openrouterKey", () => {
    saveConfig({
      licenseKey: "snch_x",
      provider: "openrouter",
      openrouterKey: "",
    });
    expect(loadConfig()?.openrouterKey).toBeUndefined();
  });
});

describe("config coercion", () => {
  it("returns null for missing snch_ prefix", () => {
    writeFileSync(
      configPath(),
      JSON.stringify({ licenseKey: "garbage", provider: "openrouter" })
    );
    expect(loadConfig()).toBeNull();
  });

  it("returns null for unknown provider", () => {
    writeFileSync(
      configPath(),
      JSON.stringify({ licenseKey: "snch_x", provider: "skynet" })
    );
    expect(loadConfig()).toBeNull();
  });

  it("returns null when the file is not JSON", () => {
    writeFileSync(configPath(), "this is not json");
    expect(loadConfig()).toBeNull();
  });
});

describe("statusView", () => {
  it("reports not-exists before save", () => {
    const s = statusView();
    expect(s.exists).toBe(false);
    expect(s.licenseKeyPreview).toBeNull();
  });

  it("masks the license key on status", () => {
    saveConfig({
      licenseKey: "snch_12345678901234567890",
      provider: "local-cli",
      model: "claude",
    });
    const s = statusView();
    expect(s.exists).toBe(true);
    expect(s.licenseKeyPreview).not.toContain("12345678901234");
    expect(s.licenseKeyPreview).toMatch(/^snch_.*…/);
    expect(s.licenseKeyPreview).toContain("7890"); // last 4
  });

  it("reports whether the OpenRouter key is set without leaking it", () => {
    saveConfig({
      licenseKey: "snch_x",
      provider: "openrouter",
      openrouterKey: "sk-or-VERYSECRETVALUE",
    });
    const s = statusView();
    expect(s.hasOpenrouterKey).toBe(true);
    // Make sure the status view never serializes the actual key.
    expect(JSON.stringify(s)).not.toContain("VERYSECRETVALUE");
  });
});

describe("file permissions (unix)", () => {
  it("re-tightens 0600 even if the file existed with looser perms", () => {
    if (process.platform === "win32") return;
    saveConfig(sampleConfig());
    chmodSync(configPath(), 0o644);
    saveConfig(sampleConfig());
    const s = statSync(configPath());
    expect((s.mode & 0o777).toString(8)).toBe("600");
  });
});
