import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";

// Resolve paths lazily so tests that mock homedir() via vi.mock("node:os")
// can intercept the call before config-store reads ~/.snitch.
function dirs(): { dir: string; file: string } {
  const dir = path.join(homedir(), ".snitch");
  return { dir, file: path.join(dir, "config.json") };
}

const PROVIDERS = [
  "openrouter",
  "anthropic",
  "openai",
  "google",
  "copilot",
  "local-cli",
] as const;

type Provider = (typeof PROVIDERS)[number];

export interface StoredConfig {
  // Snitch license key. Always required.
  licenseKey: string;
  // Which provider the scan uses by default.
  provider: Provider;
  // Provider-relative model alias (e.g. "claude" for local-cli, "sonnet" for openrouter).
  model?: string;
  // Only stored when the user picked OpenRouter. Other hosted providers are
  // not offered via the wizard (local-cli path is the friends default).
  openrouterKey?: string;
}

export function configPath(): string {
  return dirs().file;
}

export function configExists(): boolean {
  return existsSync(dirs().file);
}

export function loadConfig(): StoredConfig | null {
  const { file } = dirs();
  if (!existsSync(file)) return null;
  try {
    const raw = readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    return coerce(parsed);
  } catch {
    return null;
  }
}

export function saveConfig(cfg: StoredConfig): void {
  const { dir, file } = dirs();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  // Lock the directory down too, in case it existed with looser perms.
  try {
    chmodSync(dir, 0o700);
  } catch {
    // On Windows chmod is a no-op; ignore failures.
  }

  const payload = JSON.stringify(normalize(cfg), null, 2) + "\n";
  writeFileSync(file, payload, "utf-8");

  try {
    chmodSync(file, 0o600);
  } catch {
    // Windows
  }
}

export function deleteConfig(): boolean {
  const { file } = dirs();
  if (!existsSync(file)) return false;
  rmSync(file, { force: true });
  return true;
}

/**
 * Summary view safe to print to the terminal (no keys shown in full).
 */
export interface ConfigStatus {
  exists: boolean;
  path: string;
  licenseKeyPreview: string | null;
  provider: Provider | null;
  model: string | null;
  hasOpenrouterKey: boolean;
  permissions: string | null;
}

export function statusView(): ConfigStatus {
  const { file } = dirs();
  const cfg = loadConfig();
  if (!cfg) {
    return {
      exists: false,
      path: file,
      licenseKeyPreview: null,
      provider: null,
      model: null,
      hasOpenrouterKey: false,
      permissions: null,
    };
  }
  let mode: string | null = null;
  try {
    const s = statSync(file);
    mode = (s.mode & 0o777).toString(8);
  } catch {
    mode = null;
  }
  return {
    exists: true,
    path: file,
    licenseKeyPreview: preview(cfg.licenseKey),
    provider: cfg.provider,
    model: cfg.model ?? null,
    hasOpenrouterKey: !!cfg.openrouterKey,
    permissions: mode,
  };
}

function preview(key: string): string {
  if (!key) return "";
  if (key.length <= 12) return `${key.slice(0, 4)}…`;
  return `${key.slice(0, 8)}…${key.slice(-4)}`;
}

function coerce(raw: unknown): StoredConfig | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.licenseKey !== "string" || !obj.licenseKey.startsWith("snch_")) {
    return null;
  }
  const provider = obj.provider;
  if (typeof provider !== "string" || !PROVIDERS.includes(provider as Provider)) {
    return null;
  }
  const out: StoredConfig = {
    licenseKey: obj.licenseKey,
    provider: provider as Provider,
  };
  if (typeof obj.model === "string" && obj.model.length > 0) out.model = obj.model;
  if (typeof obj.openrouterKey === "string" && obj.openrouterKey.length > 0) {
    out.openrouterKey = obj.openrouterKey;
  }
  return out;
}

function normalize(cfg: StoredConfig): StoredConfig {
  const out: StoredConfig = {
    licenseKey: cfg.licenseKey.trim(),
    provider: cfg.provider,
  };
  if (cfg.model) out.model = cfg.model.trim();
  if (cfg.openrouterKey) out.openrouterKey = cfg.openrouterKey.trim();
  return out;
}
