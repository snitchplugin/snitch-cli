import { execFileSync } from "node:child_process";
import * as readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { configPath, saveConfig, type StoredConfig } from "./config-store.js";
import { validateLicense } from "./validate.js";

interface ProviderOption {
  label: string;
  value: StoredConfig["provider"];
  model: string;
  needsKey: boolean;
  binaryToCheck?: string;
  hint: string;
}

const OPTIONS: ProviderOption[] = [
  {
    label: "OpenRouter (one key, all models, hosted)",
    value: "openrouter",
    model: "anthropic/claude-sonnet-4-6",
    needsKey: true,
    hint: "Sends your code to OpenRouter. Needs an OpenRouter API key.",
  },
  {
    label: "Claude Code (uses your installed `claude` CLI)",
    value: "local-cli",
    model: "claude",
    needsKey: false,
    binaryToCheck: "claude",
    hint: "Nothing new leaves your laptop. Uses whatever model Claude Code is configured with.",
  },
  {
    label: "Codex CLI (uses your installed `codex`)",
    value: "local-cli",
    model: "codex",
    needsKey: false,
    binaryToCheck: "codex",
    hint: "Nothing new leaves your laptop. Uses your OpenAI Codex subscription.",
  },
  {
    label: "Gemini CLI (uses your installed `gemini`)",
    value: "local-cli",
    model: "gemini",
    needsKey: false,
    binaryToCheck: "gemini",
    hint: "Nothing new leaves your laptop. Uses your Gemini CLI auth.",
  },
];

function isTty(): boolean {
  return !!stdin.isTTY && !!stdout.isTTY;
}

function isBinaryOnPath(binary: string): boolean {
  try {
    const lookup = process.platform === "win32" ? "where" : "which";
    execFileSync(lookup, [binary], { stdio: ["ignore", "pipe", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

export class SetupAbort extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SetupAbort";
  }
}

/**
 * First-run interactive setup. Prompts for license key + provider choice,
 * validates, writes config, returns the saved config for the caller to use
 * for the scan about to run.
 *
 * Throws SetupAbort if stdin/stdout is not a TTY (so the scan doesn't hang
 * waiting for input in CI).
 */
export async function runSetup(): Promise<StoredConfig> {
  if (!isTty()) {
    throw new SetupAbort(
      "Snitch is not configured and this is not an interactive terminal. Run `snitch init` on your laptop first, or export SNITCH_LICENSE_KEY + provider key env vars."
    );
  }

  const rl = readline.createInterface({ input: stdin, output: stdout });

  try {
    stdout.write("\n");
    stdout.write("Welcome to Snitch. Let's set up.\n");
    stdout.write("\n");

    // 1) License key
    const licenseKey = await promptLicenseKey(rl);

    // 2) Provider choice
    const choice = await promptProvider(rl);

    // 3) OpenRouter key (only if needed)
    let openrouterKey: string | undefined;
    if (choice.needsKey) {
      openrouterKey = await promptOpenRouterKey(rl);
    }

    const cfg: StoredConfig = {
      licenseKey,
      provider: choice.value,
      model: choice.model,
    };
    if (openrouterKey) cfg.openrouterKey = openrouterKey;

    saveConfig(cfg);

    stdout.write(`\n\u2713 Saved to ${configPath()} (chmod 600)\n\n`);

    return cfg;
  } finally {
    rl.close();
  }
}

async function promptLicenseKey(rl: readline.Interface): Promise<string> {
  for (;;) {
    const raw = (
      await rl.question(
        "Paste your license key from https://snitchplugin.com/dashboard/github:\n> "
      )
    ).trim();

    if (raw.length === 0) {
      stdout.write("No key entered. Press Ctrl+C to abort, or paste it now.\n");
      continue;
    }
    if (!raw.startsWith("snch_")) {
      stdout.write("That does not look like a Snitch license key (expected prefix \"snch_\"). Try again.\n");
      continue;
    }

    stdout.write("Validating with snitchplugin.com...\n");
    const result = await validateLicense(raw);
    if (!result.ok) {
      stdout.write(
        `License rejected: ${result.reason ?? "unknown reason"}. Copy again from /dashboard/github.\n`
      );
      continue;
    }

    if (result.tier) {
      stdout.write(
        `\u2713 Key valid. Plan: ${result.tier}. Quota: ${result.quotaUsed ?? "?"} / ${result.quotaMonthly ?? "?"} this period.\n`
      );
    } else if (result.reason) {
      stdout.write(`Key accepted. Note: ${result.reason}\n`);
    } else {
      stdout.write("\u2713 Key accepted.\n");
    }
    stdout.write("\n");
    return raw;
  }
}

async function promptProvider(rl: readline.Interface): Promise<ProviderOption> {
  stdout.write("How should Snitch run scans?\n");
  stdout.write("(Options 2-4 keep your code on your laptop; option 1 sends to OpenRouter.)\n\n");

  // Annotate which local binaries are installed so the friend knows which
  // option actually works without more install work.
  const status = OPTIONS.map((o) => {
    if (!o.binaryToCheck) return { option: o, available: true, note: "" };
    const ok = isBinaryOnPath(o.binaryToCheck);
    return {
      option: o,
      available: ok,
      note: ok ? "\u2713 detected" : "not installed",
    };
  });

  status.forEach((s, idx) => {
    const num = idx + 1;
    const badge = s.note ? ` [${s.note}]` : "";
    stdout.write(`  [${num}] ${s.option.label}${badge}\n`);
    stdout.write(`       ${s.option.hint}\n`);
  });

  stdout.write("\n");

  for (;;) {
    const raw = (await rl.question("Choice [1-4, default 2]: ")).trim();
    const n = raw.length === 0 ? 2 : parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 1 || n > OPTIONS.length) {
      stdout.write("Pick a number from 1 to 4.\n");
      continue;
    }
    const picked = status[n - 1]!;
    if (!picked.available) {
      stdout.write(
        `\`${picked.option.binaryToCheck}\` is not on your PATH. Install it and rerun, or pick another option.\n`
      );
      continue;
    }
    stdout.write("\n");
    return picked.option;
  }
}

async function promptOpenRouterKey(rl: readline.Interface): Promise<string> {
  stdout.write("Paste your OpenRouter API key (https://openrouter.ai/keys).\n");
  stdout.write("(Starts with \"sk-or-\".)\n");
  for (;;) {
    const raw = (await rl.question("> ")).trim();
    if (raw.length === 0) {
      stdout.write("No key entered. Paste it now or Ctrl+C to abort.\n");
      continue;
    }
    if (!raw.startsWith("sk-or-")) {
      stdout.write("That does not look like an OpenRouter key. Try again.\n");
      continue;
    }
    return raw;
  }
}

