import { ArgError, HELP_TEXT, parseArgs } from "./args.js";
import { runScan } from "./scan.js";
import { LicenseError } from "./_shared/license.js";
import { runSetup, SetupAbort } from "./setup.js";
import {
  configPath,
  deleteConfig,
  loadConfig,
  saveConfig,
  statusView,
  type StoredConfig,
} from "./config-store.js";
import { validateLicense } from "./validate.js";

const VERSION = "1.1.5";

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    if (err instanceof ArgError) {
      console.error(err.message);
      console.error("");
      console.error(HELP_TEXT);
      process.exit(2);
    }
    throw err;
  }

  if (parsed.command === "help") {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (parsed.command === "version") {
    console.log(VERSION);
    process.exit(0);
  }

  if (parsed.command === "init") {
    try {
      await runSetup();
      console.log("Run `snitch scan` to use the new config.");
      process.exit(0);
    } catch (err) {
      if (err instanceof SetupAbort) {
        console.error(err.message);
        process.exit(1);
      }
      throw err;
    }
  }

  if (parsed.command === "logout") {
    const removed = deleteConfig();
    if (removed) {
      console.log(`Deleted ${configPath()}.`);
    } else {
      console.log(`No config file at ${configPath()}.`);
    }
    process.exit(0);
  }

  if (parsed.command === "auth") {
    try {
      await runAuth(parsed);
      process.exit(0);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  }

  if (parsed.command === "status") {
    const s = statusView();
    if (!s.exists) {
      console.log(`No config at ${s.path}. Run \`snitch init\` or \`snitch scan\`.`);
      process.exit(0);
    }
    console.log(`Config:      ${s.path}`);
    console.log(`Permissions: ${s.permissions ?? "(unknown)"}`);
    console.log(`License key: ${s.licenseKeyPreview}`);
    console.log(`Provider:    ${s.provider}`);
    console.log(`Model:       ${s.model ?? "(provider default)"}`);
    console.log(`OpenRouter:  ${s.hasOpenrouterKey ? "configured" : "not set"}`);
    process.exit(0);
  }

  // scan
  try {
    const result = await runScan(parsed);
    process.exit(result.exitCode);
  } catch (err) {
    if (err instanceof LicenseError) {
      console.error(`License: ${err.message}`);
      if (err.upgradeUrl) {
        console.error(`Upgrade: ${err.upgradeUrl}`);
      }
      process.exit(1);
    }
    if (err instanceof SetupAbort) {
      console.error(err.message);
      process.exit(1);
    }
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

async function runAuth(parsed: {
  authKey?: string;
  authOpenrouterKey?: string;
  provider?: string;
  model?: string;
}): Promise<void> {
  const key = parsed.authKey!;
  console.log("Validating license key against snitchplugin.com…");
  const result = await validateLicense(key);
  if (!result.ok) {
    throw new Error(result.reason ?? "License key rejected.");
  }

  const existing = loadConfig();
  const provider =
    (parsed.provider as StoredConfig["provider"] | undefined) ??
    existing?.provider ??
    "openrouter";
  const next: StoredConfig = {
    licenseKey: key,
    provider,
  };
  const model = parsed.model ?? existing?.model;
  if (model) next.model = model;
  const openrouterKey = parsed.authOpenrouterKey ?? existing?.openrouterKey;
  if (openrouterKey) next.openrouterKey = openrouterKey;

  saveConfig(next);

  console.log(`Saved to ${configPath()} (0600).`);
  if (result.tier) {
    const used = result.quotaUsed ?? 0;
    const monthly = result.quotaMonthly;
    const quota = monthly === undefined ? `${used} scans used` : `${used} / ${monthly} scans this period`;
    console.log(`Plan:  ${result.tier}`);
    console.log(`Quota: ${quota}`);
  } else if (result.reason) {
    console.log(result.reason);
  }
  console.log("");
  console.log("Next: run `snitch scan` from inside a git repo.");
}

main();
