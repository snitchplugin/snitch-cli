export interface ParsedArgs {
  command: "scan" | "help" | "version" | "init" | "logout" | "status" | "auth";
  files?: string[];
  full?: boolean;
  base?: string;
  failOn?: "critical" | "high" | "medium" | "low" | "none";
  provider?: string;
  model?: string;
  quiet?: boolean;
  repo?: string;
  forceAfterInjection?: boolean;
  // Positional shorthand: @path (file or dir) or #123 / #PR-123 (PR number).
  positionals?: string[];
  // Restrict the scan to a subset of the 68 categories. Number is the
  // category ID from the methodology (1-68). Overrides .snitch.yml categories.
  categories?: number[];
  quick?: boolean; // scan only the 10 core categories
  // auth subcommand
  authKey?: string;
  authOpenrouterKey?: string;
}

export class ArgError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArgError";
  }
}

const FAIL_ON_VALUES = new Set(["critical", "high", "medium", "low", "none"]);

const COMMANDS = [
  "scan",
  "auth",
  "init",
  "status",
  "logout",
  "help",
  "version",
] as const;

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const prev = new Array(b.length + 1);
  const curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }
  return prev[b.length];
}

function suggestCommand(input: string): string | null {
  const lower = input.toLowerCase();
  let best: { cmd: string; d: number } | null = null;
  for (const cmd of COMMANDS) {
    const d = levenshtein(lower, cmd);
    if (d <= 2 && (!best || d < best.d)) best = { cmd, d };
  }
  return best?.cmd ?? null;
}
const PROVIDERS = new Set([
  "openrouter",
  "anthropic",
  "openai",
  "google",
  "copilot",
  "local-cli",
]);

export function parseArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0) return { command: "help" };

  const head = argv[0];
  if (head === "-h" || head === "--help" || head === "help") {
    return { command: "help" };
  }
  if (head === "-v" || head === "--version" || head === "version") {
    return { command: "version" };
  }
  if (head === "init") return { command: "init" };
  if (head === "logout") return { command: "logout" };
  if (head === "status") return { command: "status" };
  if (head === "auth") return parseAuthArgs(argv);
  if (head !== "scan") {
    const suggestion = suggestCommand(head!);
    const hint = suggestion ? ` Did you mean \`snitch ${suggestion}\`?` : "";
    throw new ArgError(
      `Unknown command: ${head}.${hint} Try \`snitch help\` for the full list.`
    );
  }

  const parsed: ParsedArgs = { command: "scan" };
  let i = 1;
  while (i < argv.length) {
    const arg = argv[i]!;
    switch (arg) {
      case "--files":
      case "-f": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires a comma-separated file list.`);
        }
        parsed.files = next.split(",").map((s) => s.trim()).filter(Boolean);
        i += 2;
        break;
      }
      case "--full":
        parsed.full = true;
        i += 1;
        break;
      case "--base":
      case "-b": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires a git ref.`);
        }
        parsed.base = next;
        i += 2;
        break;
      }
      case "--fail-on": {
        const next = argv[i + 1];
        if (!next) throw new ArgError("--fail-on requires a value.");
        if (!FAIL_ON_VALUES.has(next)) {
          throw new ArgError(
            `--fail-on must be one of: ${Array.from(FAIL_ON_VALUES).join(", ")}.`
          );
        }
        parsed.failOn = next as ParsedArgs["failOn"];
        i += 2;
        break;
      }
      case "--provider":
      case "-p": {
        const next = argv[i + 1];
        if (!next) throw new ArgError("--provider requires a value.");
        if (!PROVIDERS.has(next)) {
          throw new ArgError(
            `--provider must be one of: ${Array.from(PROVIDERS).join(", ")}.`
          );
        }
        parsed.provider = next;
        i += 2;
        break;
      }
      case "--model":
      case "-m": {
        const next = argv[i + 1];
        if (!next) throw new ArgError("--model requires a value.");
        parsed.model = next;
        i += 2;
        break;
      }
      case "--quiet":
      case "-q":
        parsed.quiet = true;
        i += 1;
        break;
      case "--repo":
      case "-r": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires a path or URL.`);
        }
        parsed.repo = next;
        i += 2;
        break;
      }
      case "--force-after-injection":
        parsed.forceAfterInjection = true;
        i += 1;
        break;
      case "--category":
      case "--categories":
      case "-c": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires one or more category IDs (comma-separated).`);
        }
        const nums = next
          .split(",")
          .map((s) => parseInt(s.trim(), 10))
          .filter((n) => Number.isInteger(n) && n > 0 && n <= 68);
        if (nums.length === 0) {
          throw new ArgError(
            `${arg} requires integer category IDs between 1 and 68. Got: "${next}".`
          );
        }
        parsed.categories = nums;
        i += 2;
        break;
      }
      case "--quick":
        parsed.quick = true;
        i += 1;
        break;
      default:
        // Positional shorthand: @path or #PR reference. Accumulate and keep
        // parsing; the scan runner resolves them to an explicit file list.
        if (arg.startsWith("@") || arg.startsWith("#")) {
          parsed.positionals = parsed.positionals ?? [];
          parsed.positionals.push(arg);
          i += 1;
          break;
        }
        throw new ArgError(`Unknown flag: ${arg}. Try \`snitch help\`.`);
    }
  }

  if (parsed.files && parsed.full) {
    throw new ArgError("--files and --full are mutually exclusive.");
  }
  if (parsed.quick && parsed.categories) {
    throw new ArgError(
      "--quick and --category/--categories are mutually exclusive. --quick is shorthand for the core 10 categories."
    );
  }
  if (parsed.positionals && parsed.positionals.length > 0) {
    if (parsed.full) {
      throw new ArgError(
        "--full cannot be combined with @path / #PR shortcuts (they target a specific subset)."
      );
    }
    if (parsed.files && parsed.files.length > 0) {
      throw new ArgError(
        "--files cannot be combined with @path / #PR shortcuts. Pick one."
      );
    }
  }

  return parsed;
}

function parseAuthArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { command: "auth" };
  let i = 1;
  while (i < argv.length) {
    const arg = argv[i]!;
    switch (arg) {
      case "--key":
      case "-k": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires a license key.`);
        }
        parsed.authKey = next;
        i += 2;
        break;
      }
      case "--openrouter-key": {
        const next = argv[i + 1];
        if (!next || next.startsWith("-")) {
          throw new ArgError(`${arg} requires an OpenRouter API key.`);
        }
        parsed.authOpenrouterKey = next;
        i += 2;
        break;
      }
      case "--provider":
      case "-p": {
        const next = argv[i + 1];
        if (!next) throw new ArgError("--provider requires a value.");
        if (!PROVIDERS.has(next)) {
          throw new ArgError(
            `--provider must be one of: ${Array.from(PROVIDERS).join(", ")}.`
          );
        }
        parsed.provider = next;
        i += 2;
        break;
      }
      case "--model":
      case "-m": {
        const next = argv[i + 1];
        if (!next) throw new ArgError("--model requires a value.");
        parsed.model = next;
        i += 2;
        break;
      }
      default:
        throw new ArgError(`Unknown flag for auth: ${arg}. Try \`snitch help\`.`);
    }
  }

  if (!parsed.authKey) {
    throw new ArgError(
      "snitch auth requires --key <snch_...>. Example: snitch auth --key snch_abc123"
    );
  }
  if (!parsed.authKey.startsWith("snch_")) {
    throw new ArgError("License keys start with `snch_`. Check the value you pasted.");
  }

  return parsed;
}

export const HELP_TEXT = `snitch. Local security scan for your branch.

Usage:
  snitch scan [options]    # run a scan (asks for setup on first run)
  snitch auth [options]    # save a license key without the interactive wizard
  snitch init              # re-run interactive setup
  snitch status            # show current config (no secrets leaked)
  snitch logout            # delete saved config
  snitch help
  snitch version

Non-interactive auth:
  snitch auth --key snch_xxxxxxxxxxxx
  snitch auth --key snch_xxxx --provider openrouter --openrouter-key sk-or-...
  snitch auth --key snch_xxxx --provider local-cli --model claude

  The key is validated against snitchplugin.com. On success it is written to
  ~/.snitch/config.json (0600). Provider defaults to openrouter when no
  config exists yet; existing values are preserved when you only pass --key.

First run:
  Just run \`snitch scan\`. It will prompt for your license key and pick
  your AI provider, then save the answers to ~/.snitch/config.json.
  Subsequent runs read the config and do not prompt.

Scan modes (mutually exclusive; default is git diff vs main):
  --files, -f <a,b,c>   Scan an explicit comma-separated list of files.
  --full                Scan every tracked file in the working tree.
  --base, -b <ref>      Base ref for diff mode (default: origin/main).

Category scope (default is whatever your plan entitles):
  --quick               Shorthand for the 10 core categories (fastest).
  --category, -c <n>    One category ID, e.g. -c 3 for hardcoded secrets.
  --categories <a,b,c>  Comma-separated subset of the 68 category IDs.
                        Free plans already run the core 10 only; this is
                        mainly for Pro/Team users who want a focused pass.

Quick target shortcuts (positional, no flag needed):
  snitch scan @src/auth.ts            # scan one file
  snitch scan @packages/api           # scan every file under a folder
  snitch scan @src/auth.ts @src/db.ts # any number of paths
  snitch scan #123                    # scan files changed in GitHub PR #123
  snitch scan #PR-123                 # same thing, verbose form
                                      # (#PR targets require the gh CLI)

Repo target (optional, defaults to the current directory):
  --repo, -r <path|url> Scan a sibling directory on your laptop, or clone a
                        remote URL into a temp dir and scan that.
  --force-after-injection
                        When --repo <url> clones a repo, a category-68
                        prompt-injection gate runs before the main scan. If
                        the gate blocks, this flag lets you run the main
                        scan anyway. Use at your own risk.

Output:
  Writes SECURITY_AUDIT_REPORT.md and SECURITY_AUDIT_REPORT.sarif to cwd.
  Exits non-zero when --fail-on severity or worse is found. The gate exits
  with a dedicated code (10) so CI can distinguish a blocked clone from a
  failed audit.

Options:
  --fail-on <level>     critical | high | medium | low | none (default high)
  --provider, -p <p>    openrouter | local-cli  (see below)
  --model, -m <name>    Provider-relative model alias.
                        - openrouter: e.g. sonnet, opus, gpt-4o, gemini
                        - local-cli:  claude | codex | gemini | (custom)
  --quiet, -q           Suppress progress output.

Two ways to run:

  1. Hosted via OpenRouter. Set OPENROUTER_API_KEY and go.
       export SNITCH_LICENSE_KEY=snch_...
       export OPENROUTER_API_KEY=sk-or-...
       snitch scan

  2. Local AI CLI. Shell out to an AI coding CLI already on your machine.
     Nothing new leaves your laptop; only what your AI CLI already sends.
       export SNITCH_LICENSE_KEY=snch_...
       snitch scan --provider local-cli --model claude
       snitch scan --provider local-cli --model codex
       snitch scan --provider local-cli --model gemini

     For a custom AI CLI, set LOCAL_AI_CMD (and optionally LOCAL_AI_ARGS):
       export LOCAL_AI_CMD=my-llm
       export LOCAL_AI_ARGS="--flag"
       snitch scan --provider local-cli --model my-llm

Environment (summary):
  SNITCH_LICENSE_KEY    Required. License key from snitchplugin.com/dashboard/github.
  OPENROUTER_API_KEY    Required for --provider openrouter.
  LOCAL_AI_CMD          Custom binary for --provider local-cli with an unknown --model.
  LOCAL_AI_ARGS         Optional space-separated args for LOCAL_AI_CMD.
`;
