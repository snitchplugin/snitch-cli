import { spawn, type SpawnOptions } from "node:child_process";
import { buildPrompt, parseResponse } from "../_shared/providers/_shared.js";
import type {
  AnalyzeArgs,
  AnalyzeResult,
} from "../_shared/providers/types.js";

// local-cli lives outside the shared ProviderName enum. It is CLI-specific
// (the Action can't shell out to a local binary on a GitHub runner), so it
// gets its own adapter shape rather than polluting the hosted-provider type.
export interface LocalCliAdapter {
  name: "local-cli";
  defaultModel: string;
  analyze(args: AnalyzeArgs): Promise<AnalyzeResult>;
}

interface PresetCommand {
  command: string;
  args: string[];
}

/**
 * Invocation presets for the AI CLIs friends are most likely to already have
 * installed. Each preset spawns the binary with stdin piped (we feed the
 * prompt via stdin and read the response from stdout).
 *
 * If the friend is using something else, they set LOCAL_AI_CMD and optionally
 * LOCAL_AI_ARGS and we honor that as `custom`.
 */
const PRESETS: Record<string, PresetCommand> = {
  // Claude Code: `claude -p` reads the prompt from stdin in non-interactive mode.
  claude: { command: "claude", args: ["-p"] },
  // Codex CLI: `codex exec -` routes stdin as the prompt (without `-` Codex
  // assumes a TTY and errors out). --skip-git-repo-check lets us invoke Codex
  // from any cwd since we only use it for inference; we never ask it to read
  // or modify files (we pass the code inline in the prompt).
  codex: { command: "codex", args: ["exec", "--skip-git-repo-check", "-"] },
  // Gemini CLI: `-p` is required to flip to headless mode. When stdin is piped,
  // the CLI appends it to whatever `-p` argument is given, so we pass an empty
  // arg and the full prompt arrives via stdin.
  gemini: { command: "gemini", args: ["-p", ""] },
};

function resolveCommand(model: string): PresetCommand {
  const preset = PRESETS[model.toLowerCase()];
  if (preset) return preset;

  // Custom: require LOCAL_AI_CMD. Space-split LOCAL_AI_ARGS if provided.
  const envCmd = process.env.LOCAL_AI_CMD;
  if (!envCmd || envCmd.trim().length === 0) {
    throw new LocalCliError(
      `Unknown model "${model}" for local-cli. Set LOCAL_AI_CMD env var, or use one of: ${Object.keys(PRESETS).join(", ")}.`
    );
  }
  const envArgs = (process.env.LOCAL_AI_ARGS ?? "")
    .split(/\s+/)
    .filter((s) => s.length > 0);
  return { command: envCmd.trim(), args: envArgs };
}

export class LocalCliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalCliError";
  }
}

/**
 * Spawn a binary, write `stdin` to it, collect stdout until exit. Resolves
 * with the captured stdout; rejects with a clear error on ENOENT or non-zero
 * exit code.
 */
export async function runSubprocess(
  command: string,
  args: string[],
  stdinText: string,
  timeoutMs: number = 300_000,
  spawnOpts: SpawnOptions = {}
): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      ...spawnOpts,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      done(() =>
        reject(
          new LocalCliError(
            `Local AI CLI "${command}" timed out after ${timeoutMs / 1000}s.`
          )
        )
      );
    }, timeoutMs);

    proc.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") {
        done(() =>
          reject(
            new LocalCliError(
              `Local AI CLI "${command}" not found on PATH. Install it, or pick a different --model.`
            )
          )
        );
        return;
      }
      done(() => reject(new LocalCliError(`Failed to spawn "${command}": ${err.message}`)));
    });

    proc.stdout?.on("data", (chunk) => {
      stdout += chunk.toString("utf-8");
    });
    proc.stderr?.on("data", (chunk) => {
      stderr += chunk.toString("utf-8");
    });

    proc.on("close", (code) => {
      if (code !== 0) {
        const snippet = stderr.slice(0, 500).trim();
        done(() =>
          reject(
            new LocalCliError(
              `Local AI CLI "${command}" exited with code ${code}. ${snippet ? `stderr: ${snippet}` : ""}`
            )
          )
        );
        return;
      }
      done(() => resolve(stdout));
    });

    if (proc.stdin) {
      proc.stdin.on("error", () => {
        // stdin EPIPE when the child closes early; swallow and let the close
        // handler produce the real error message.
      });
      proc.stdin.end(stdinText, "utf-8");
    } else {
      done(() =>
        reject(new LocalCliError(`Subprocess "${command}" did not expose stdin.`))
      );
    }
  });
}

export async function analyzeLocalCli(args: AnalyzeArgs): Promise<AnalyzeResult> {
  const { command, args: commandArgs } = resolveCommand(args.model);
  const prompt = buildPrompt(args.methodology, args.files);
  const stdout = await runSubprocess(command, commandArgs, prompt);
  // Token counts are not uniformly available across local CLIs. Telemetry
  // records 0s so the dashboard still shows the scan, without faking numbers.
  return parseResponse(stdout, undefined);
}

export const localCli: LocalCliAdapter = {
  name: "local-cli",
  defaultModel: "claude",
  analyze: analyzeLocalCli,
};
