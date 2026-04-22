import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import yaml from "js-yaml";
import { z } from "zod";

const TriggerMode = z.enum(["smart", "always", "manual"]);
const Provider = z.enum(["openrouter", "anthropic", "openai", "google", "copilot"]);
const FailOn = z.enum(["critical", "high", "medium", "low", "none"]);

const ConfigSchema = z.object({
  trigger: TriggerMode.optional(),
  provider: Provider.optional(),
  model: z.string().optional(),
  "fail-on": FailOn.optional(),
  categories: z.array(z.number().int().positive()).optional(),
  paths: z
    .object({
      ignore: z.array(z.string()).optional(),
      include: z.array(z.string()).optional(),
    })
    .optional(),
  "ignore-comments": z.boolean().optional(),
  "override-label": z.string().optional(),
});

export type SnitchConfig = z.infer<typeof ConfigSchema>;

export const DEFAULT_PATHS_IGNORE = [
  "**/*.md",
  "**/*.test.*",
  "**/*.spec.*",
  "docs/**",
  "vendor/**",
  "node_modules/**",
];

export const DEFAULT_CONFIG: Required<
  Pick<SnitchConfig, "trigger" | "fail-on" | "ignore-comments" | "override-label">
> & { paths: { ignore: string[]; include: string[] } } = {
  trigger: "smart",
  "fail-on": "high",
  "ignore-comments": true,
  "override-label": "snitch-override",
  paths: { ignore: DEFAULT_PATHS_IGNORE, include: [] },
};

export class ConfigError extends Error {
  readonly issues: string[];
  constructor(issues: string[]) {
    super(`Invalid .snitch.yml: ${issues.join("; ")}`);
    this.name = "ConfigError";
    this.issues = issues;
  }
}

export function parseConfigYaml(yamlText: string): SnitchConfig {
  const raw = yaml.load(yamlText);
  const parsed = ConfigSchema.safeParse(raw ?? {});
  if (!parsed.success) {
    const issues = parsed.error.issues.map(
      (i) => `${i.path.join(".") || "(root)"}: ${i.message}`
    );
    throw new ConfigError(issues);
  }
  return parsed.data;
}

export function loadConfig(repoRoot: string): SnitchConfig {
  const configPath = path.join(repoRoot, ".snitch.yml");
  if (!existsSync(configPath)) return {};
  const text = readFileSync(configPath, "utf-8");
  return parseConfigYaml(text);
}

export function mergeWithDefaults(cfg: SnitchConfig): {
  trigger: "smart" | "always" | "manual";
  failOn: "critical" | "high" | "medium" | "low" | "none";
  ignoreComments: boolean;
  overrideLabel: string;
  pathsIgnore: string[];
  pathsInclude: string[];
  provider?: SnitchConfig["provider"];
  model?: string;
  categories?: number[];
} {
  return {
    trigger: cfg.trigger ?? DEFAULT_CONFIG.trigger,
    failOn: cfg["fail-on"] ?? DEFAULT_CONFIG["fail-on"],
    ignoreComments: cfg["ignore-comments"] ?? DEFAULT_CONFIG["ignore-comments"],
    overrideLabel: cfg["override-label"] ?? DEFAULT_CONFIG["override-label"],
    pathsIgnore: cfg.paths?.ignore ?? DEFAULT_CONFIG.paths.ignore,
    pathsInclude: cfg.paths?.include ?? DEFAULT_CONFIG.paths.include,
    provider: cfg.provider,
    model: cfg.model,
    categories: cfg.categories,
  };
}
