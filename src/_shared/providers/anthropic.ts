import { createAnthropic } from "@ai-sdk/anthropic";
import { runScan } from "./_shared.js";
import type { ProviderAdapter } from "./types.js";

export const anthropic: ProviderAdapter = {
  name: "anthropic",
  defaultModel: "claude-sonnet-4-6",
  async analyze(args) {
    const provider = createAnthropic({ apiKey: args.apiKey });
    return runScan(provider(resolveModel(args.model)), args);
  },
};

function resolveModel(model: string): string {
  // Accept short aliases for ergonomics in .snitch.yml.
  const aliases: Record<string, string> = {
    sonnet: "claude-sonnet-4-6",
    opus: "claude-opus-4-7",
    haiku: "claude-haiku-4-5-20251001",
  };
  return aliases[model.toLowerCase()] ?? model;
}
