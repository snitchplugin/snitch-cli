import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { runScan } from "./_shared.js";
import type { ProviderAdapter } from "./types.js";

export const openrouter: ProviderAdapter = {
  name: "openrouter",
  defaultModel: "anthropic/claude-sonnet-4-6",
  async analyze(args) {
    const provider = createOpenRouter({ apiKey: args.apiKey });
    return runScan(provider(resolveModel(args.model)), args);
  },
};

function resolveModel(model: string): string {
  // OpenRouter expects "vendor/model" form. Accept short aliases that map to common picks.
  const aliases: Record<string, string> = {
    sonnet: "anthropic/claude-sonnet-4-6",
    opus: "anthropic/claude-opus-4-7",
    "gpt-4o": "openai/gpt-4o",
    gpt4: "openai/gpt-4o",
    gemini: "google/gemini-2.5-pro",
  };
  return aliases[model.toLowerCase()] ?? model;
}
