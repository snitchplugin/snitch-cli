import { createOpenAI } from "@ai-sdk/openai";
import { runScan } from "./_shared.js";
import type { ProviderAdapter } from "./types.js";

export const openai: ProviderAdapter = {
  name: "openai",
  defaultModel: "gpt-4o",
  async analyze(args) {
    const provider = createOpenAI({ apiKey: args.apiKey });
    return runScan(provider(resolveModel(args.model)), args);
  },
};

function resolveModel(model: string): string {
  const aliases: Record<string, string> = {
    gpt4: "gpt-4o",
    "gpt-4": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    o3: "o3",
    "o3-mini": "o3-mini",
  };
  return aliases[model.toLowerCase()] ?? model;
}
