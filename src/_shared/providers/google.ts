import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { runScan } from "./_shared.js";
import type { ProviderAdapter } from "./types.js";

export const google: ProviderAdapter = {
  name: "google",
  defaultModel: "gemini-2.5-pro",
  async analyze(args) {
    const provider = createGoogleGenerativeAI({ apiKey: args.apiKey });
    return runScan(provider(resolveModel(args.model)), args);
  },
};

function resolveModel(model: string): string {
  const aliases: Record<string, string> = {
    gemini: "gemini-2.5-pro",
    pro: "gemini-2.5-pro",
    flash: "gemini-2.5-flash",
  };
  return aliases[model.toLowerCase()] ?? model;
}
