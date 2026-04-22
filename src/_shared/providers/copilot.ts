import { buildPrompt, parseResponse } from "./_shared.js";
import type { AnalyzeArgs, AnalyzeResult, ProviderAdapter } from "./types.js";

const COPILOT_ENDPOINT = "https://models.inference.ai.azure.com/chat/completions";

/**
 * GitHub Copilot adapter. Uses the GitHub Models OpenAI-compatible endpoint.
 * Requires an active Copilot or GitHub Models entitlement on the supplied token.
 */
export const copilot: ProviderAdapter = {
  name: "copilot",
  defaultModel: "gpt-4o",
  async analyze(args) {
    const prompt = buildPrompt(args.methodology, args.files);
    const model = resolveModel(args.model);
    const maxTokens = args.maxOutputTokens ?? 4096;

    const response = await fetch(COPILOT_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${args.apiKey}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(
        `Copilot endpoint returned ${response.status}. Body: ${errBody.slice(0, 500)}. Confirm the supplied token has Copilot or GitHub Models access.`
      );
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };

    const text = data.choices?.[0]?.message?.content ?? "";
    return parseResponse(text, {
      inputTokens: data.usage?.prompt_tokens,
      outputTokens: data.usage?.completion_tokens,
    });
  },
};

function resolveModel(model: string): string {
  const aliases: Record<string, string> = {
    "gpt-4o": "gpt-4o",
    gpt4: "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
  };
  return aliases[model.toLowerCase()] ?? model;
}

// parseResponse needs the same return shape as runScan.
// Re-export so this file can be imported uniformly with the other adapters.
export type { AnalyzeArgs, AnalyzeResult };
