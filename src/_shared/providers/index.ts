import { anthropic } from "./anthropic.js";
import { copilot } from "./copilot.js";
import { google } from "./google.js";
import { openai } from "./openai.js";
import { openrouter } from "./openrouter.js";
import type { ProviderAdapter, ProviderName } from "./types.js";

export const ADAPTERS: Record<ProviderName, ProviderAdapter> = {
  openrouter,
  anthropic,
  openai,
  google,
  copilot,
};

// Auto-selection priority. OpenRouter wins because one key gives access to
// every other provider's models.
export const SELECTION_PRIORITY: ProviderName[] = [
  "openrouter",
  "anthropic",
  "openai",
  "google",
  "copilot",
];

export interface ProviderKeys {
  openrouter?: string;
  anthropic?: string;
  openai?: string;
  google?: string;
  copilot?: string;
}

export interface SelectedProvider {
  adapter: ProviderAdapter;
  apiKey: string;
}

export class NoProviderKeyError extends Error {
  constructor() {
    super(
      "No AI provider key supplied. Provide one of: openrouter-api-key, anthropic-api-key, openai-api-key, google-api-key, or copilot-token."
    );
    this.name = "NoProviderKeyError";
  }
}

export class UnknownProviderError extends Error {
  constructor(name: string) {
    super(
      `Unknown provider "${name}". Valid: ${SELECTION_PRIORITY.join(", ")}.`
    );
    this.name = "UnknownProviderError";
  }
}

export class MissingKeyForProviderError extends Error {
  constructor(provider: ProviderName) {
    super(
      `Provider "${provider}" was selected but no key was supplied for it. Set the ${provider}-api-key (or copilot-token) input.`
    );
    this.name = "MissingKeyForProviderError";
  }
}

/**
 * Pick a provider. If `forced` is set, validate that the corresponding key is
 * present and use it. Otherwise pick the highest-priority provider for which a
 * key is present.
 */
export function selectProvider(
  keys: ProviderKeys,
  forced?: string | undefined
): SelectedProvider {
  if (forced) {
    const name = forced.toLowerCase() as ProviderName;
    if (!(name in ADAPTERS)) {
      throw new UnknownProviderError(forced);
    }
    const apiKey = keys[name];
    if (!apiKey) {
      throw new MissingKeyForProviderError(name);
    }
    return { adapter: ADAPTERS[name], apiKey };
  }

  for (const name of SELECTION_PRIORITY) {
    const apiKey = keys[name];
    if (apiKey) {
      return { adapter: ADAPTERS[name], apiKey };
    }
  }

  throw new NoProviderKeyError();
}
