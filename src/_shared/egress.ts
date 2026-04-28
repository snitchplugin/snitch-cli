// Runtime egress allowlist. Wraps global fetch to enforce that the Action
// only talks to known hosts. Any attempt to reach an unexpected host throws
// loudly — surfacing in the workflow log.
//
// This is the structural defense against a poisoned transitive dep
// exfiltrating secrets / source / env to an attacker-controlled host
// (the same attack vector that hit Bitwarden CLI users via the Checkmarx
// supply-chain compromise in April 2026). A compromised dep can still
// crash the scan, but it can't quietly phone home — every outbound
// request is gated by this list.
//
// The list is derived at install time from:
//   - Snitch's own services (snitchplugin.com)
//   - OSV.dev (the only third party we query for SCA)
//   - The customer-selected AI provider (passed in as `provider` so the
//     allowlist matches the keys they actually wired up)
//   - GitHub's own API (octokit calls in github.ts)
//
// Anything else throws a SnitchEgressBlocked error. The caller can pass
// an `onBlocked` callback to report the violation to whatever logger
// they're using (`core.error` in the GitHub Action, `console.error` in
// the CLI). Customers can audit the request set in their workflow log.

// Exact hostnames that are always allowed.
const SNITCH_HOSTS = new Set<string>([
  "snitchplugin.com",
  "snitch.live",
  "api.osv.dev",
  // GitHub APIs (Octokit + actions/* implementations call these directly)
  "api.github.com",
  "uploads.github.com",
  "objects.githubusercontent.com",
  "raw.githubusercontent.com",
  "codeload.github.com",
  "www.githubstatus.com",
]);

// Suffix patterns that match dynamically-generated hostnames. GitHub Actions
// allocates per-run storage backends with hostnames like
// `productionresultssa12.blob.core.windows.net` — we can't enumerate every
// instance, so suffix-match the trusted parent zones.
const SNITCH_HOST_SUFFIXES = [
  ".actions.githubusercontent.com",  // results-receiver, pipelines, etc.
  ".blob.core.windows.net",          // GitHub Actions artifact storage
  ".githubusercontent.com",          // any githubusercontent subdomain
];

// Per-provider host allowlist. Only the provider the customer selected
// gets unblocked, so a compromised dep can't switch providers and exfil
// through one we didn't vet.
const PROVIDER_HOSTS: Record<string, string[]> = {
  openrouter: ["openrouter.ai"],
  anthropic: ["api.anthropic.com"],
  openai: ["api.openai.com"],
  google: ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
  copilot: [
    "models.inference.ai.azure.com",
    "models.github.ai",
    "api.githubcopilot.com",
  ],
};

export class SnitchEgressBlocked extends Error {
  readonly host: string;
  readonly url: string;
  constructor(host: string, url: string) {
    super(
      `[snitch-egress] Blocked outbound request to '${host}' — not on the Snitch allowlist. ` +
        `If this is legitimate, file an issue at https://github.com/snitchplugin/snitch-github-action/issues. ` +
        `If you didn't expect this request, you may have a compromised dependency. Full URL: ${url}`,
    );
    this.name = "SnitchEgressBlocked";
    this.host = host;
    this.url = url;
  }
}

let installed = false;

/**
 * Install the egress allowlist by replacing the global `fetch` with a
 * wrapper that checks every URL's hostname against the allowlist before
 * delegating. Idempotent — safe to call multiple times. Should be called
 * exactly once at the very top of the Action's main(), before any other
 * code path that might issue a fetch.
 *
 * @param provider - the selected AI provider name (`openrouter`, `anthropic`, etc.)
 * @param extraHosts - any additional hosts to allow (e.g. `SNITCH_API_BASE` override for dev)
 */
export interface EgressOptions {
  /** AI provider name to derive the provider-specific host allowlist from. */
  provider?: string;
  /** Additional hosts to allow (e.g. SNITCH_API_BASE override for dev). */
  extraHosts?: string[];
  /** Called once per blocked request before the throw. Use this to surface
   *  the violation to your logger (core.error in the Action, console.error
   *  in the CLI). Default: silent (the throw still propagates). */
  onBlocked?: (msg: string) => void;
}

export function installEgressAllowlist(opts: EgressOptions = {}): void {
  if (installed) return;
  installed = true;

  const allowed = new Set<string>(SNITCH_HOSTS);
  const providerHosts = opts.provider ? PROVIDER_HOSTS[opts.provider] : undefined;
  if (providerHosts) {
    for (const h of providerHosts) allowed.add(h);
  }
  for (const h of opts.extraHosts ?? []) {
    try {
      const u = new URL(h.startsWith("http") ? h : `https://${h}`);
      allowed.add(u.hostname);
    } catch {
      // ignore malformed entries silently — empty SNITCH_API_BASE etc.
    }
  }

  const originalFetch = globalThis.fetch;
  const wrapper = async (
    input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    let url: string;
    if (typeof input === "string") url = input;
    else if (input instanceof URL) url = input.toString();
    else url = input.url;
    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      // Non-URL input — let the original fetch handle it (it'll throw too).
      return originalFetch(input as Parameters<typeof fetch>[0], init);
    }
    if (!isAllowed(host, allowed)) {
      const err = new SnitchEgressBlocked(host, url);
      opts.onBlocked?.(err.message);
      throw err;
    }
    return originalFetch(input as Parameters<typeof fetch>[0], init);
  };

  // Preserve any properties Node attached to fetch.
  globalThis.fetch = wrapper as typeof fetch;
}

/** For tests only — restore the original fetch. */
export function _resetEgressForTests(): void {
  installed = false;
}

function isAllowed(host: string, exact: Set<string>): boolean {
  if (exact.has(host)) return true;
  for (const suffix of SNITCH_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return true;
  }
  return false;
}
