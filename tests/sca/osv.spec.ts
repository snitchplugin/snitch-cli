import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { lookupVulnerabilities } from "../../src/_shared/sca/osv.js";
import type { DepEntry } from "../../src/_shared/sca/types.js";

function mkDep(over: Partial<DepEntry> = {}): DepEntry {
  return {
    ecosystem: "npm",
    name: "lodash",
    version: "4.17.20",
    manifestPath: "package.json",
    ...over,
  };
}

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  }) as unknown as Response;
}

const HIGH_VULN = {
  id: "GHSA-jf85-cpcp-j695",
  aliases: ["CVE-2019-10744"],
  summary: "Prototype Pollution in lodash",
  details: "Versions of lodash prior to 4.17.12 are vulnerable...",
  database_specific: { severity: "HIGH", cwe_ids: ["CWE-1321", "CWE-20"] },
  references: [
    { type: "WEB", url: "https://example.com/other" },
    { type: "ADVISORY", url: "https://github.com/lodash/lodash/security/advisories/GHSA-jf85-cpcp-j695" },
    { type: "WEB", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744" },
  ],
  affected: [
    {
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "0" }, { fixed: "4.17.12" }],
        },
      ],
    },
  ],
};

let cacheDir: string;

beforeEach(() => {
  cacheDir = mkdtempSync(join(tmpdir(), "osv-test-"));
});

afterEach(() => {
  rmSync(cacheDir, { recursive: true, force: true });
});

describe("lookupVulnerabilities", () => {
  it("returns one finding for a single dep with one HIGH vuln", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ vulns: [HIGH_VULN] }));
    const findings = await lookupVulnerabilities([mkDep()], { cacheDir, fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.vuln.id).toBe("GHSA-jf85-cpcp-j695");
    expect(findings[0]?.vuln.severity).toBe("HIGH");
    expect(findings[0]?.vuln.cwe).toBe("CWE-1321");
    expect(findings[0]?.vuln.affectedRanges).toBe("< 4.17.12");
    // GHSA URL should sort to front of references list.
    expect(findings[0]?.vuln.references[0]).toContain("github.com/lodash/lodash/security/advisories");
  });

  it("returns findings only for the dep that has vulns (3 deps, one vulnerable)", async () => {
    const fetchImpl = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { package: { name: string } };
      if (body.package.name === "lodash") return jsonResponse({ vulns: [HIGH_VULN] });
      return jsonResponse({});
    });
    const deps = [
      mkDep({ name: "lodash" }),
      mkDep({ name: "react", version: "18.0.0" }),
      mkDep({ name: "express", version: "4.18.0" }),
    ];
    const findings = await lookupVulnerabilities(deps, { cacheDir, fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.dep.name).toBe("lodash");
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("hits the cache on a second call for the same dep", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ vulns: [HIGH_VULN] }));
    await lookupVulnerabilities([mkDep()], { cacheDir, fetchImpl });
    await lookupVulnerabilities([mkDep()], { cacheDir, fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("re-fetches when cache TTL has expired", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ vulns: [HIGH_VULN] }));
    await lookupVulnerabilities([mkDep()], { cacheDir, fetchImpl, cacheTtlMs: 1 });
    await new Promise((r) => setTimeout(r, 10));
    await lookupVulnerabilities([mkDep()], { cacheDir, fetchImpl, cacheTtlMs: 1 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  describe("CVSS score parsing falls back when database_specific.severity is absent", () => {
    const cases: Array<{ score: string; want: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" }> = [
      { score: "9.8", want: "CRITICAL" },
      { score: "7.5", want: "HIGH" },
      { score: "4.5", want: "MODERATE" },
      { score: "2.0", want: "LOW" },
    ];
    for (const { score, want } of cases) {
      it(`maps CVSS ${score} to ${want}`, async () => {
        const vuln = {
          id: `GHSA-test-${score}`,
          severity: [{ type: "CVSS_V3", score }],
          references: [],
          affected: [],
        };
        const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ vulns: [vuln] }));
        const dep = mkDep({ name: `pkg-${score}`, version: "1.0.0" });
        const findings = await lookupVulnerabilities([dep], { cacheDir, fetchImpl });
        expect(findings[0]?.vuln.severity).toBe(want);
      });
    }
  });

  it("returns findings for healthy deps even if one request errors out", async () => {
    const fetchImpl = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { package: { name: string } };
      if (body.package.name === "broken") throw new Error("network down");
      if (body.package.name === "lodash") return jsonResponse({ vulns: [HIGH_VULN] });
      return jsonResponse({});
    });
    const deps = [
      mkDep({ name: "broken", version: "1.0.0" }),
      mkDep({ name: "lodash" }),
      mkDep({ name: "clean", version: "2.0.0" }),
    ];
    const findings = await lookupVulnerabilities(deps, { cacheDir, fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.dep.name).toBe("lodash");
  });

  it("respects the concurrency cap on in-flight requests", async () => {
    let inFlight = 0;
    let peak = 0;
    let started = 0;
    const releases: Array<() => void> = [];
    const fetchImpl = vi.fn().mockImplementation(() => {
      inFlight++;
      started++;
      peak = Math.max(peak, inFlight);
      return new Promise<Response>((resolve) => {
        releases.push(() => {
          inFlight--;
          resolve(jsonResponse({}));
        });
      });
    });

    const total = 10;
    const deps = Array.from({ length: total }, (_, i) =>
      mkDep({ name: `pkg-${i}`, version: "1.0.0" })
    );
    const promise = lookupVulnerabilities(deps, { cacheDir, fetchImpl, concurrency: 3 });

    // Drain pending requests in waves. Each release lets a worker finish, write
    // its cache, then call fetchImpl again (which pushes a new release).
    while (started < total || releases.length > 0) {
      if (releases.length === 0) {
        // Yield until at least one worker has registered its release callback.
        await new Promise((r) => setImmediate(r));
        continue;
      }
      const release = releases.shift()!;
      release();
      await new Promise((r) => setImmediate(r));
    }
    await promise;

    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(0);
    expect(fetchImpl).toHaveBeenCalledTimes(10);
  });
});
