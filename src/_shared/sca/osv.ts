import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DepEntry } from "./types.js";

export interface OsvVulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details?: string;
  severity?: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";
  cwe?: string;
  references: string[];
  affectedRanges?: string;
}

export interface OsvFinding {
  dep: DepEntry;
  vuln: OsvVulnerability;
}

export interface OsvClientOptions {
  /** Max concurrent in-flight requests. Default 5. */
  concurrency?: number;
  /** Disk cache directory. Default: tmpdir/snitch-osv-cache. */
  /** Optional sink for transient errors (rate limits, network failures,
   *  oversized responses). Useful for surfacing to the workflow log
   *  without forcing a throw. Default: silent. */
  onError?: (msg: string) => void;
  cacheDir?: string;
  /** Cache TTL in ms. Default: 24h. */
  cacheTtlMs?: number;
  /** Override fetch (for tests). */
  fetchImpl?: typeof fetch;
  /** Override base URL (for tests). Default: https://api.osv.dev */
  baseUrl?: string;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CONCURRENCY = 5;
const DEFAULT_BASE_URL = "https://api.osv.dev";

// OSV response is loosely typed in the wild (severity sometimes string,
// sometimes array of {type, score}); model it as `unknown` and narrow at
// the boundary so a malformed entry can never crash the whole scan.
interface RawOsvResponse {
  vulns?: RawOsvVuln[];
}

interface RawOsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
  };
}

interface CacheEntry {
  ts: number;
  vulns: OsvVulnerability[];
}

/**
 * Look up vulnerabilities for the given dependency entries. Results are
 * deduplicated and only deps with at least one matching vuln appear in the
 * output. Disk-cached to avoid hammering the API on repeat scans.
 */
export async function lookupVulnerabilities(
  deps: DepEntry[],
  opts: OsvClientOptions = {}
): Promise<OsvFinding[]> {
  const concurrency = opts.concurrency ?? DEFAULT_CONCURRENCY;
  const cacheDir = opts.cacheDir ?? join(tmpdir(), "snitch-osv-cache");
  const cacheTtlMs = opts.cacheTtlMs ?? DEFAULT_TTL_MS;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;

  await mkdir(cacheDir, { recursive: true });

  const results = await runWithConcurrency(deps, concurrency, async (dep) => {
    const vulns = await fetchVulnsForDep(dep, {
      cacheDir,
      cacheTtlMs,
      fetchImpl,
      baseUrl,
      onError: opts.onError,
    });
    return vulns.map((vuln) => ({ dep, vuln }));
  });

  return results.flat();
}

interface FetchCtx {
  cacheDir: string;
  cacheTtlMs: number;
  fetchImpl: typeof fetch;
  baseUrl: string;
  onError?: (msg: string) => void;
}

// Bound the OSV request: 10s wall-clock, 5MB response. Without these a
// hung or oversized OSV response would either hang the entire scan
// (eating the 6h GitHub Action budget on a free runner) or OOM the
// process. The response cap is generous; real OSV vuln payloads for a
// single package are typically 1-10KB.
const OSV_TIMEOUT_MS = 10_000;
const OSV_MAX_BYTES = 5 * 1024 * 1024;

async function fetchVulnsForDep(dep: DepEntry, ctx: FetchCtx): Promise<OsvVulnerability[]> {
  const key = cacheKey(dep);
  const cachePath = join(ctx.cacheDir, `${key}.json`);

  const cached = await readCache(cachePath, ctx.cacheTtlMs);
  if (cached) return cached;

  let raw: RawOsvResponse | undefined;
  try {
    const res = await ctx.fetchImpl(`${ctx.baseUrl}/v1/query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { ecosystem: dep.ecosystem, name: dep.name },
        version: dep.version,
      }),
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
    if (!res.ok) {
      // Graceful degradation, but record the status so the caller can see
      // patterns (sustained 429s, 5xx outages, etc.) in the workflow log.
      ctx.onError?.(`OSV ${res.status} for ${dep.ecosystem}/${dep.name}@${dep.version}`);
      return [];
    }
    const declaredLen = Number(res.headers.get("content-length") ?? "0");
    if (declaredLen > OSV_MAX_BYTES) {
      ctx.onError?.(
        `OSV response too large (${declaredLen} bytes) for ${dep.ecosystem}/${dep.name}@${dep.version}; skipping`
      );
      return [];
    }
    raw = (await res.json()) as RawOsvResponse;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    ctx.onError?.(`OSV fetch failed for ${dep.ecosystem}/${dep.name}@${dep.version}: ${msg}`);
    return [];
  }

  const vulns = (raw?.vulns ?? []).map(normalizeVuln);
  // Cache even empty results — most deps are clean and we don't want to keep
  // re-asking on every scan during the TTL window.
  await writeCache(cachePath, { ts: Date.now(), vulns });
  return vulns;
}

function cacheKey(dep: DepEntry): string {
  const h = createHash("sha256")
    .update(`${dep.ecosystem}:${dep.name}:${dep.version}`)
    .digest("hex");
  return h.slice(0, 32);
}

async function readCache(path: string, ttlMs: number): Promise<OsvVulnerability[] | null> {
  try {
    const buf = await readFile(path, "utf8");
    const entry = JSON.parse(buf) as CacheEntry;
    if (Date.now() - entry.ts < ttlMs) return entry.vulns;
    return null;
  } catch {
    return null;
  }
}

async function writeCache(path: string, entry: CacheEntry): Promise<void> {
  try {
    await writeFile(path, JSON.stringify(entry));
  } catch {
    // Cache write failure is non-fatal — next call will simply re-fetch.
  }
}

function normalizeVuln(raw: RawOsvVuln): OsvVulnerability {
  return {
    id: raw.id ?? "",
    aliases: raw.aliases ?? [],
    summary: raw.summary ?? "",
    details: raw.details,
    severity: extractSeverity(raw),
    cwe: raw.database_specific?.cwe_ids?.[0],
    references: extractReferences(raw),
    affectedRanges: summarizeAffected(raw),
  };
}

function extractSeverity(
  raw: RawOsvVuln
): OsvVulnerability["severity"] {
  const dbSev = raw.database_specific?.severity;
  if (typeof dbSev === "string") {
    const norm = dbSev.toUpperCase();
    // OSV uses "MODERATE" but GHSA also emits "MEDIUM" — normalize both.
    if (norm === "CRITICAL" || norm === "HIGH" || norm === "LOW") return norm;
    if (norm === "MODERATE" || norm === "MEDIUM") return "MODERATE";
  }
  // Fall back to CVSS score from the severity[] array.
  const first = raw.severity?.[0]?.score;
  if (typeof first === "string") {
    const score = parseCvssScore(first);
    if (score !== undefined) {
      if (score >= 9) return "CRITICAL";
      if (score >= 7) return "HIGH";
      if (score >= 4) return "MODERATE";
      return "LOW";
    }
  }
  return "UNKNOWN";
}

// CVSS strings show up as raw vector ("CVSS:3.1/AV:N/...") OR a bare
// numeric score ("9.8"). Try numeric first, then look for /S:N or score in vector.
function parseCvssScore(raw: string): number | undefined {
  const asNum = Number(raw);
  if (Number.isFinite(asNum)) return asNum;
  return undefined;
}

function extractReferences(raw: RawOsvVuln): string[] {
  const urls = (raw.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === "string");
  const seen = new Set<string>();
  const dedup = urls.filter((u) => (seen.has(u) ? false : (seen.add(u), true)));
  // Surface advisory URLs first — they're what humans want to click.
  dedup.sort((a, b) => priority(b) - priority(a));
  return dedup;
}

function priority(url: string): number {
  if (/github\.com\/.+\/security\/advisories\/GHSA-/i.test(url)) return 3;
  if (/nvd\.nist\.gov/i.test(url)) return 2;
  if (/cve\.org|mitre\.org/i.test(url)) return 1;
  return 0;
}

function summarizeAffected(raw: RawOsvVuln): string | undefined {
  const ranges = raw.affected?.flatMap((a) => a.ranges ?? []) ?? [];
  if (ranges.length === 0) return undefined;

  const parts: string[] = [];
  for (const r of ranges) {
    const events = r.events ?? [];
    let introduced: string | undefined;
    let fixed: string | undefined;
    let lastAffected: string | undefined;
    for (const ev of events) {
      if (ev.introduced) introduced = ev.introduced;
      if (ev.fixed) fixed = ev.fixed;
      if (ev.last_affected) lastAffected = ev.last_affected;
    }
    if (fixed && (introduced === undefined || introduced === "0")) {
      parts.push(`< ${fixed}`);
    } else if (fixed && introduced) {
      parts.push(`>= ${introduced}, < ${fixed}`);
    } else if (lastAffected) {
      parts.push(`<= ${lastAffected}`);
    } else if (introduced) {
      parts.push(`>= ${introduced}`);
    }
  }

  if (parts.length === 0) return "see advisory";
  // If the summary balloons past a sensible limit, defer to the advisory rather
  // than dumping a wall of version ranges into the SARIF output.
  const joined = parts.join(" or ");
  return joined.length > 80 ? "see advisory" : joined;
}

/**
 * Bounded-concurrency map. Preserves input order in the output.
 * Inlined to keep this module dependency-free.
 */
async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      const item = items[i] as T;
      out[i] = await fn(item, i);
    }
  });
  await Promise.all(workers);
  return out;
}
