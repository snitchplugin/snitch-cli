// High-level entry point used by the Action / CLI / any caller.
// Walks the in-memory file list, parses every supported manifest,
// queries OSV for vulnerabilities, and returns the result as Snitch
// Findings — same shape the AI batches produce — so the rest of the
// pipeline (SARIF, sticky comment, inline review, artifact) treats
// dependency vulns as first-class findings without special casing.

import { discoverManifests } from "./discover.js";
import { lookupVulnerabilities, type OsvFinding, type OsvClientOptions } from "./osv.js";
import type { DepEntry } from "./types.js";
import type { Finding, Severity } from "../providers/types.js";

const SEVERITY_MAP: Record<NonNullable<OsvFinding["vuln"]["severity"]>, Severity> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MODERATE: "Medium",
  LOW: "Low",
  UNKNOWN: "Medium",
};

export interface ScaScanInput {
  files: { path: string; content: string }[];
  /** Optional. Forwarded to the OSV client (cache dir, concurrency, etc.). */
  osvOptions?: OsvClientOptions;
}

export interface ScaScanResult {
  /** All deps discovered across every supported manifest. */
  deps: DepEntry[];
  /** Subset of deps that had at least one OSV match. */
  vulnFindings: OsvFinding[];
  /** Snitch-shape Findings ready to merge with AI findings. */
  findings: Finding[];
}

export async function runScaScan(input: ScaScanInput): Promise<ScaScanResult> {
  const matches = discoverManifests(input.files);
  const deps: DepEntry[] = [];
  for (const m of matches) {
    try {
      deps.push(...m.parser.parse(m.file.content, m.file.path));
    } catch {
      // A malformed lockfile shouldn't kill the whole scan.
      // Findings from the rest of the manifests still ship.
    }
  }
  if (deps.length === 0) {
    return { deps, vulnFindings: [], findings: [] };
  }

  const vulnFindings = await lookupVulnerabilities(deps, input.osvOptions);
  const findings = vulnFindings.map(toFinding);
  return { deps, vulnFindings, findings };
}

// Strip the chars that have semantic meaning in markdown ([](),!,<,>,*,_,`)
// from any free-form text we splice into the sticky comment. We DO NOT
// touch version-range tokens like `>=`, `<`, `,`, dots — those are
// handled by always rendering ranges inside a code fence (downstream).
function safeText(s: string, max = 200): string {
  // Collapse newlines first (advisory markdown headings break our layout).
  let out = s.replace(/\r?\n+/g, " ").replace(/\s+/g, " ").trim();
  // Strip markdown-active chars only (preserve numbers, dashes, dots).
  out = out.replace(/[`*_<>!\[\]]/g, "");
  // Drop trailing punctuation noise that often gets through.
  out = out.replace(/[\s.,;:]+$/, "");
  if (out.length > max) out = out.slice(0, max - 1).trimEnd() + "…";
  return out;
}

function safeId(s: string): string {
  // IDs are GHSA-xxxx / CVE-NNNN-NNNN style; strip anything that isn't.
  return s.replace(/[^A-Za-z0-9._\-:/]/g, "");
}

function pickAdvisoryUrl(refs: string[], vulnId: string): string | undefined {
  // Prefer the GHSA page (richest UI), then NVD, then any reference.
  const safe = refs.filter((u) => /^https?:\/\//.test(u));
  const ghsa = safe.find((u) => /github\.com\/(?:advisories|.*\/security\/advisories)\//.test(u));
  if (ghsa) return ghsa;
  const nvd = safe.find((u) => /nvd\.nist\.gov\/vuln\/detail\//.test(u));
  if (nvd) return nvd;
  if (vulnId.startsWith("GHSA-")) return `https://github.com/advisories/${vulnId}`;
  if (vulnId.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${vulnId}`;
  return safe[0];
}

function toFinding(of: OsvFinding): Finding {
  const sev: Severity = SEVERITY_MAP[of.vuln.severity ?? "UNKNOWN"];
  const id = safeId(of.vuln.id);
  // The advisory summary is the one sentence we want on the comment.
  // The full `details` text stays out of the finding entirely — readers
  // click through to the advisory for the full write-up.
  const summary = safeText(of.vuln.summary, 200);
  const advisoryUrl = pickAdvisoryUrl(of.vuln.references, id);
  // Version ranges include `<`, `>`, `=`, `,` — keep them as-is inside
  // a backtick code fence so markdown doesn't try to interpret anything.
  const fixedRange = of.vuln.affectedRanges ? `\`${of.vuln.affectedRanges.replace(/`/g, "")}\`` : "";
  const fix = fixedRange
    ? `Upgrade out of the affected range ${fixedRange}.`
    : `Upgrade to a non-vulnerable version. See ${advisoryUrl ?? "the advisory"}.`;

  // Compact title: package + one-line summary, with the canonical id at the end.
  // Renderer uses metadata to group by package, so the title doesn't need
  // every alias / CWE shoehorned in.
  const title = `${of.dep.name}@${of.dep.version}: ${summary || id}`;

  return {
    title,
    severity: sev,
    file: of.dep.manifestPath,
    evidence: `${of.dep.ecosystem} package ${of.dep.name}@${of.dep.version}`,
    risk: summary || `Vulnerability ${id} affects this version.`,
    fix,
    cwe: of.vuln.cwe ? safeId(of.vuln.cwe) : undefined,
    confidence: "high",
    metadata: {
      kind: "sca",
      ecosystem: of.dep.ecosystem,
      packageName: of.dep.name,
      packageVersion: of.dep.version,
      vulnId: id,
      advisoryUrl,
      summary: summary || `Vulnerability ${id}`,
      fixedVersion: of.vuln.affectedRanges,
    },
  };
}
