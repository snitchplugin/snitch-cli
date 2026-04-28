// High-level entry point for the DCA pass. Mirrors sca/scan.ts:
// orchestrate parsers + analyzers, return Snitch Findings ready to merge
// with AI / SCA findings in the main scan flow.

import type { Finding, Severity } from "../providers/types.js";
import type { DcaFinding, DepEntry, Ecosystem } from "./types.js";
import { routeExtractor } from "./discover.js";
import { extractDirectDeps, analyzeUnusedDeps } from "./unused-deps.js";
import { analyzeDeadFiles } from "./dead-files.js";

export interface DcaScanInput {
  files: { path: string; content: string }[];
  /** Optional. Accepted for forward compat; not currently used as primary
   *  input — we re-extract direct deps from manifests internally so we
   *  only flag what a developer can actually remove. */
  deps?: DepEntry[];
}

export interface DcaScanResult {
  findings: Finding[];
  unusedDeps: number;
  deadFiles: number;
}

export async function runDcaScan(input: DcaScanInput): Promise<DcaScanResult> {
  // 1. Walk source files, extract imports per ecosystem.
  const importsByEcosystem = new Map<Ecosystem, Set<string>>();
  // Map an extractor's first ecosystem mapping. The extractors return raw
  // names; the analyzer normalizes per-eco for matching. We bucket by which
  // SCA ecosystem their imports could match against.
  const EXTRACTOR_TO_ECOSYSTEMS: Record<string, Ecosystem[]> = {
    ".ts": ["npm"], ".tsx": ["npm"], ".js": ["npm"], ".jsx": ["npm"], ".mjs": ["npm"], ".cjs": ["npm"],
    ".py": ["PyPI"],
    ".go": ["Go"],
    ".rs": ["crates.io"],
    ".rb": ["RubyGems"],
    ".java": ["Maven"], ".kt": ["Maven"],
    ".php": ["Packagist"],
    ".cs": ["NuGet"],
  };

  for (const file of input.files) {
    const extr = routeExtractor(file.path);
    if (!extr) continue;
    const ext = (file.path.match(/\.[^./]+$/) ?? [""])[0].toLowerCase();
    const ecosystems = EXTRACTOR_TO_ECOSYSTEMS[ext] ?? [];
    let imps: Set<string>;
    try {
      imps = extr.extract(file.content, file.path);
    } catch {
      continue; // extractor crash on malformed input — skip the file
    }
    for (const eco of ecosystems) {
      const bucket = importsByEcosystem.get(eco) ?? new Set<string>();
      for (const i of imps) bucket.add(i);
      importsByEcosystem.set(eco, bucket);
    }
  }

  // 2. Direct deps from manifests.
  const directDeps = extractDirectDeps(input.files);

  // 3. Unused-dep analysis.
  const unusedFindings = analyzeUnusedDeps({ deps: directDeps, importsByEcosystem });

  // 4. Dead-file analysis.
  const deadFindings = analyzeDeadFiles({ files: input.files });

  // 5. Map to Snitch Finding shape.
  const findings: Finding[] = [
    ...unusedFindings.map(toFinding),
    ...deadFindings.map(toFinding),
  ];
  return {
    findings,
    unusedDeps: unusedFindings.length,
    deadFiles: deadFindings.length,
  };
}

function toFinding(d: DcaFinding): Finding {
  if (d.subkind === "unused-dep") {
    const eco = d.ecosystem ?? "npm";
    const name = d.packageName ?? "unknown";
    return {
      title: `Unused dependency: \`${eco}/${name}\` declared in \`${d.path}\``,
      severity: "Low" as Severity,
      file: d.path,
      evidence: `${eco} dep \`${name}\` declared but no \`import\` / \`require\` / \`use\` reference found in source`,
      risk: "Unused dependencies expand supply chain attack surface, slow installs, and can carry CVEs you never benefit from. Removing them is free defense-in-depth.",
      fix: `Remove \`${name}\` from ${d.path}.`,
      confidence: "high",
      metadata: {
        kind: "dca",
        subkind: "unused-dep",
        ecosystem: eco,
        packageName: name,
        manifestPath: d.path,
      },
    };
  }
  // dead-file
  const isAggregate = d.path === "(repository)";
  const title = isAggregate
    ? `Dead-file scan disabled: ${d.packageName ?? "too many candidates"}`
    : `Dead file: \`${d.path}\` is not imported anywhere`;
  const risk = isAggregate
    ? "More than 50 files appeared to be unreached from any entry point. Suppressing detail to avoid overwhelming the report; common cause is a project layout we don't yet recognize as an entry-point convention."
    : "Dead code still ships to users. If it later contains a vulnerability, attackers can still hit it via stale routes, lazy-loaded paths, or framework auto-discovery you forgot about.";
  const fix = isAggregate
    ? "Confirm the project's entry-point convention (Next.js pages, Django views, custom router) is in our list, or set `include-dead-code: false` to silence this section."
    : "Delete the file or wire it up by importing it from where it should be used.";
  return {
    title,
    severity: "Low" as Severity,
    file: isAggregate ? "" : d.path,
    evidence: isAggregate ? "" : `Source file with zero inbound imports`,
    risk,
    fix,
    confidence: "medium",
    metadata: {
      kind: "dca",
      subkind: "dead-file",
    },
  };
}
