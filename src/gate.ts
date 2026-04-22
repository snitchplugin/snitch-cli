import {
  fetchMethodology,
  flattenMethodology,
} from "../../snitch-github/src/methodology.js";
import type {
  AnalyzeArgs,
  AnalyzeResult,
  Finding,
  Severity,
} from "../../snitch-github/src/providers/types.js";
import { listAllTrackedPaths, loadFiles } from "./git.js";

const PI_CATEGORY_ID = 68; // skills/snitch/categories/68-agent-prompt-injection.md
const METHODOLOGY_VERSION = process.env.SNITCH_METHODOLOGY_VERSION ?? "v7.1.0";

export interface GateArgs {
  repoRoot: string;
  licenseKey: string;
  provider: {
    apiKey: string;
    analyze(args: AnalyzeArgs): Promise<AnalyzeResult>;
    name: string;
    defaultModel: string;
  };
  model: string;
}

export interface GateResult {
  pass: boolean;
  findings: Finding[];
  summary: string;
  fileCount: number;
}

const BLOCKING: ReadonlySet<Severity> = new Set(["Critical", "High"]);

/**
 * Pure gate: runs a category-68-only pass over the repo's tracked files and
 * returns whether the repo is safe to feed into the main scan. Prints
 * nothing; the caller decides how loudly to fail.
 */
export async function runGate(args: GateArgs): Promise<GateResult> {
  const paths = listAllTrackedPaths(args.repoRoot);
  const files = loadFiles(paths, null, args.repoRoot);

  if (files.length === 0) {
    // Nothing to scan means nothing to inject through. Pass.
    return { pass: true, findings: [], summary: "No readable files in repo.", fileCount: 0 };
  }

  const bundle = await fetchMethodology(args.licenseKey, METHODOLOGY_VERSION, [
    PI_CATEGORY_ID,
  ]);
  const methodology = flattenMethodology(bundle);

  const analysis = await args.provider.analyze({
    apiKey: args.provider.apiKey,
    model: args.model,
    methodology,
    files,
  });

  const blocking = analysis.findings.filter((f) => BLOCKING.has(f.severity));
  return {
    pass: blocking.length === 0,
    findings: analysis.findings,
    summary: analysis.summary,
    fileCount: files.length,
  };
}

/**
 * Human-readable block message for a failed gate. Caller prints this to
 * stderr and exits 1 (unless --force-after-injection was passed).
 */
export function formatBlockMessage(result: GateResult, cloneDir: string): string {
  const lines: string[] = [];
  lines.push("");
  lines.push("=== Snitch gate: prompt-injection risk detected ===");
  lines.push("");
  lines.push(
    `The repository at ${cloneDir} triggered category 68 (prompt injection).`
  );
  lines.push(
    "Main scan is blocked so an adversarial repo cannot hijack the scanner."
  );
  lines.push("");

  const blocking = result.findings.filter((f) => BLOCKING.has(f.severity));
  lines.push(`Blocking findings: ${blocking.length}`);
  for (const f of blocking) {
    const loc = f.line ? `${f.file}:${f.line}` : f.file;
    lines.push(`  [${f.severity}] ${f.title}`);
    lines.push(`    at ${loc}`);
    lines.push(`    ${f.risk}`);
  }
  lines.push("");
  lines.push(`Clone preserved at: ${cloneDir}`);
  lines.push(
    "Inspect it, remove the payload, and rerun. Or pass --force-after-injection to run the main scan anyway."
  );
  lines.push("");
  return lines.join("\n");
}
