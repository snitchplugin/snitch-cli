import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import * as path from "node:path";
import type {
  AnalyzeArgs,
  AnalyzeResult,
  Finding,
} from "../../snitch-github/src/providers/types.js";
import type { MethodologyBundle } from "../../snitch-github/src/methodology.js";
import { flattenMethodology } from "../../snitch-github/src/methodology.js";
import { runSubprocess } from "./providers/local-cli.js";

// ─── Shape ──────────────────────────────────────────────────────────
// An orchestrated scan has three phases:
//
//   1. Recon. One AI call on a small set of top-level config files.
//      Output: stack summary + a plan of 1-3 specialists.
//
//   2. Dispatch. For each specialist, filter the candidate files to
//      the globs the specialist claimed, fetch a methodology slice
//      containing only the categories that specialist needs, and run
//      the adapter. Specialists run in parallel (up to concurrency).
//
//   3. Merge. Collect findings across all specialists, dedupe on
//      file:line:title, return as a single AnalyzeResult.
//
// If recon fails or returns bad JSON, the caller should fall back to
// the existing batched scan.

export interface SpecialistPlan {
  name: string;
  categories: number[];
  files: string[]; // glob patterns, relative to repo root
  rationale: string;
}

export interface OrchestratorPlan {
  stack: string;
  specialists: SpecialistPlan[];
}

type AnyAdapter = {
  name: string;
  defaultModel: string;
  analyze(args: AnalyzeArgs): Promise<AnalyzeResult>;
};

// Provider → max concurrent AI calls. Hosted APIs rate-limit aggressively;
// local subprocesses are only bounded by the user's machine.
const CONCURRENCY_BY_PROVIDER: Record<string, number> = {
  "local-cli": 3,
  openrouter: 3,
  anthropic: 2,
  openai: 2,
  google: 2,
  copilot: 2,
};

function concurrencyFor(provider: string): number {
  return CONCURRENCY_BY_PROVIDER[provider] ?? 2;
}

// ─── Recon: which files to hand the orchestrator ────────────────────

const RECON_CANDIDATES = [
  "package.json",
  "tsconfig.json",
  "next.config.js",
  "next.config.ts",
  "next.config.mjs",
  "vite.config.js",
  "vite.config.ts",
  "wrangler.toml",
  "wrangler.jsonc",
  "drizzle.config.ts",
  "drizzle.config.js",
  "astro.config.mjs",
  "remix.config.js",
  "nuxt.config.ts",
  "svelte.config.js",
  "Gemfile",
  "go.mod",
  "Cargo.toml",
  "pyproject.toml",
  "requirements.txt",
  "composer.json",
  "pom.xml",
  "build.gradle",
  "supabase/config.toml",
  ".env.example",
  "README.md",
  "middleware.ts",
  "middleware.js",
];

const RECON_WORKFLOWS_DIR = ".github/workflows";

const MAX_RECON_FILE_CHARS = 4000;
const MAX_RECON_TOTAL_CHARS = 40000;

/**
 * Gather a small, representative slice of the repo for the recon agent.
 * Top-level config + CI workflows. Never includes source code.
 */
export function collectReconFiles(root: string): AnalyzeArgs["files"] {
  const out: AnalyzeArgs["files"] = [];
  let total = 0;

  function add(rel: string, abs: string) {
    if (total >= MAX_RECON_TOTAL_CHARS) return;
    if (!existsSync(abs)) return;
    let content: string;
    try {
      content = readFileSync(abs, "utf-8").slice(0, MAX_RECON_FILE_CHARS);
    } catch {
      return;
    }
    total += content.length;
    out.push({ path: rel, content, patch: "" });
  }

  for (const name of RECON_CANDIDATES) {
    add(name, path.join(root, name));
  }

  const wfDir = path.join(root, RECON_WORKFLOWS_DIR);
  if (existsSync(wfDir)) {
    try {
      const entries = statSync(wfDir).isDirectory() ? readdirSync(wfDir) : [];
      for (const f of entries) {
        if (f.endsWith(".yml") || f.endsWith(".yaml")) {
          add(`${RECON_WORKFLOWS_DIR}/${f}`, path.join(wfDir, f));
        }
      }
    } catch {
      // ignore
    }
  }

  return out;
}

// ─── Recon prompt ───────────────────────────────────────────────────

function reconPrompt(
  bundle: MethodologyBundle,
  reconFiles: AnalyzeArgs["files"],
  maxSpecialists: number
): string {
  const catalog = bundle.categories
    .map((c) => {
      const firstLine = (c.body.split("\n").find((l) => l.trim()) ?? "").slice(0, 140);
      return `- [${c.id}] ${c.title}: ${firstLine}`;
    })
    .join("\n");

  const configs = reconFiles
    .map((f) => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join("\n\n");

  return `You are the security audit orchestrator for Snitch. Your one job: given a repo's top-level config files, decide which security specialists to dispatch.

Return ONLY valid JSON matching this schema (no prose, no markdown fences):
{
  "stack": "One sentence describing what this repo is (e.g. 'Next.js 15 + Supabase + Stripe webhooks on Cloudflare Workers')",
  "specialists": [
    {
      "name": "auth-specialist",
      "categories": [3, 7, 14],
      "files": ["app/api/auth/**", "middleware.ts", "lib/auth.ts"],
      "rationale": "Better-Auth + Next.js middleware; auth flows are top risk surface"
    }
  ]
}

Rules:
1. Pick 1 to ${maxSpecialists} specialists based on what the stack actually needs. Fewer is fine if the repo is small or focused.
2. Each specialist must claim NON-OVERLAPPING file globs.
3. Category IDs must come from the catalog below (1-68 range). Pick the most relevant 3-8 per specialist.
4. Prefer depth over breadth: 3 specialists going deep beats 6 being shallow.
5. Every specialist name should be descriptive: auth-specialist, secrets-specialist, platform-specialist, injection-specialist, crypto-specialist, ai-specialist, supply-chain-specialist, access-control-specialist.
6. File globs use minimatch syntax. ** matches any directories. Use globs broad enough to cover the specialist's surface.

## CATEGORY CATALOG (1-68, pick relevant ones per specialist)

${catalog}

## CONFIG FILES FOR RECON

${configs}
`;
}

// ─── Parse recon JSON ───────────────────────────────────────────────

function parseReconResponse(text: string, maxSpecialists: number): OrchestratorPlan | null {
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) return null;
  let parsed: any;
  try {
    parsed = JSON.parse(match[0]);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed.stack !== "string") return null;
  if (!Array.isArray(parsed.specialists) || parsed.specialists.length === 0) return null;

  const specialists: SpecialistPlan[] = [];
  for (const s of parsed.specialists.slice(0, maxSpecialists)) {
    if (!s || typeof s.name !== "string") continue;
    if (!Array.isArray(s.categories)) continue;
    if (!Array.isArray(s.files)) continue;
    const categories = s.categories
      .map((n: unknown) => (typeof n === "number" ? n : parseInt(String(n), 10)))
      .filter((n: number) => Number.isInteger(n) && n >= 1 && n <= 68);
    const files = s.files.filter((f: unknown) => typeof f === "string" && f.length > 0);
    if (categories.length === 0 || files.length === 0) continue;
    specialists.push({
      name: s.name,
      categories,
      files,
      rationale: typeof s.rationale === "string" ? s.rationale : "",
    });
  }
  if (specialists.length === 0) return null;

  return { stack: parsed.stack, specialists };
}

// ─── Plan (phase 1) ─────────────────────────────────────────────────

/**
 * The recon phase needs the AI's RAW text response (a JSON object with
 * stack + specialists), not the findings-shaped JSON that adapter.analyze
 * extracts. For local-cli we shell out directly and capture stdout. Hosted
 * providers go through the AI SDK, which we don't currently have a raw
 * entry point for; those callers should fall back to batched scan when
 * planSpecialists returns null.
 */
export async function planSpecialists(params: {
  adapter: AnyAdapter;
  model: string;
  methodologyBundle: MethodologyBundle;
  reconFiles: AnalyzeArgs["files"];
  maxSpecialists: number;
}): Promise<OrchestratorPlan | null> {
  const { adapter, model, methodologyBundle, reconFiles, maxSpecialists } = params;
  if (reconFiles.length === 0) return null;

  // Only local-cli exposes a raw-text path today. Hosted providers fall
  // back to batched scanning; the orchestrator is a local-cli feature.
  if (adapter.name !== "local-cli") return null;

  const prompt = reconPrompt(methodologyBundle, reconFiles, maxSpecialists);
  const { command, commandArgs } = resolveLocalCliCommand(model);

  let stdout: string;
  try {
    stdout = await runSubprocess(command, commandArgs, prompt);
  } catch {
    return null;
  }

  return parseReconResponse(stdout, maxSpecialists);
}

// Mirror of the PRESETS map in local-cli.ts, kept narrow to avoid
// circular imports. If the user passes an unknown model we return the
// claude preset since that's the most common local-cli target.
function resolveLocalCliCommand(model: string): { command: string; commandArgs: string[] } {
  const m = model.toLowerCase();
  if (m === "codex") return { command: "codex", commandArgs: ["exec", "--skip-git-repo-check", "-"] };
  if (m === "gemini") return { command: "gemini", commandArgs: ["-p", ""] };
  // claude + fallback
  return { command: "claude", commandArgs: ["-p"] };
}

// ─── Dispatch helpers ───────────────────────────────────────────────

import { minimatch } from "minimatch";

function filesMatchingGlobs(
  files: AnalyzeArgs["files"],
  globs: string[]
): AnalyzeArgs["files"] {
  return files.filter((f) =>
    globs.some((g) => minimatch(f.path, g, { dot: true, matchBase: false }))
  );
}

function subsetMethodology(
  bundle: MethodologyBundle,
  categoryIds: number[]
): string {
  const ids = new Set(categoryIds);
  const filtered: MethodologyBundle = {
    version: bundle.version,
    skill: bundle.skill,
    categories: bundle.categories.filter((c) => ids.has(c.id)),
  };
  return flattenMethodology(filtered);
}

// Simple semaphore: run `tasks` with max `limit` concurrent.
async function runWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  limit: number
): Promise<Array<PromiseSettledResult<T>>> {
  const results: Array<PromiseSettledResult<T>> = new Array(tasks.length);
  let cursor = 0;
  async function worker() {
    while (true) {
      const idx = cursor++;
      if (idx >= tasks.length) return;
      try {
        const value = await tasks[idx]!();
        results[idx] = { status: "fulfilled", value };
      } catch (reason) {
        results[idx] = { status: "rejected", reason };
      }
    }
  }
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, worker);
  await Promise.all(workers);
  return results;
}

// ─── Dispatch (phase 2) + Merge (phase 3) ───────────────────────────

export interface DispatchResult {
  findings: Finding[];
  specialistStats: Array<{
    name: string;
    files: number;
    findings: number;
    durationMs: number;
    error?: string;
  }>;
  totalInputTokens: number;
  totalOutputTokens: number;
}

export async function dispatchSpecialists(params: {
  adapter: AnyAdapter;
  apiKey: string;
  model: string;
  plan: OrchestratorPlan;
  allFiles: AnalyzeArgs["files"];
  methodologyBundle: MethodologyBundle;
  batchSize: number;
  onBatchStart?: (specialist: string, batch: number, total: number, files: number) => void;
  onSpecialistDone?: (name: string, findings: number, ms: number) => void;
}): Promise<DispatchResult> {
  const {
    adapter,
    apiKey,
    model,
    plan,
    allFiles,
    methodologyBundle,
    batchSize,
    onBatchStart,
    onSpecialistDone,
  } = params;

  const specialistStats: DispatchResult["specialistStats"] = [];

  const tasks = plan.specialists.map((spec) => async () => {
    const started = Date.now();
    const scope = filesMatchingGlobs(allFiles, spec.files);
    if (scope.length === 0) {
      const record = {
        name: spec.name,
        files: 0,
        findings: 0,
        durationMs: Date.now() - started,
      };
      specialistStats.push(record);
      onSpecialistDone?.(spec.name, 0, record.durationMs);
      return { findings: [] as Finding[], inputTokens: 0, outputTokens: 0 };
    }

    const methodology = subsetMethodology(methodologyBundle, spec.categories);

    // Batch within this specialist's file scope so prompts stay sane.
    const all: Finding[] = [];
    let inTok = 0;
    let outTok = 0;
    const totalBatches = Math.ceil(scope.length / batchSize);
    for (let i = 0; i < scope.length; i += batchSize) {
      const batch = scope.slice(i, i + batchSize);
      const batchNum = Math.floor(i / batchSize) + 1;
      onBatchStart?.(spec.name, batchNum, totalBatches, batch.length);
      try {
        const result = await adapter.analyze({
          apiKey,
          model,
          methodology,
          files: batch,
        });
        all.push(...result.findings);
        inTok += result.inputTokens ?? 0;
        outTok += result.outputTokens ?? 0;
      } catch (err) {
        // Specialist batch failed; keep going, record at specialist level.
        const msg = err instanceof Error ? err.message : String(err);
        specialistStats.push({
          name: spec.name,
          files: scope.length,
          findings: all.length,
          durationMs: Date.now() - started,
          error: msg,
        });
        onSpecialistDone?.(spec.name, all.length, Date.now() - started);
        return { findings: all, inputTokens: inTok, outputTokens: outTok };
      }
    }

    const ms = Date.now() - started;
    specialistStats.push({
      name: spec.name,
      files: scope.length,
      findings: all.length,
      durationMs: ms,
    });
    onSpecialistDone?.(spec.name, all.length, ms);
    return { findings: all, inputTokens: inTok, outputTokens: outTok };
  });

  const results = await runWithConcurrency(tasks, concurrencyFor(adapter.name));

  // Merge + dedupe.
  const seen = new Set<string>();
  const findings: Finding[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  for (const r of results) {
    if (r.status !== "fulfilled") continue;
    totalInputTokens += r.value.inputTokens;
    totalOutputTokens += r.value.outputTokens;
    for (const f of r.value.findings) {
      const key = `${f.file}:${f.line ?? 0}:${f.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }

  return { findings, specialistStats, totalInputTokens, totalOutputTokens };
}

// ─── Heuristic ──────────────────────────────────────────────────────

/**
 * Orchestrator is worth the extra recon call when the file set is big
 * enough that specialist parallelism wins back the cost, and when the
 * caller didn't already hand-pick categories (in which case recon has
 * nothing to decide).
 */
export function shouldUseOrchestrator(params: {
  fileCount: number;
  userPickedCategories: boolean;
}): boolean {
  if (params.userPickedCategories) return false;
  return params.fileCount >= 10;
}
