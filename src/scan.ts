import { loadConfig, mergeWithDefaults } from "./_shared/config.js";
import {
  completeScanEvent,
  LicenseError,
  startScanEvent,
} from "./_shared/license.js";
import {
  fetchMethodology,
  flattenMethodology,
} from "./_shared/methodology.js";
import {
  selectProvider,
  type ProviderKeys,
} from "./_shared/providers/index.js";
import { findingsToSarif } from "./_shared/sarif.js";
import { filterPaths } from "./_shared/trigger.js";
import type {
  AnalyzeArgs,
  AnalyzeResult,
  Finding,
  Severity,
} from "./_shared/providers/types.js";
import { localCli } from "./providers/local-cli.js";

// A loose adapter shape that accepts both the hosted providers and local-cli.
// local-cli lives outside the shared ProviderName enum because the Action
// cannot use it, so we widen here where both call sites meet.
interface AnyAdapter {
  name: string;
  defaultModel: string;
  analyze(args: AnalyzeArgs): Promise<AnalyzeResult>;
}
interface Selection {
  adapter: AnyAdapter;
  apiKey: string;
}

import {
  headSha,
  listAllTrackedPaths,
  listChangedPaths,
  loadFiles,
  repoIdentity,
  repoRoot,
  resolveBaseRef,
} from "./git.js";
import { reportPaths, writeMarkdown, writeSarif } from "./report.js";
import { formatBlockMessage, runGate } from "./gate.js";
import {
  assertLocalPath,
  classifyRepo,
  cloneRemote,
  keepClone,
  type RemoteClone,
} from "./remote.js";
import { loadConfig as loadStoredConfig } from "./config-store.js";
import { runSetup } from "./setup.js";
import {
  collectReconFiles,
  dispatchSpecialists,
  planSpecialists,
  shouldUseOrchestrator,
} from "./orchestrator.js";
import * as readline from "node:readline";
import { existsSync, statSync, readdirSync } from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";

function emptyOutcome(): ScanOutcome {
  return {
    exitCode: 0,
    findings: [],
    reportMd: "",
    reportSarif: "",
    scanId: "",
  };
}

async function maybePromptForFull(): Promise<boolean> {
  const stdin = process.stdin as any;
  const stdout = process.stdout as any;
  if (!stdin.isTTY || !stdout.isTTY) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer: string = await new Promise((resolve) => {
      rl.question("Scan every tracked file instead? [Y/n] ", (a) => resolve(a));
    });
    const trimmed = answer.trim().toLowerCase();
    return trimmed === "" || trimmed === "y" || trimmed === "yes";
  } finally {
    rl.close();
  }
}

/**
 * Expand positional args into an explicit file list.
 *   @path       file or directory; directory is expanded recursively
 *   #123        GitHub PR number; requires `gh` CLI
 *   #PR-123     same as above
 */
function expandPositionals(root: string, positionals: string[]): {
  files?: string[];
  errors: string[];
} {
  if (positionals.length === 0) return { errors: [] };
  const files: string[] = [];
  const errors: string[] = [];

  for (const raw of positionals) {
    if (raw.startsWith("#")) {
      const prNum = raw.replace(/^#(PR-)?/i, "");
      if (!/^\d+$/.test(prNum)) {
        errors.push(`"${raw}" is not a recognized PR reference. Use #123 or #PR-123.`);
        continue;
      }
      try {
        const diffOut = execSync(`gh pr diff ${prNum} --name-only`, {
          cwd: root,
          stdio: ["ignore", "pipe", "pipe"],
        }).toString();
        const prFiles = diffOut.split("\n").map((s) => s.trim()).filter(Boolean);
        if (prFiles.length === 0) {
          errors.push(`PR #${prNum} had no changed files (or \`gh\` returned nothing).`);
        } else {
          files.push(...prFiles);
        }
      } catch (err: any) {
        const msg = err?.stderr?.toString?.() ?? err?.message ?? String(err);
        if (msg.includes("command not found") || msg.includes("ENOENT")) {
          errors.push(
            `Cannot resolve #${prNum}: the \`gh\` CLI is not installed. Install it from https://cli.github.com or pass --files instead.`
          );
        } else if (msg.toLowerCase().includes("not authenticated")) {
          errors.push(`Cannot resolve #${prNum}: run \`gh auth login\` first.`);
        } else {
          errors.push(`Cannot resolve #${prNum}: ${msg.trim()}`);
        }
      }
      continue;
    }

    const target = raw.startsWith("@") ? raw.slice(1) : raw;
    const abs = path.resolve(root, target);
    if (!existsSync(abs)) {
      errors.push(`"${raw}" does not exist (looked for ${abs}).`);
      continue;
    }
    const st = statSync(abs);
    if (st.isDirectory()) {
      for (const f of walkDir(abs)) {
        files.push(path.relative(root, f));
      }
    } else {
      files.push(path.relative(root, abs));
    }
  }

  return { files, errors };
}

function walkDir(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkDir(full));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

const METHODOLOGY_VERSION = process.env.SNITCH_METHODOLOGY_VERSION ?? "v7.1.0";
const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];

// --quick shorthand. These are the ten highest-impact categories for a
// first-pass triage: injection, auth, secrets, XSS, crypto, SSRF, access
// control, deserialization, CSRF, path traversal. Matches the free tier.
const QUICK_CATEGORIES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

export interface ScanOptions {
  files?: string[]; // explicit file list
  full?: boolean; // scan whole working tree (respects paths-ignore)
  base?: string; // base ref for diff mode
  failOn?: "critical" | "high" | "medium" | "low" | "none";
  provider?: string; // openrouter | anthropic | openai | google | copilot | local-cli
  model?: string;
  quiet?: boolean;
  repo?: string; // local path or remote URL
  positionals?: string[]; // @path / #PR shortcuts
  categories?: number[]; // subset of 1-68 methodology category IDs
  quick?: boolean; // shorthand for the 10 core categories
  forceAfterInjection?: boolean;
}

export interface ScanOutcome {
  exitCode: 0 | 1 | 10;
  findings: Finding[];
  reportMd: string;
  reportSarif: string;
  scanId: string;
}

// Dedicated exit code for a gate block. CI can distinguish "blocked adversarial
// repo" from "failed security audit" without parsing stderr.
export const EXIT_GATE_BLOCK = 10;

export async function runScan(opts: ScanOptions): Promise<ScanOutcome> {
  const start = Date.now();

  // Resolve credentials. Precedence: env vars → ~/.snitch/config.json → first-run prompt.
  let licenseKey = nonEmpty(process.env.SNITCH_LICENSE_KEY);
  const envKeys: ProviderKeys = {
    openrouter: nonEmpty(process.env.OPENROUTER_API_KEY),
    anthropic: nonEmpty(process.env.ANTHROPIC_API_KEY),
    openai: nonEmpty(process.env.OPENAI_API_KEY),
    google: nonEmpty(process.env.GOOGLE_API_KEY),
    copilot: nonEmpty(process.env.COPILOT_TOKEN),
  };

  let storedConfig = loadStoredConfig();

  // If we have no license key AND no stored config, run the first-run wizard.
  // Subsequent runs skip this because either env var or config is populated.
  if (!licenseKey && !storedConfig) {
    storedConfig = await runSetup();
  }

  if (!licenseKey && storedConfig) licenseKey = storedConfig.licenseKey;
  if (!licenseKey) {
    throw new LicenseError(0, "Missing SNITCH_LICENSE_KEY. Run `snitch init`.");
  }

  // Merge env keys with stored OpenRouter key (env wins if both present).
  const keys: ProviderKeys = {
    ...envKeys,
    openrouter: envKeys.openrouter ?? storedConfig?.openrouterKey,
  };

  // Resolve the scan root. Three modes:
  //   1. --repo <url>   → shallow clone into os.tmpdir(), run gate, then scan
  //   2. --repo <path>  → scan that local directory
  //   3. no --repo      → scan cwd (legacy behavior)
  let clone: RemoteClone | null = null;
  let root: string;
  if (opts.repo) {
    const classified = classifyRepo(opts.repo);
    if (classified.kind === "url") {
      if (!opts.quiet) {
        console.log(`Cloning ${classified.value} ...`);
      }
      clone = cloneRemote(classified.value);
      root = clone.root;
    } else {
      const abs = assertLocalPath(classified.value);
      root = repoRoot(abs);
    }
  } else {
    root = repoRoot(process.cwd());
  }

  const config = mergeWithDefaults(loadConfig(root));

  const failOn = opts.failOn ?? config.failOn;
  // Provider + model resolution: CLI flag → .snitch.yml → user-global config → adapter default.
  const provider = opts.provider ?? config.provider ?? storedConfig?.provider;
  const model = opts.model ?? config.model ?? storedConfig?.model;

  // Determine candidate files + base ref for diff metadata.
  let base: string | null = null;
  let candidatePaths: string[];
  if (opts.positionals && opts.positionals.length > 0) {
    const { files: expanded, errors } = expandPositionals(root, opts.positionals);
    if (errors.length > 0) {
      for (const e of errors) console.error(e);
      throw new Error("One or more scan targets could not be resolved.");
    }
    candidatePaths = expanded ?? [];
  } else if (opts.files && opts.files.length > 0) {
    candidatePaths = opts.files;
  } else if (opts.full) {
    candidatePaths = listAllTrackedPaths(root);
  } else {
    base = resolveBaseRef(opts.base, root);
    candidatePaths = listChangedPaths(base, root);
  }

  if (candidatePaths.length === 0) {
    if (!opts.quiet) {
      if (opts.files && opts.files.length > 0) {
        console.log("No readable files matched your --files list. Nothing to do.");
      } else if (opts.full) {
        console.log("No tracked files found in this repo. Is it empty or not a git repo?");
      } else {
        const baseLabel = base ?? opts.base ?? "origin/main";
        console.log(`No changed files vs ${baseLabel}.`);
        const wantFull = await maybePromptForFull();
        if (wantFull) {
          console.log("");
          candidatePaths = listAllTrackedPaths(root);
          if (candidatePaths.length === 0) {
            console.log("No tracked files found in this repo either. Nothing to do.");
            return emptyOutcome();
          }
          console.log(`Scanning every tracked file in the repo (${candidatePaths.length} total).`);
        } else {
          console.log("");
          console.log("Other options:");
          console.log("  snitch scan --full             # every tracked file");
          console.log("  snitch scan --base HEAD~10     # diff vs 10 commits back");
          console.log("  snitch scan --files src/foo.ts # explicit list");
          return emptyOutcome();
        }
      }
    }
    if (candidatePaths.length === 0) return emptyOutcome();
  }

  const allowed = new Set(
    filterPaths(candidatePaths, config.pathsInclude, config.pathsIgnore)
  );
  const scanPaths = candidatePaths.filter((p) => allowed.has(p));
  if (scanPaths.length === 0) {
    if (!opts.quiet) {
      console.log("All candidate files were excluded by .snitch.yml paths filters.");
    }
    return {
      exitCode: 0,
      findings: [],
      reportMd: "",
      reportSarif: "",
      scanId: "",
    };
  }

  // Pick provider. local-cli bypasses the key-based selector because it
  // doesn't need an API key (it shells out to a binary on PATH instead).
  let selected: Selection;
  if (provider === "local-cli") {
    selected = { adapter: localCli, apiKey: "" };
  } else {
    selected = selectProvider(keys, provider);
  }
  const adapterModel = model ?? selected.adapter.defaultModel;

  // Prompt-injection gate. Runs only when we cloned a remote URL, since the
  // threat model is "adversarial repo hijacks the scanner." Local scans and
  // non-repo scans trust the code and skip the gate.
  if (clone) {
    const gateStart = Date.now();
    const repoId = repoIdentity(clone.root);
    const gateEvent = await startScanEvent(licenseKey, {
      repoOwner: repoId.owner,
      repoName: repoId.name,
      prNumber: 0,
      fileCount: 0, // gate may scan a different file set than main; record on complete
      scanMode: "gate",
      provider: selected.adapter.name,
      model: adapterModel,
      triggeredBy: "cli",
    });
    const gateResult = await runGate({
      repoRoot: clone.root,
      licenseKey,
      provider: {
        apiKey: selected.apiKey,
        analyze: selected.adapter.analyze,
        name: selected.adapter.name,
        defaultModel: selected.adapter.defaultModel,
      },
      model: adapterModel,
    });

    const blocking = gateResult.findings.filter(
      (f) => f.severity === "Critical" || f.severity === "High"
    );

    await completeScanEvent(licenseKey, gateEvent.scanId, {
      findingsCount: gateResult.findings.length,
      criticalCount: gateResult.findings.filter((f) => f.severity === "Critical").length,
      highCount: blocking.filter((f) => f.severity === "High").length,
      mediumCount: gateResult.findings.filter((f) => f.severity === "Medium").length,
      lowCount: gateResult.findings.filter((f) => f.severity === "Low").length,
      durationMs: Date.now() - gateStart,
      inputTokens: 0,
      outputTokens: 0,
    }).catch(() => {});

    if (!gateResult.pass && !opts.forceAfterInjection) {
      keepClone(clone);
      if (!opts.quiet) {
        console.error(formatBlockMessage(gateResult, clone.root));
      }
      return {
        exitCode: EXIT_GATE_BLOCK,
        findings: gateResult.findings,
        reportMd: "",
        reportSarif: "",
        scanId: gateEvent.scanId,
      };
    }

    if (!gateResult.pass && opts.forceAfterInjection && !opts.quiet) {
      console.warn(
        `Snitch gate flagged ${blocking.length} prompt-injection finding(s); --force-after-injection was set, main scan will run anyway.`
      );
    }
  }

  // Load file content + patches.
  const files = loadFiles(scanPaths, base, root);
  if (files.length === 0) {
    if (!opts.quiet) {
      console.log("No readable files in scope (binary / unreadable). Nothing to do.");
    }
    return {
      exitCode: 0,
      findings: [],
      reportMd: "",
      reportSarif: "",
      scanId: "",
    };
  }

  const repo = repoIdentity(root);
  if (!opts.quiet) {
    const envBatch = parseInt(process.env.SNITCH_BATCH_SIZE ?? "5", 10) || 5;
    const total = Math.ceil(files.length / envBatch);
    console.log(
      `Scanning ${files.length} file(s) with ${selected.adapter.name}/${adapterModel} in ${total} batch${total === 1 ? "" : "es"} of ${envBatch}...`
    );
  }

  // License check + scan_id allocation.
  const entitlement = await startScanEvent(licenseKey, {
    repoOwner: repo.owner,
    repoName: repo.name,
    // CLI scans are not tied to a PR. Use 0 so server accepts it; dashboards
    // can render as "local/<sha>".
    prNumber: 0,
    fileCount: files.length,
    scanMode: "local",
    provider: selected.adapter.name,
    model: adapterModel,
    categories: opts.categories ?? (opts.quick ? QUICK_CATEGORIES : config.categories),
    triggeredBy: "cli",
  });

  // Fetch methodology. CLI flag > --quick shorthand > .snitch.yml > server entitlement.
  const effectiveCategories =
    opts.categories ??
    (opts.quick ? QUICK_CATEGORIES : undefined) ??
    config.categories ??
    entitlement.entitledCategories;
  const bundle = await fetchMethodology(
    licenseKey,
    METHODOLOGY_VERSION,
    effectiveCategories
  );
  const methodology = flattenMethodology(bundle);

  const batchSize = parseInt(process.env.SNITCH_BATCH_SIZE ?? "5", 10) || 5;
  const userPickedCategories = !!(opts.categories || opts.quick || config.categories);

  // Orchestrator path: for local-cli on a scan of 10+ files where the user
  // didn't hand-pick categories, run a recon agent first, then dispatch
  // specialists in parallel. Each specialist gets a focused methodology
  // slice and a subset of files. Much better signal than one-size-fits-all
  // batching, and faster because specialists run concurrently.
  let allFindings: Finding[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let orchestratorUsed = false;

  if (shouldUseOrchestrator({ fileCount: files.length, userPickedCategories })) {
    const reconFiles = collectReconFiles(root);
    if (!opts.quiet) {
      console.log(`  Reconnaissance (${reconFiles.length} config files)...`);
    }
    const plan = await planSpecialists({
      adapter: selected.adapter,
      model: adapterModel,
      methodologyBundle: bundle,
      reconFiles,
      maxSpecialists: 3,
    });
    if (plan) {
      orchestratorUsed = true;
      if (!opts.quiet) {
        console.log(`  Stack: ${plan.stack}`);
        console.log(`  Dispatching ${plan.specialists.length} specialist(s) in parallel:`);
        for (const s of plan.specialists) {
          console.log(`    ${s.name} (cats: ${s.categories.join(", ")})`);
        }
      }
      const dispatched = await dispatchSpecialists({
        adapter: selected.adapter,
        apiKey: selected.apiKey,
        model: adapterModel,
        plan,
        allFiles: files,
        methodologyBundle: bundle,
        batchSize,
        onSpecialistDone: (name, findings, ms) => {
          if (!opts.quiet) {
            console.log(`    ✓ ${name}: ${findings} finding(s) in ${(ms / 1000).toFixed(1)}s`);
          }
        },
      });
      allFindings = dispatched.findings;
      totalInputTokens = dispatched.totalInputTokens;
      totalOutputTokens = dispatched.totalOutputTokens;
    } else if (!opts.quiet) {
      console.log(`  Orchestrator unavailable for this provider/model. Falling back to batched scan.`);
    }
  }

  // Fallback + default path: batched sequential scan.
  if (!orchestratorUsed) {
    const totalBatches = Math.ceil(files.length / batchSize);
    if (!opts.quiet && files.length > 0) {
      console.log(
        `  Batched sequential scan: ${totalBatches} batch${totalBatches === 1 ? "" : "es"} of ${batchSize}...`
      );
    }
    const accum: Finding[] = [];
    for (let i = 0; i < files.length; i += batchSize) {
      const batch = files.slice(i, i + batchSize);
      const batchNum = Math.floor(i / batchSize) + 1;
      if (!opts.quiet) {
        console.log(
          `  Batch ${batchNum}/${totalBatches} (${batch.length} file${batch.length === 1 ? "" : "s"})...`
        );
      }
      try {
        const batchResult = await selected.adapter.analyze({
          apiKey: selected.apiKey,
          model: adapterModel,
          methodology,
          files: batch,
        });
        accum.push(...batchResult.findings);
        totalInputTokens += batchResult.inputTokens ?? 0;
        totalOutputTokens += batchResult.outputTokens ?? 0;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (!opts.quiet) {
          console.warn(`  Batch ${batchNum} failed: ${msg}. Continuing.`);
        }
      }
    }
    allFindings = accum;
  }

  // Dedupe. Orchestrator dispatches non-overlapping file globs so duplicate
  // findings should be rare, but specialists can re-flag the same issue
  // under slightly different wording; sequential batches sometimes repeat
  // a category pass across the same file. Key on file:line:title.
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const f of allFindings) {
    const key = `${f.file}:${f.line ?? 0}:${f.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(f);
  }

  const analysis = {
    findings,
    inputTokens: totalInputTokens,
    outputTokens: totalOutputTokens,
  };
  const durationMs = Date.now() - start;

  // Write reports.
  const paths = reportPaths(process.cwd());
  const sarif = findingsToSarif(findings, "1.0.0");
  writeSarif(sarif, paths.sarif);
  writeMarkdown(
    findings,
    {
      fileCount: files.length,
      scanMode: "local",
      provider: selected.adapter.name,
      model: adapterModel,
      durationMs,
      repo: `${repo.owner}/${repo.name}@${headSha(root)}`,
      base,
    },
    paths.markdown
  );

  // Telemetry (metadata only).
  try {
    await completeScanEvent(licenseKey, entitlement.scanId, {
      findingsCount: findings.length,
      criticalCount: findings.filter((f) => f.severity === "Critical").length,
      highCount: findings.filter((f) => f.severity === "High").length,
      mediumCount: findings.filter((f) => f.severity === "Medium").length,
      lowCount: findings.filter((f) => f.severity === "Low").length,
      durationMs,
      inputTokens: analysis.inputTokens,
      outputTokens: analysis.outputTokens,
    });
  } catch {
    // Telemetry failures don't block the local scan result.
  }

  // Decide exit code from fail-on.
  const exitCode = shouldFail(findings, failOn) ? 1 : 0;

  if (!opts.quiet) {
    summarize(findings, paths, durationMs, exitCode, failOn);
  }

  return {
    exitCode,
    findings,
    reportMd: paths.markdown,
    reportSarif: paths.sarif,
    scanId: entitlement.scanId,
  };
}

function shouldFail(findings: Finding[], failOn: string): boolean {
  if (failOn === "none") return false;
  const idx = SEVERITY_ORDER.findIndex((s) => s.toLowerCase() === failOn);
  if (idx === -1) return false;
  return findings.some((f) => {
    const i = SEVERITY_ORDER.indexOf(f.severity);
    return i !== -1 && i <= idx;
  });
}

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

function color(text: string, code: string): string {
  const tty = (process.stdout as any).isTTY;
  const noColor = !!process.env.NO_COLOR;
  if (!tty || noColor) return text;
  return `${code}${text}${ANSI.reset}`;
}

function summarize(
  findings: Finding[],
  paths: { markdown: string; sarif: string },
  durationMs: number,
  exitCode: number,
  failOn: string
): void {
  const counts = {
    c: findings.filter((f) => f.severity === "Critical").length,
    h: findings.filter((f) => f.severity === "High").length,
    m: findings.filter((f) => f.severity === "Medium").length,
    l: findings.filter((f) => f.severity === "Low").length,
  };

  const parts: string[] = [];
  if (counts.c > 0) parts.push(color(`${counts.c} critical`, ANSI.bold + ANSI.red));
  else parts.push(color("0 critical", ANSI.gray));
  if (counts.h > 0) parts.push(color(`${counts.h} high`, ANSI.yellow));
  else parts.push(color("0 high", ANSI.gray));
  parts.push(`${counts.m} medium`);
  parts.push(`${counts.l} low`);

  const seconds = (durationMs / 1000).toFixed(1);
  const icon = exitCode === 0 ? color("✓", ANSI.cyan) : color("✗", ANSI.red);

  console.log("");
  console.log(
    `${icon} ${findings.length} finding(s) in ${seconds}s · ${parts.join(" · ")}`
  );
  console.log(color(`  report: ${paths.markdown}`, ANSI.dim));
  console.log(color(`  sarif:  ${paths.sarif}`, ANSI.dim));
  if (exitCode !== 0) {
    console.log("");
    console.log(
      color(
        `Exit ${exitCode}: at least one ${failOn}-or-higher finding. Pass --fail-on none to return 0 regardless.`,
        ANSI.yellow
      )
    );
  }
}

function nonEmpty(v: string | undefined): string | undefined {
  return v && v.trim().length > 0 ? v.trim() : undefined;
}
