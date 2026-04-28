// Single source of truth for the human-readable Snitch report markdown.
// Used by:
//   - postComment (sticky PR comment)
//   - the on-disk SECURITY_AUDIT_REPORT.md artifact
//   - the GitHub Actions Job Summary
// All three should look identical so reviewers don't get confused.
//
// SCA findings (metadata.kind === "sca") are grouped by package so a
// single vulnerable dep with 25 CVEs renders as ONE collapsible block
// with a 25-row table inside, not 25 top-level bullets. Code-review
// findings (no metadata) keep the existing severity-bucketed layout.

import type { Finding, FindingMetadata, Severity } from "./providers/types.js";
// FindingMetadata referenced via Extract<> in renderer helpers below.

export interface ReportMeta {
  fileCount: number;
  provider: string;
  model: string;
  durationMs: number;
  scanType: string;
  partial?: { failedBatches: number; totalBatches: number; lastError?: string };
}

const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];
const SEV_BADGE: Record<Severity, string> = {
  Critical: "🔴 **Critical**",
  High: "🟠 **High**",
  Medium: "🟡 Medium",
  Low: "⚪ Low",
};

const STICKY_HEADER = "## Snitch Security Scan";

export function buildReportMarkdown(
  findings: Finding[],
  meta: ReportMeta,
  opts: { includeStickyHeader?: boolean } = {}
): string {
  const total = findings.length;
  const counts = countBy(findings, (f) => f.severity);
  const sca = findings.filter((f) => f.metadata?.kind === "sca");
  const dca = findings.filter((f) => f.metadata?.kind === "dca");
  const iac = findings.filter((f) => f.metadata?.kind === "iac");
  const code = findings.filter((f) => !f.metadata);

  const out: string[] = [];
  if (opts.includeStickyHeader) out.push(STICKY_HEADER, "");
  if (meta.partial) {
    out.push(
      `> ⚠️ **Partial scan.** ${meta.partial.failedBatches} of ${meta.partial.totalBatches} batches failed. Findings below are incomplete.${
        meta.partial.lastError ? ` Last error: \`${meta.partial.lastError.slice(0, 200)}\`` : ""
      }`,
      ""
    );
  }

  // ── Top summary ─────────────────────────────────────────────────
  out.push(
    `**${total} finding${total !== 1 ? "s" : ""}** across ${meta.fileCount} file${meta.fileCount !== 1 ? "s" : ""}. Mode \`${meta.scanType}\` · Model \`${meta.provider}/${meta.model}\` · Duration ${(meta.durationMs / 1000).toFixed(1)}s.`,
    ""
  );

  if (total === 0) {
    out.push("No security issues found in the changed files. ✅");
    return out.join("\n");
  }

  // ── Severity table ─────────────────────────────────────────────
  out.push("| Severity | Count |");
  out.push("|---|---:|");
  for (const sev of SEV_ORDER) {
    out.push(`| ${SEV_BADGE[sev]} | ${counts[sev] ?? 0} |`);
  }
  out.push("");

  // ── SCA section: grouped by package ────────────────────────────
  if (sca.length > 0) {
    out.push(renderScaSection(sca));
  }

  // ── DCA section: unused deps + dead files ──────────────────────
  if (dca.length > 0) {
    out.push(renderDcaSection(dca));
  }

  // ── IaC section: misconfigurations grouped by framework ────────
  if (iac.length > 0) {
    out.push(renderIacSection(iac));
  }

  // ── Code-review section: severity-bucketed bullets ─────────────
  if (code.length > 0) {
    out.push(renderCodeSection(code));
  }

  return out.join("\n").trimEnd() + "\n";
}

function renderDcaSection(dcaFindings: Finding[]): string {
  const lines: string[] = [];
  const unusedDeps = dcaFindings.filter(
    (f) => f.metadata?.kind === "dca" && f.metadata.subkind === "unused-dep"
  );
  const deadFiles = dcaFindings.filter(
    (f) => f.metadata?.kind === "dca" && f.metadata.subkind === "dead-file"
  );

  lines.push(
    `### 🧹 Dead code & unused dependencies (${dcaFindings.length})`,
    "",
    "_Deterministic scan: parsed manifests + walked imports to find code and packages that ship but aren't connected to anything. Severity is Low because dead code rarely breaks anything — but it expands attack surface for free._",
    ""
  );

  if (unusedDeps.length > 0) {
    // Group by ecosystem.
    const byEco = new Map<string, Finding[]>();
    for (const f of unusedDeps) {
      const meta = f.metadata as Extract<FindingMetadata, { kind: "dca" }>;
      const eco = meta.ecosystem ?? "unknown";
      const arr = byEco.get(eco);
      if (arr) arr.push(f);
      else byEco.set(eco, [f]);
    }
    lines.push(
      `<details${unusedDeps.length <= 8 ? " open" : ""}><summary><strong>Unused dependencies</strong> · ${unusedDeps.length}</summary>`,
      "",
      "| Ecosystem | Package | Manifest |",
      "|---|---|---|"
    );
    const ecoOrder = [...byEco.keys()].sort();
    for (const eco of ecoOrder) {
      const items = byEco.get(eco)!;
      for (const f of items.sort((a, b) => {
        const an = (a.metadata as Extract<FindingMetadata, { kind: "dca" }>).packageName ?? "";
        const bn = (b.metadata as Extract<FindingMetadata, { kind: "dca" }>).packageName ?? "";
        return an.localeCompare(bn);
      })) {
        const meta = f.metadata as Extract<FindingMetadata, { kind: "dca" }>;
        lines.push(`| \`${eco}\` | \`${meta.packageName ?? ""}\` | \`${meta.manifestPath ?? f.file}\` |`);
      }
    }
    lines.push("", "**Suggested fix:** remove these from their manifests. They are not imported anywhere in the source tree.", "", "</details>", "");
  }

  if (deadFiles.length > 0) {
    lines.push(
      `<details${deadFiles.length <= 10 ? " open" : ""}><summary><strong>Dead files</strong> · ${deadFiles.length}</summary>`,
      ""
    );
    const aggregate = deadFiles.find((f) => f.file === "");
    if (aggregate) {
      lines.push(
        `> ${escapeMd(aggregate.title)}`,
        "",
        escapeMd(aggregate.risk),
        "",
        `**Suggested fix:** ${escapeMd(aggregate.fix)}`
      );
    } else {
      lines.push("| File |", "|---|");
      for (const f of deadFiles.sort((a, b) => a.file.localeCompare(b.file))) {
        lines.push(`| \`${f.file}\` |`);
      }
      lines.push("", "**Suggested fix:** delete the file, or wire it up by importing it from where it should be used. Confidence is medium because dynamic imports and framework auto-discovery can produce false positives.");
    }
    lines.push("", "</details>", "");
  }

  return lines.join("\n");
}

function renderScaSection(scaFindings: Finding[]): string {
  const lines: string[] = [];
  // Group by package coordinate.
  const groups = new Map<string, Finding[]>();
  for (const f of scaFindings) {
    const m = f.metadata as Extract<FindingMetadata, { kind: "sca" }>;
    const key = `${m.ecosystem}::${m.packageName}::${m.packageVersion}`;
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }

  // Order groups by worst severity, then by vuln count.
  const sorted = [...groups.entries()].sort((a, b) => {
    const aWorst = worstSeverity(a[1]);
    const bWorst = worstSeverity(b[1]);
    if (aWorst !== bWorst) return SEV_ORDER.indexOf(aWorst) - SEV_ORDER.indexOf(bWorst);
    return b[1].length - a[1].length;
  });

  lines.push(`### 📦 Vulnerable dependencies (${groups.size} package${groups.size === 1 ? "" : "s"}, ${scaFindings.length} CVE${scaFindings.length === 1 ? "" : "s"})`, "");

  // Top-line package summary table (always visible).
  lines.push("| Package | Version | Vulns | Worst | Manifest |");
  lines.push("|---|---|---:|---|---|");
  for (const [, vulns] of sorted) {
    const m0 = vulns[0]!.metadata as Extract<FindingMetadata, { kind: "sca" }>;
    const worst = worstSeverity(vulns);
    lines.push(
      `| \`${m0.packageName}\` | \`${m0.packageVersion}\` | ${vulns.length} | ${SEV_BADGE[worst]} | \`${vulns[0]!.file}\` |`
    );
  }
  lines.push("");

  // Per-package collapsible details with a CVE table inside.
  for (const [, vulns] of sorted) {
    const m0 = vulns[0]!.metadata as Extract<FindingMetadata, { kind: "sca" }>;
    const worst = worstSeverity(vulns);
    lines.push(
      `<details><summary><strong>${escapeHtml(m0.packageName)}@${escapeHtml(m0.packageVersion)}</strong> · ${vulns.length} vulnerabilit${vulns.length === 1 ? "y" : "ies"} · ${SEV_BADGE[worst]}</summary>`,
      ""
    );
    lines.push("| Severity | ID | Summary |");
    lines.push("|---|---|---|");
    // Sort CVEs by severity within the package.
    const sortedVulns = [...vulns].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
    for (const v of sortedVulns) {
      const m = v.metadata as Extract<FindingMetadata, { kind: "sca" }>;
      const idCell = m.advisoryUrl ? `[\`${m.vulnId}\`](${m.advisoryUrl})` : `\`${m.vulnId}\``;
      lines.push(`| ${SEV_BADGE[v.severity]} | ${idCell} | ${escapeMd(m.summary)} |`);
    }
    // Suggested fix (consistent across the group: upgrade the package).
    // Some advisories have ranges too complex for our normalizer; in that
    // case `fixedVersion` is the literal "see advisory" — render plainly.
    const fixHint = vulns.find((v) => {
      const mm = v.metadata as Extract<FindingMetadata, { kind: "sca" }>;
      return mm.fixedVersion && mm.fixedVersion !== "see advisory";
    });
    if (fixHint) {
      const mm = fixHint.metadata as Extract<FindingMetadata, { kind: "sca" }>;
      lines.push("", `**Suggested fix:** upgrade \`${m0.packageName}\` out of the affected range \`${(mm.fixedVersion ?? "").replace(/`/g, "")}\`.`);
    } else {
      lines.push("", `**Suggested fix:** upgrade \`${m0.packageName}\` to a non-vulnerable version (see linked advisories above).`);
    }
    lines.push("", "</details>", "");
  }

  return lines.join("\n");
}

function renderCodeSection(codeFindings: Finding[]): string {
  const lines: string[] = [];
  lines.push("### 🔍 Code-review findings", "");

  for (const sev of SEV_ORDER) {
    const items = codeFindings.filter((f) => f.severity === sev);
    if (items.length === 0) continue;
    lines.push(`<details${sev === "Critical" || sev === "High" ? " open" : ""}><summary>${SEV_BADGE[sev]} (${items.length})</summary>`, "");
    for (const f of items) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const tags = [f.cwe, f.owasp].filter(Boolean).join(" · ");
      lines.push(`- **${escapeMd(f.title)}** in \`${loc}\``);
      if (tags) lines.push(`  - _${tags}_`);
      lines.push(`  - ${escapeMd(f.risk)}`);
      if (f.fix) lines.push(`  - **Fix:** ${escapeMd(f.fix)}`);
    }
    lines.push("", "</details>", "");
  }
  return lines.join("\n");
}

function renderIacSection(iacFindings: Finding[]): string {
  const lines: string[] = [];
  lines.push(
    `### 🏗️ Infrastructure misconfigurations (${iacFindings.length})`,
    "",
    "_Static policy checks on Terraform, CloudFormation, Kubernetes, and Dockerfiles. Caught before merge so the runtime never has the chance to be exploited._",
    ""
  );

  // Group by framework
  const byFramework = new Map<string, Finding[]>();
  for (const f of iacFindings) {
    const meta = f.metadata as Extract<FindingMetadata, { kind: "iac" }>;
    const fw = meta.framework;
    const arr = byFramework.get(fw);
    if (arr) arr.push(f);
    else byFramework.set(fw, [f]);
  }

  // Top-line summary table.
  lines.push("| Framework | Misconfigs | Worst |");
  lines.push("|---|---:|---|");
  const fwOrder = [...byFramework.keys()].sort();
  for (const fw of fwOrder) {
    const items = byFramework.get(fw)!;
    lines.push(`| \`${fw}\` | ${items.length} | ${SEV_BADGE[worstSeverity(items)]} |`);
  }
  lines.push("");

  // Per-framework collapsible.
  for (const fw of fwOrder) {
    const items = byFramework.get(fw)!;
    const worst = worstSeverity(items);
    const open = items.length <= 12 ? " open" : "";
    lines.push(
      `<details${open}><summary><strong>${escapeHtml(fw)}</strong> · ${items.length} misconfig${items.length === 1 ? "" : "s"} · ${SEV_BADGE[worst]}</summary>`,
      "",
      "| Severity | Rule | Resource | File:line | Fix |",
      "|---|---|---|---|---|"
    );
    const sorted = [...items].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
    for (const f of sorted) {
      const meta = f.metadata as Extract<FindingMetadata, { kind: "iac" }>;
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const resource = meta.resourceName
        ? `${meta.resourceType} \`${meta.resourceName}\``
        : meta.resourceType;
      lines.push(
        `| ${SEV_BADGE[f.severity]} | \`${meta.ruleId}\` | ${escapeMd(resource)} | \`${loc}\` | ${escapeMd(f.fix)} |`
      );
    }
    lines.push("", "</details>", "");
  }

  return lines.join("\n");
}

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = "Low";
  for (const f of findings) {
    if (SEV_ORDER.indexOf(f.severity) < SEV_ORDER.indexOf(worst)) worst = f.severity;
  }
  return worst;
}

function countBy<T, K extends string | number>(arr: T[], fn: (t: T) => K): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const item of arr) {
    const k = fn(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function escapeMd(s: string): string {
  // Light escape for table cells: kill newlines and pipes.
  return s.replace(/\r?\n+/g, " ").replace(/\|/g, "\\|").trim();
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
