import { createHash } from "node:crypto";
import type { Finding, Severity } from "./providers/types.js";

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri: string;
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties: {
    tags: string[];
    precision: "very-high" | "high" | "medium" | "low";
    "problem.severity": "error" | "warning" | "recommendation" | "note";
    "security-severity": string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints: { primaryLocationLineHash: string };
  properties: { "security-severity": string };
}

interface SarifDocument {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        organization: string;
        version: string;
        semanticVersion: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

const SEVERITY_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "note",
};

const SEVERITY_SCORE: Record<Severity, string> = {
  Critical: "9.5",
  High: "8.0",
  Medium: "5.5",
  Low: "3.0",
};

const SEVERITY_PROBLEM: Record<Severity, "error" | "warning" | "recommendation" | "note"> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "recommendation",
};

function ruleIdFor(finding: Finding): string {
  // SCA findings: one rule per vulnerable package (not per CVE) so the
  // Code Scanning UI groups all CVEs for the same package together.
  if (finding.metadata?.kind === "sca") {
    const m = finding.metadata;
    return `SNITCH-SCA-${m.ecosystem.toUpperCase()}-${slug(m.packageName).toUpperCase()}`;
  }
  return finding.cwe
    ? `SNITCH-${finding.cwe.toUpperCase()}`
    : `SNITCH-${slug(finding.title).toUpperCase()}`;
}

function helpUriFor(finding: Finding): string {
  if (finding.metadata?.kind === "sca" && finding.metadata.advisoryUrl) {
    return finding.metadata.advisoryUrl;
  }
  if (finding.cwe) {
    const num = finding.cwe.replace(/[^0-9]/g, "");
    if (num) return `https://cwe.mitre.org/data/definitions/${num}.html`;
  }
  return "https://snitchplugin.com";
}

function ruleShortDescription(finding: Finding): string {
  if (finding.metadata?.kind === "sca") {
    return `Vulnerable dependency: ${finding.metadata.ecosystem}/${finding.metadata.packageName}`;
  }
  return finding.title;
}

function ruleFullDescription(finding: Finding): string {
  if (finding.metadata?.kind === "sca") {
    return `One or more known vulnerabilities affect ${finding.metadata.ecosystem} package ${finding.metadata.packageName}. See individual results for CVE details and the linked advisory.`;
  }
  return finding.risk;
}

function resultMessage(finding: Finding): string {
  if (finding.metadata?.kind === "sca") {
    const m = finding.metadata;
    return `${m.ecosystem}/${m.packageName}@${m.packageVersion} — ${m.vulnId}: ${m.summary}`;
  }
  return `${finding.title}. ${finding.risk}`;
}

/**
 * Stable per-finding fingerprint. GHAS uses partialFingerprints to track
 * a finding across runs — to persist dismiss / triage state when lines
 * shift. We hash (ruleId + file + risk) so small line moves don't break
 * dedup, but the same finding in a different file or with a different
 * underlying rule does get a fresh alert.
 */
function fingerprint(finding: Finding, ruleId: string): string {
  return createHash("sha256")
    .update(`${ruleId}|${finding.file}|${finding.title}|${finding.risk}`)
    .digest("hex");
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function buildHelpMarkdown(f: Finding): string {
  let md = `## ${f.title}\n\n${f.risk}\n`;
  if (f.fix) md += `\n### Suggested fix\n\n${f.fix}\n`;
  const tags = [f.cwe, f.owasp].filter(Boolean);
  if (tags.length) md += `\n_${tags.join(" · ")}_\n`;
  md += `\n---\nDetected by [Snitch](https://snitchplugin.com).`;
  return md;
}

export function findingsToSarif(
  findings: Finding[],
  toolVersion = "1.0.0"
): string {
  const rulesByid = new Map<string, { rule: SarifRule; index: number }>();
  const results: SarifResult[] = [];

  for (const f of findings) {
    const ruleId = ruleIdFor(f);

    if (!rulesByid.has(ruleId)) {
      const isSca = f.metadata?.kind === "sca";
      const rule: SarifRule = {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: ruleShortDescription(f) },
        fullDescription: { text: ruleFullDescription(f) },
        help: { text: f.fix || f.risk, markdown: buildHelpMarkdown(f) },
        helpUri: helpUriFor(f),
        defaultConfiguration: { level: SEVERITY_LEVEL[f.severity] },
        properties: {
          tags: [
            "security",
            ...(isSca ? ["external/cwe/cwe-1395", "supply-chain"] : []),
            ...(f.cwe ? [`external/cwe/${f.cwe.toLowerCase()}`] : []),
            ...(f.owasp ? [f.owasp] : []),
          ],
          precision: "high",
          "problem.severity": SEVERITY_PROBLEM[f.severity],
          "security-severity": SEVERITY_SCORE[f.severity],
        },
      };
      rulesByid.set(ruleId, { rule, index: rulesByid.size });
    }

    const ruleEntry = rulesByid.get(ruleId)!;
    results.push({
      ruleId,
      ruleIndex: ruleEntry.index,
      level: SEVERITY_LEVEL[f.severity],
      message: { text: resultMessage(f) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
            region: f.line ? { startLine: f.line } : undefined,
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: fingerprint(f, ruleId),
      },
      properties: { "security-severity": SEVERITY_SCORE[f.severity] },
    });
  }

  const doc: SarifDocument = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Snitch",
            organization: "Snitch",
            version: toolVersion,
            semanticVersion: toolVersion,
            informationUri: "https://snitchplugin.com",
            rules: Array.from(rulesByid.values()).map((e) => e.rule),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}
