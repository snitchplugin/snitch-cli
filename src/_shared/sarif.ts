import type { Finding, Severity } from "./providers/types.js";

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  properties: { tags: string[]; "security-severity": string };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints: { primaryLocationLineHash: string };
}

interface SarifDocument {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
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

function ruleIdFor(finding: Finding): string {
  return finding.cwe
    ? `SNITCH-${finding.cwe.toUpperCase()}`
    : `SNITCH-${slug(finding.title).toUpperCase()}`;
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

export function findingsToSarif(
  findings: Finding[],
  toolVersion = "1.0.0"
): string {
  const rulesByid = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const f of findings) {
    const ruleId = ruleIdFor(f);

    if (!rulesByid.has(ruleId)) {
      rulesByid.set(ruleId, {
        id: ruleId,
        shortDescription: { text: f.title },
        fullDescription: { text: f.risk },
        help: { text: f.fix },
        properties: {
          tags: ["security", ...(f.owasp ? [f.owasp] : [])],
          "security-severity": SEVERITY_SCORE[f.severity],
        },
      });
    }

    results.push({
      ruleId,
      level: SEVERITY_LEVEL[f.severity],
      message: { text: `${f.title}. ${f.risk}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
            region: f.line ? { startLine: f.line } : undefined,
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: `${f.file}:${f.line ?? 0}:${f.cwe ?? ruleId}`,
      },
    });
  }

  const doc: SarifDocument = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "snitch",
            version: toolVersion,
            informationUri: "https://snitchplugin.com",
            rules: Array.from(rulesByid.values()),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}
