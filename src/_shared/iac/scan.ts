// High-level IaC entry point. Mirrors sca/scan.ts and dca/scan.ts:
// orchestrate parsers + rules, return Snitch Findings ready to merge with
// AI / SCA / DCA findings in the main scan flow.
import type { Finding } from "../providers/types.js";
import { discoverFramework } from "./discover.js";
import { parseTerraform } from "./parsers/terraform.js";
import { parseCloudFormation } from "./parsers/cloudformation.js";
import { parseKubernetes } from "./parsers/kubernetes.js";
import { parseDockerfile } from "./parsers/dockerfile.js";
import { RULES } from "./rules/index.js";
import type { IacFinding, IacFramework, ResourceContext } from "./types.js";

export interface IacScanInput {
  files: { path: string; content: string }[];
}

export interface IacScanResult {
  findings: Finding[];
  resourcesScanned: number;
  rulesFlagged: number;
}

export async function runIacScan(input: IacScanInput): Promise<IacScanResult> {
  let resourcesScanned = 0;
  const iacFindings: IacFinding[] = [];

  for (const file of input.files) {
    const framework = discoverFramework(file);
    if (!framework) continue;

    let resources: ResourceContext[];
    try {
      resources = parseFile(framework, file.content, file.path);
    } catch {
      // A malformed manifest shouldn't kill the whole scan — same posture
      // SCA takes when a single lockfile fails to parse.
      continue;
    }
    resourcesScanned += resources.length;

    for (const resource of resources) {
      for (const rule of RULES) {
        if (!rule.frameworks.includes(framework)) continue;
        let result: { evidence: string; fix: string } | null;
        try {
          result = rule.check(resource);
        } catch {
          // A rule misbehaving on a weird input shouldn't take down the
          // whole pass — keep going so the rest of the rules still ship.
          continue;
        }
        if (!result) continue;
        iacFindings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          filePath: resource.filePath,
          line: resource.line,
          resourceType: resource.resourceType,
          resourceName: resource.resourceName,
          evidence: result.evidence,
          fix: result.fix,
          framework,
        });
      }
    }
  }

  const findings = iacFindings.map(toFinding);
  return { findings, resourcesScanned, rulesFlagged: iacFindings.length };
}

function parseFile(
  framework: IacFramework,
  content: string,
  filePath: string,
): ResourceContext[] {
  switch (framework) {
    case "terraform":
      return parseTerraform(content, filePath);
    case "cloudformation":
      return parseCloudFormation(content, filePath);
    case "kubernetes":
      return parseKubernetes(content, filePath);
    case "dockerfile":
      return parseDockerfile(content, filePath);
  }
}

function toFinding(f: IacFinding): Finding {
  return {
    title: `IaC misconfiguration: ${f.title}`,
    severity: f.severity,
    file: f.filePath,
    line: f.line,
    evidence: f.evidence,
    risk: f.description,
    fix: f.fix,
    // Most IaC rules don't have a one-to-one CWE mapping; downstream renderers
    // already handle undefined gracefully.
    cwe: undefined,
    confidence: "high",
    metadata: {
      kind: "iac",
      framework: f.framework,
      ruleId: f.ruleId,
      resourceType: f.resourceType,
      resourceName: f.resourceName,
    },
  };
}
