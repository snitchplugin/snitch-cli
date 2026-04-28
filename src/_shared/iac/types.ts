// Shared types for the infrastructure-as-code (IaC) misconfiguration scan.
// Mirrors the SCA / DCA module shape: a deterministic pass that produces
// Snitch Findings ready to merge with AI-generated findings.
import type { Severity } from "../providers/types.js";

export type IacFramework = "terraform" | "cloudformation" | "kubernetes" | "dockerfile";

export interface ResourceContext {
  framework: IacFramework;
  /** Free-form resource type: "aws_s3_bucket", "AWS::IAM::Role", "Pod", "Dockerfile". */
  resourceType: string;
  /** Resource name when extractable (HCL local name, K8s metadata.name, etc.). */
  resourceName?: string;
  /** Repo-relative path of the file. */
  filePath: string;
  /** Approximate line number in the file when extractable. */
  line?: number;
  /** Free-form structured data the rule needs to do its check. Per-parser:
   *  Terraform parser hands rules a flat key=>raw-value dict + a `__raw` body string;
   *  CFN/K8s parsers hand rules the parsed YAML/JSON sub-tree;
   *  Dockerfile parser hands rules the full source string (rules walk lines themselves
   *  so each rule can decide its own state machine — USER may appear after RUN, etc). */
  body: Record<string, unknown> | string;
}

export interface IacRule {
  /** Stable rule id, e.g. "IAC-AWS-S3-PUBLIC". Used as the canonical key in
   *  both the report renderer and the metadata payload. */
  id: string;
  title: string;
  description: string;
  severity: Severity;
  /** What frameworks this rule applies to (filters before evaluation so the
   *  per-rule check() doesn't have to defensively re-check framework). */
  frameworks: IacFramework[];
  /** Returns null when the resource is clean, otherwise an object describing
   *  the violation. Evidence is what we splice into the Finding; fix is the
   *  actionable guidance. Both are short — full prose lives in description. */
  check(ctx: ResourceContext): { evidence: string; fix: string } | null;
}

export interface IacFinding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  line?: number;
  resourceType: string;
  resourceName?: string;
  evidence: string;
  fix: string;
  framework: IacFramework;
}
