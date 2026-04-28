export type Severity = "Critical" | "High" | "Medium" | "Low";

export type ProviderName =
  | "openrouter"
  | "anthropic"
  | "openai"
  | "google"
  | "copilot";

export interface Finding {
  title: string;
  severity: Severity;
  file: string;
  line?: number;
  evidence: string;
  risk: string;
  fix: string;
  cwe?: string;
  owasp?: string;
  confidence?: "low" | "medium" | "high";
  /** Optional structured metadata. SCA findings populate this so the
   *  renderer can group by package and link to the advisory. AI code
   *  findings leave it undefined. */
  metadata?: FindingMetadata;
}

export type FindingMetadata =
  | {
      kind: "sca";
      ecosystem: string;
      packageName: string;
      packageVersion: string;
      vulnId: string;
      /** GHSA / NVD / advisory link, used as the canonical "learn more" URL. */
      advisoryUrl?: string;
      /** Human-readable summary line (one sentence, ~150 chars). */
      summary: string;
      /** Suggested upgrade target if known. */
      fixedVersion?: string;
    }
  | {
      kind: "dca";
      /** Distinguishes "unused dependency" from "dead file" within DCA. */
      subkind: "unused-dep" | "dead-file";
      ecosystem?: string;
      packageName?: string;
      manifestPath?: string;
    };

export interface AnalyzeArgs {
  apiKey: string;
  model: string;
  methodology: string;
  files: Array<{ path: string; content: string; patch: string }>;
  maxOutputTokens?: number;
}

export interface AnalyzeResult {
  findings: Finding[];
  summary: string;
  inputTokens: number;
  outputTokens: number;
}

export interface ProviderAdapter {
  name: ProviderName;
  defaultModel: string;
  analyze(args: AnalyzeArgs): Promise<AnalyzeResult>;
}
