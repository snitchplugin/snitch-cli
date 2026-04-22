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
}

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
