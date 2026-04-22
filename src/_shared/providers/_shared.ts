import { generateText, type LanguageModel } from "ai";
import type { AnalyzeArgs, AnalyzeResult, Finding, Severity } from "./types.js";

const SEVERITIES: ReadonlySet<Severity> = new Set([
  "Critical",
  "High",
  "Medium",
  "Low",
]);

const MAX_FILE_CHARS = 8000;
const MAX_PATCH_CHARS = 4000;

export function buildPrompt(methodology: string, files: AnalyzeArgs["files"]): string {
  const fileBlocks = files
    .map((f) => {
      const content = f.content.slice(0, MAX_FILE_CHARS);
      const patch = f.patch.slice(0, MAX_PATCH_CHARS);
      return `### File: ${f.path}\n\`\`\`\n${content}\n\`\`\`\n\nDiff:\n\`\`\`diff\n${patch}\n\`\`\``;
    })
    .join("\n\n---\n\n");

  return `You are performing a security audit on a pull request. Use the methodology below to analyze the changed files and report findings.

Return ONLY valid JSON matching this schema (no markdown fences, no prose):
{
  "findings": [
    {
      "title": "Short finding title",
      "severity": "Critical|High|Medium|Low",
      "file": "path/to/file.ts",
      "line": 47,
      "evidence": "exact code snippet",
      "risk": "what could happen",
      "fix": "suggested remediation",
      "cwe": "CWE-89",
      "owasp": "A03:2021 Injection",
      "confidence": "low|medium|high"
    }
  ],
  "summary": "1-2 sentence summary"
}

If no issues are found, return {"findings": [], "summary": "No security issues found in the changed files."}.

---

${methodology}

---

## CHANGED FILES

${fileBlocks}`;
}

interface RawFinding {
  title?: unknown;
  severity?: unknown;
  file?: unknown;
  line?: unknown;
  evidence?: unknown;
  risk?: unknown;
  fix?: unknown;
  cwe?: unknown;
  owasp?: unknown;
  confidence?: unknown;
}

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && SEVERITIES.has(v as Severity);
}

function isConfidence(v: unknown): v is Finding["confidence"] {
  return v === "low" || v === "medium" || v === "high";
}

function coerceFinding(raw: RawFinding): Finding | null {
  if (typeof raw.title !== "string" || !raw.title) return null;
  if (!isSeverity(raw.severity)) return null;
  if (typeof raw.file !== "string" || !raw.file) return null;
  if (typeof raw.evidence !== "string") return null;
  if (typeof raw.risk !== "string") return null;
  if (typeof raw.fix !== "string") return null;

  const finding: Finding = {
    title: raw.title,
    severity: raw.severity,
    file: raw.file,
    evidence: raw.evidence,
    risk: raw.risk,
    fix: raw.fix,
  };
  if (typeof raw.line === "number" && Number.isFinite(raw.line)) finding.line = raw.line;
  if (typeof raw.cwe === "string") finding.cwe = raw.cwe;
  if (typeof raw.owasp === "string") finding.owasp = raw.owasp;
  if (isConfidence(raw.confidence)) finding.confidence = raw.confidence;
  return finding;
}

export function parseResponse(
  text: string,
  usage: { inputTokens?: number; outputTokens?: number } | undefined
): AnalyzeResult {
  const inputTokens = usage?.inputTokens ?? 0;
  const outputTokens = usage?.outputTokens ?? 0;

  const match = text.match(/\{[\s\S]*\}/);
  if (!match) {
    return {
      findings: [],
      summary: "Provider returned no parseable JSON. Treating as no findings.",
      inputTokens,
      outputTokens,
    };
  }

  let parsed: { findings?: unknown; summary?: unknown };
  try {
    parsed = JSON.parse(match[0]);
  } catch {
    return {
      findings: [],
      summary: "Provider response was not valid JSON. Treating as no findings.",
      inputTokens,
      outputTokens,
    };
  }

  const summary =
    typeof parsed.summary === "string" ? parsed.summary : "Audit complete.";
  const rawFindings = Array.isArray(parsed.findings) ? parsed.findings : [];
  const findings: Finding[] = [];
  for (const raw of rawFindings) {
    const f = coerceFinding(raw as RawFinding);
    if (f) findings.push(f);
  }

  return { findings, summary, inputTokens, outputTokens };
}

export async function runScan(
  model: LanguageModel,
  args: AnalyzeArgs
): Promise<AnalyzeResult> {
  const prompt = buildPrompt(args.methodology, args.files);
  const result = await generateText({
    model,
    prompt,
    maxTokens: args.maxOutputTokens ?? 4096,
  });
  return parseResponse(result.text, {
    inputTokens: result.usage?.promptTokens,
    outputTokens: result.usage?.completionTokens,
  });
}
