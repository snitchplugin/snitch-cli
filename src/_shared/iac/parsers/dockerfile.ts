// Parses Dockerfiles. Dockerfiles are line-oriented (with backslash line
// continuations); rules need to reason about ordered instructions (USER may
// appear after multiple RUNs, FROM may be repeated for multi-stage builds).
// We hand each rule the full source plus a parsed instruction list so each
// rule can decide its own state machine.
import type { ResourceContext } from "../types.js";

export interface DockerInstruction {
  /** Lower-cased instruction keyword: "from", "run", "user", "copy", etc. */
  instruction: string;
  /** The instruction's argument string (line continuations already merged). */
  args: string;
  /** 1-indexed line number where the instruction started. */
  line: number;
}

export function parseDockerfile(content: string, filePath: string): ResourceContext[] {
  const instructions: DockerInstruction[] = [];
  const rawLines = content.split(/\r?\n/);
  let i = 0;
  while (i < rawLines.length) {
    const line = rawLines[i] ?? "";
    const trimmed = line.trim();
    // skip blank + comments. `# syntax=` parser directives are also comments
    // for our purposes.
    if (!trimmed || trimmed.startsWith("#")) {
      i++;
      continue;
    }
    const startLine = i + 1; // 1-indexed
    // Merge backslash-line-continuations so multi-line RUN gets seen as one.
    let merged = line;
    while (merged.replace(/\s+$/, "").endsWith("\\") && i + 1 < rawLines.length) {
      merged = merged.replace(/\\\s*$/, "") + " " + (rawLines[i + 1] ?? "");
      i++;
    }
    const m = merged.match(/^\s*([A-Za-z]+)\s+([\s\S]+)$/);
    if (m) {
      instructions.push({
        instruction: m[1]!.toLowerCase(),
        args: m[2]!.trim(),
        line: startLine,
      });
    }
    i++;
  }
  // One ResourceContext per Dockerfile (not per stage). Rules can iterate
  // the parsed instruction list to find FROM/RUN/USER patterns themselves.
  return [
    {
      framework: "dockerfile",
      resourceType: "Dockerfile",
      resourceName: undefined,
      filePath,
      line: 1,
      body: { instructions, raw: content },
    },
  ];
}
