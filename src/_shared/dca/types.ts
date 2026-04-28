// Shared types for the dead-code-analysis (DCA) module.
// DepEntry / Ecosystem are reused from sca/ — DCA cross-references the
// SCA pass's manifest parsing to find unused declarations.
import type { DepEntry, Ecosystem } from "../sca/types.js";

export type { DepEntry, Ecosystem };

export interface ImportExtractor {
  /** File extensions this extractor handles (lowercase, with leading dot). */
  extensions: string[];
  /** Parse a source file, return the set of distinct package names imported.
   *  Naming convention varies by ecosystem; the analyzer normalizes per-eco
   *  before comparing against declared deps. Skip relative / built-in /
   *  intra-crate imports. Best-effort regex; AST parsing is out of scope. */
  extract(content: string, path: string): Set<string>;
}

export type DcaSubkind = "unused-dep" | "dead-file";

export interface DcaFinding {
  subkind: DcaSubkind;
  /** For unused-dep: the manifest file. For dead-file: the dead file path. */
  path: string;
  ecosystem?: Ecosystem;
  packageName?: string;
}

// DcaMetadata is structurally a match for the "dca" branch of FindingMetadata
// in providers/types.ts. Keep these two in lockstep.
export interface DcaMetadata {
  kind: "dca";
  subkind: DcaSubkind;
  ecosystem?: string;
  packageName?: string;
  manifestPath?: string;
}
