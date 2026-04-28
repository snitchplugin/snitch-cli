// Parses Kubernetes manifests. A K8s file may contain multiple documents
// joined by `---`; each doc with both `apiVersion` and `kind` becomes a
// ResourceContext. We hand the rule the parsed object so it can chase
// nested fields like `spec.template.spec.containers[*].securityContext`
// without re-parsing.
import yaml from "js-yaml";
import type { ResourceContext } from "../types.js";

interface K8sDoc {
  apiVersion?: unknown;
  kind?: unknown;
  metadata?: { name?: unknown };
}

export function parseKubernetes(content: string, filePath: string): ResourceContext[] {
  let docs: unknown[];
  try {
    docs = yaml.loadAll(content);
  } catch {
    return [];
  }
  const out: ResourceContext[] = [];
  for (const doc of docs) {
    if (!doc || typeof doc !== "object") continue;
    const d = doc as K8sDoc;
    if (typeof d.apiVersion !== "string" || typeof d.kind !== "string") continue;
    const name = typeof d.metadata?.name === "string" ? d.metadata.name : undefined;
    out.push({
      framework: "kubernetes",
      resourceType: d.kind,
      resourceName: name,
      filePath,
      // Per-document line lookup is hard with yaml.loadAll (no source map).
      // We surface the file-level line of the kind: line as a hint when there's
      // exactly one doc; for multi-doc we leave it undefined and rely on the
      // resourceName for navigation.
      line: docs.length === 1 ? findKindLine(content) : undefined,
      body: doc as Record<string, unknown>,
    });
  }
  return out;
}

function findKindLine(content: string): number | undefined {
  const m = /^[ \t]*kind\s*:/m.exec(content);
  if (!m) return undefined;
  let line = 1;
  for (let i = 0; i < m.index; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

// Detect: does this YAML look like a Kubernetes manifest? We only check the
// first document because mixing K8s + non-K8s in one file is rare and would
// be ambiguous either way.
export function looksLikeKubernetes(content: string): boolean {
  // apiVersion AND kind in the first document. Multi-doc separator is `---`,
  // so we only scan up to the first one.
  const firstDoc = content.split(/^---\s*$/m)[0] ?? content;
  return /^\s*apiVersion\s*:/m.test(firstDoc) && /^\s*kind\s*:/m.test(firstDoc);
}
