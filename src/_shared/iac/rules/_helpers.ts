// Shared parsing helpers for rule check() functions. Kept tiny — anything
// that grows past one screen belongs in a per-framework helper module.

// HCL value cleanup: strip surrounding quotes from a captured Terraform value.
// Terraform values come back as raw strings from our minimal parser; e.g.
// `acl = "public-read"` yields the literal `"public-read"` (with quotes).
export function unquoteHcl(value: string): string {
  const t = value.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

// Walk a parsed K8s object and yield every container spec (containers AND
// initContainers) regardless of whether it's a Pod, Deployment, StatefulSet,
// DaemonSet, Job, CronJob — they all nest container specs in similar paths.
export function* walkK8sContainers(doc: unknown): Generator<{
  container: Record<string, unknown>;
  podSpec: Record<string, unknown>;
  containerKind: "container" | "initContainer";
}> {
  const podSpecs = collectPodSpecs(doc);
  for (const podSpec of podSpecs) {
    const containers = arrayOf(podSpec["containers"]);
    for (const c of containers) {
      if (c && typeof c === "object") {
        yield { container: c as Record<string, unknown>, podSpec, containerKind: "container" };
      }
    }
    const initContainers = arrayOf(podSpec["initContainers"]);
    for (const c of initContainers) {
      if (c && typeof c === "object") {
        yield { container: c as Record<string, unknown>, podSpec, containerKind: "initContainer" };
      }
    }
  }
}

// Collect the PodSpec object from any workload kind we recognize.
// - Pod: `spec`
// - Deployment / StatefulSet / DaemonSet / ReplicaSet / Job: `spec.template.spec`
// - CronJob: `spec.jobTemplate.spec.template.spec`
// We don't enumerate kinds explicitly; just probe the known shape paths so
// future workload kinds with the same layout (e.g. CRDs that mirror Deployment)
// pick up the same checks.
export function collectPodSpecs(doc: unknown): Record<string, unknown>[] {
  if (!doc || typeof doc !== "object") return [];
  const out: Record<string, unknown>[] = [];
  const root = doc as Record<string, unknown>;
  const spec = root["spec"];
  if (spec && typeof spec === "object") {
    const s = spec as Record<string, unknown>;
    // Pod (kind === "Pod")
    if (Array.isArray(s["containers"])) out.push(s);
    // Deployment / StatefulSet / DaemonSet / Job
    const template = s["template"];
    if (template && typeof template === "object") {
      const tmpl = template as Record<string, unknown>;
      const innerSpec = tmpl["spec"];
      if (innerSpec && typeof innerSpec === "object") out.push(innerSpec as Record<string, unknown>);
    }
    // CronJob
    const jobTemplate = s["jobTemplate"];
    if (jobTemplate && typeof jobTemplate === "object") {
      const inner = ((jobTemplate as Record<string, unknown>)["spec"] as Record<string, unknown> | undefined)?.["template"];
      if (inner && typeof inner === "object") {
        const innerSpec = (inner as Record<string, unknown>)["spec"];
        if (innerSpec && typeof innerSpec === "object") out.push(innerSpec as Record<string, unknown>);
      }
    }
  }
  return out;
}

export function arrayOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

// Walk every PolicyDocument Statement object inside a CFN resource's
// Properties. Used by IAM rules — covers AWS::IAM::Policy, AWS::IAM::Role
// (Policies + AssumeRolePolicyDocument), AWS::IAM::ManagedPolicy.
export function* walkCfnPolicyStatements(props: unknown): Generator<Record<string, unknown>> {
  if (!props || typeof props !== "object") return;
  const p = props as Record<string, unknown>;
  // Direct PolicyDocument (AWS::IAM::Policy, AWS::IAM::ManagedPolicy)
  yield* statementsOf(p["PolicyDocument"]);
  // AssumeRolePolicyDocument (AWS::IAM::Role)
  yield* statementsOf(p["AssumeRolePolicyDocument"]);
  // Inline Policies array (AWS::IAM::Role)
  const inline = arrayOf(p["Policies"]);
  for (const policy of inline) {
    if (policy && typeof policy === "object") {
      yield* statementsOf((policy as Record<string, unknown>)["PolicyDocument"]);
    }
  }
}

function* statementsOf(doc: unknown): Generator<Record<string, unknown>> {
  if (!doc || typeof doc !== "object") return;
  const d = doc as Record<string, unknown>;
  const stmts = d["Statement"];
  if (Array.isArray(stmts)) {
    for (const s of stmts) {
      if (s && typeof s === "object") yield s as Record<string, unknown>;
    }
  } else if (stmts && typeof stmts === "object") {
    yield stmts as Record<string, unknown>;
  }
}

// Test whether an Action / Resource field is "*" or contains "*". Both
// scalar string and array-of-strings are valid in IAM JSON.
export function fieldContainsWildcard(field: unknown): boolean {
  if (typeof field === "string") return field === "*";
  if (Array.isArray(field)) return field.some((v) => v === "*");
  return false;
}
