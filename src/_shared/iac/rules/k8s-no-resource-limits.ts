// IAC-K8S-NO-RESOURCE-LIMITS — flag containers without both CPU and memory
// limits.
//
// Why this isn't High severity: missing limits doesn't grant attacker access,
// it just means a single pod can starve a node. Real impact = noisy-neighbor
// outages and easy DoS for any path that triggers heavy compute. Medium is
// the right tier — a stability issue with a security flavor.
import type { IacRule, ResourceContext } from "../types.js";
import { collectPodSpecs, walkK8sContainers } from "./_helpers.js";

export const k8sNoResourceLimitsRule: IacRule = {
  id: "IAC-K8S-NO-RESOURCE-LIMITS",
  title: "Container has no CPU or memory limits",
  description:
    "A container is missing one or both of resources.limits.cpu / resources.limits.memory. " +
    "Without limits a runaway process (whether a bug or an attacker exhausting resources) can " +
    "take down the entire node.",
  severity: "Medium",
  frameworks: ["kubernetes"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    if (collectPodSpecs(ctx.body).length === 0) return null;
    for (const { container } of walkK8sContainers(ctx.body)) {
      const resources = container["resources"];
      const limits = resources && typeof resources === "object"
        ? (resources as Record<string, unknown>)["limits"]
        : undefined;
      const cpu = limits && typeof limits === "object" ? (limits as Record<string, unknown>)["cpu"] : undefined;
      const mem = limits && typeof limits === "object" ? (limits as Record<string, unknown>)["memory"] : undefined;
      const missing: string[] = [];
      if (cpu === undefined || cpu === null || cpu === "") missing.push("cpu");
      if (mem === undefined || mem === null || mem === "") missing.push("memory");
      if (missing.length > 0) {
        const cname = typeof container["name"] === "string" ? container["name"] : "(unnamed)";
        return {
          evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} container "${cname}" missing resources.limits.${missing.join(" + ")}`,
          fix: "Add `resources.limits.cpu` and `resources.limits.memory`. Pair with `resources.requests` set to typical-load values so the scheduler can pack pods sensibly.",
        };
      }
    }
    return null;
  },
};
