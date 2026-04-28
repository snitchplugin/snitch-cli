// IAC-K8S-PRIVILEGED — flag containers with `securityContext.privileged: true`.
//
// Privileged mode disables most container isolation (it's roughly equivalent
// to a docker --privileged run): the container gets all Linux capabilities,
// can access /dev directly, and can mount filesystems. Almost no production
// workload legitimately needs this; the few that do (CSI drivers, certain
// monitoring agents) are typically already exempted from policy scans.
import type { IacRule, ResourceContext } from "../types.js";
import { collectPodSpecs, walkK8sContainers } from "./_helpers.js";

export const k8sPrivilegedRule: IacRule = {
  id: "IAC-K8S-PRIVILEGED",
  title: "Container runs in privileged mode",
  description:
    "A container declares securityContext.privileged: true, which disables most of the " +
    "container isolation Kubernetes provides. A compromised privileged container is " +
    "effectively a node compromise.",
  severity: "Critical",
  frameworks: ["kubernetes"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    if (collectPodSpecs(ctx.body).length === 0) return null;
    for (const { container } of walkK8sContainers(ctx.body)) {
      const sc = container["securityContext"];
      if (sc && typeof sc === "object" && (sc as Record<string, unknown>)["privileged"] === true) {
        const cname = typeof container["name"] === "string" ? container["name"] : "(unnamed)";
        return {
          evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} container "${cname}" sets securityContext.privileged: true`,
          fix: "Remove `privileged: true`. If the workload needs specific kernel capabilities, request them explicitly via `securityContext.capabilities.add` instead — that is far narrower than full privileged mode.",
        };
      }
    }
    return null;
  },
};
