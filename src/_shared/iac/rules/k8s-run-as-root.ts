// IAC-K8S-RUN-AS-ROOT — flag Pods/Deployments where containers run as root.
//
// Default Kubernetes behavior is "run whatever UID the image's USER directive
// says, falling back to UID 0 if unset." Most public images don't set USER,
// so unless the workload's PodSecurityContext or container securityContext
// explicitly says "non-root, please," it's running as root by default.
//
// The rule is satisfied (clean) when at least one of these is true at the
// container level (or inherited from podSpec):
//   - securityContext.runAsNonRoot: true
//   - securityContext.runAsUser: <non-zero integer>
import type { IacRule, ResourceContext } from "../types.js";
import { collectPodSpecs, walkK8sContainers } from "./_helpers.js";

export const k8sRunAsRootRule: IacRule = {
  id: "IAC-K8S-RUN-AS-ROOT",
  title: "Container may run as root",
  description:
    "No container in this workload (and no inherited PodSecurityContext) declares runAsNonRoot " +
    "or sets runAsUser to a non-zero UID. Containers default to root, which makes a container " +
    "escape much more impactful.",
  severity: "High",
  frameworks: ["kubernetes"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    // Only workload kinds carry containers; skip Service / ConfigMap / etc.
    const podSpecs = collectPodSpecs(ctx.body);
    if (podSpecs.length === 0) return null;

    for (const { container, podSpec } of walkK8sContainers(ctx.body)) {
      if (isNonRoot(container) || isNonRoot(podSpec)) continue;
      const cname = typeof container["name"] === "string" ? container["name"] : "(unnamed)";
      return {
        evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} container "${cname}" has no runAsNonRoot or runAsUser set`,
        fix: "Add `securityContext: { runAsNonRoot: true, runAsUser: 1000 }` (or any non-zero UID) to either the pod spec or the container. Verify the image's filesystem permissions allow the chosen UID to read what it needs.",
      };
    }
    return null;
  },
};

function isNonRoot(obj: unknown): boolean {
  if (!obj || typeof obj !== "object") return false;
  const sc = (obj as Record<string, unknown>)["securityContext"];
  if (!sc || typeof sc !== "object") return false;
  const s = sc as Record<string, unknown>;
  if (s["runAsNonRoot"] === true) return true;
  const uid = s["runAsUser"];
  if (typeof uid === "number" && uid !== 0) return true;
  if (typeof uid === "string" && uid !== "0" && uid !== "" && /^\d+$/.test(uid)) return true;
  return false;
}
