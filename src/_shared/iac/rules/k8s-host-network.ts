// IAC-K8S-HOST-NETWORK — flag pods that share the host's network / PID / IPC.
//
// Sharing the host network namespace lets the pod bind to the node's actual
// ports and snoop traffic on every interface. hostPID lets the pod see/kill
// processes belonging to other pods. hostIPC shares System V IPC + POSIX
// shared memory across pods. None of these are required for typical
// workloads; they're present in CNI plugins, node-exporters, and similar
// system-level pods that should be reviewed separately, not encoded into
// general-purpose Deployment manifests.
import type { IacRule, ResourceContext } from "../types.js";
import { collectPodSpecs } from "./_helpers.js";

const RISKY = ["hostNetwork", "hostPID", "hostIPC"] as const;

export const k8sHostNetworkRule: IacRule = {
  id: "IAC-K8S-HOST-NETWORK",
  title: "Pod shares host network/PID/IPC namespace",
  description:
    "A pod sets hostNetwork, hostPID, or hostIPC to true, breaking out of the network/process " +
    "isolation Kubernetes provides between pods. That's appropriate for a CNI plugin, not for " +
    "an application workload.",
  severity: "High",
  frameworks: ["kubernetes"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    const podSpecs = collectPodSpecs(ctx.body);
    if (podSpecs.length === 0) return null;
    for (const podSpec of podSpecs) {
      const flipped = RISKY.filter((k) => podSpec[k] === true);
      if (flipped.length > 0) {
        return {
          evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} pod spec sets ${flipped.join(", ")} to true`,
          fix: "Remove the host* flags. If the workload genuinely needs host network access (CNI agent, host-level monitoring), document it and exempt this manifest in your IaC scan config.",
        };
      }
    }
    return null;
  },
};
