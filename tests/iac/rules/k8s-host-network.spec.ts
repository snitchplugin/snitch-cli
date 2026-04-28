import { describe, expect, it } from "vitest";
import { k8sHostNetworkRule } from "../../../src/_shared/iac/rules/k8s-host-network.js";
import { parseKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("IAC-K8S-HOST-NETWORK", () => {
  it("flags hostNetwork: true", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25.0
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sHostNetworkRule.check(r!)?.evidence).toContain("hostNetwork");
  });

  it("flags hostPID: true on a Deployment", () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: app
          image: nginx:1.25.0
`;
    const [r] = parseKubernetes(yaml, "deploy.yaml");
    expect(k8sHostNetworkRule.check(r!)?.evidence).toContain("hostPID");
  });

  it("does not flag a regular pod", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sHostNetworkRule.check(r!)).toBeNull();
  });
});
