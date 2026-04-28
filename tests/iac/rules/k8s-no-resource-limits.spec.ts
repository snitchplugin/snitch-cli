import { describe, expect, it } from "vitest";
import { k8sNoResourceLimitsRule } from "../../../src/_shared/iac/rules/k8s-no-resource-limits.js";
import { parseKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("IAC-K8S-NO-RESOURCE-LIMITS", () => {
  it("flags a container without limits", () => {
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
    expect(k8sNoResourceLimitsRule.check(r!)).not.toBeNull();
  });

  it("flags a container with only one of cpu/memory limits", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
      resources:
        limits:
          cpu: "500m"
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sNoResourceLimitsRule.check(r!)?.evidence).toContain("memory");
  });

  it("does not flag a container with both cpu and memory limits", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sNoResourceLimitsRule.check(r!)).toBeNull();
  });
});
