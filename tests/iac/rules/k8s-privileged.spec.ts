import { describe, expect, it } from "vitest";
import { k8sPrivilegedRule } from "../../../src/_shared/iac/rules/k8s-privileged.js";
import { parseKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("IAC-K8S-PRIVILEGED", () => {
  it("flags a container with privileged: true", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
      securityContext:
        privileged: true
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sPrivilegedRule.check(r!)).not.toBeNull();
  });

  it("does not flag a container without privileged", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
      securityContext:
        runAsNonRoot: true
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sPrivilegedRule.check(r!)).toBeNull();
  });
});
