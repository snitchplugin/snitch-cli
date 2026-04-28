import { describe, expect, it } from "vitest";
import { k8sRunAsRootRule } from "../../../src/_shared/iac/rules/k8s-run-as-root.js";
import { parseKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("IAC-K8S-RUN-AS-ROOT", () => {
  it("flags a Pod with no securityContext", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: hello }
spec:
  containers:
    - name: app
      image: nginx:1.25.0
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sRunAsRootRule.check(r!)).not.toBeNull();
  });

  it("does not flag a Pod with runAsNonRoot at the pod level", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: hello }
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: app
      image: nginx:1.25.0
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sRunAsRootRule.check(r!)).toBeNull();
  });

  it("does not flag a Deployment with runAsUser: 1000 at the container level", () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.0
          securityContext:
            runAsUser: 1000
`;
    const [r] = parseKubernetes(yaml, "deploy.yaml");
    expect(k8sRunAsRootRule.check(r!)).toBeNull();
  });
});
