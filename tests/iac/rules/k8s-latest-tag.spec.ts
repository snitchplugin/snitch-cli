import { describe, expect, it } from "vitest";
import { k8sLatestTagRule } from "../../../src/_shared/iac/rules/k8s-latest-tag.js";
import { parseKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("IAC-K8S-LATEST-TAG", () => {
  it("flags an image pinned to :latest", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx:latest
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sLatestTagRule.check(r!)?.evidence).toContain("latest");
  });

  it("flags an image with no tag", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: nginx
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sLatestTagRule.check(r!)?.evidence).toContain("no tag");
  });

  it("does not flag a digest-pinned image with a registry-port hostname", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata: { name: x }
spec:
  containers:
    - name: app
      image: registry.local:5000/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
`;
    const [r] = parseKubernetes(yaml, "pod.yaml");
    expect(k8sLatestTagRule.check(r!)).toBeNull();
  });

  it("does not flag a versioned tag", () => {
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
    expect(k8sLatestTagRule.check(r!)).toBeNull();
  });
});
