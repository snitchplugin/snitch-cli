import { describe, expect, it } from "vitest";
import { parseKubernetes, looksLikeKubernetes } from "../../../src/_shared/iac/parsers/kubernetes.js";

describe("parseKubernetes", () => {
  it("parses a single Pod manifest", () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
    - name: app
      image: nginx:1.25.0
`;
    const out = parseKubernetes(yaml, "pod.yaml");
    expect(out.length).toBe(1);
    expect(out[0]!.resourceType).toBe("Pod");
    expect(out[0]!.resourceName).toBe("hello");
  });

  it("splits multi-document files via ---", () => {
    const yaml = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  k: v
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.0
`;
    const out = parseKubernetes(yaml, "all.yaml");
    expect(out.map((r) => r.resourceType)).toEqual(["ConfigMap", "Deployment"]);
  });

  it("skips documents without apiVersion or kind", () => {
    const yaml = `
foo: bar
---
apiVersion: v1
kind: Service
metadata:
  name: s
`;
    const out = parseKubernetes(yaml, "mixed.yaml");
    expect(out.length).toBe(1);
    expect(out[0]!.resourceType).toBe("Service");
  });
});

describe("looksLikeKubernetes", () => {
  it("requires both apiVersion and kind in the first doc", () => {
    expect(looksLikeKubernetes("apiVersion: v1\nkind: Pod\n")).toBe(true);
    expect(looksLikeKubernetes("apiVersion: v1\nname: foo\n")).toBe(false);
    expect(looksLikeKubernetes("kind: Pod\n")).toBe(false);
  });
});
