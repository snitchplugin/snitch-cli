import { describe, expect, it } from "vitest";
import { discoverFramework } from "../../src/_shared/iac/discover.js";

describe("discoverFramework", () => {
  it("routes by extension when unambiguous", () => {
    expect(discoverFramework({ path: "main.tf", content: "" })).toBe("terraform");
    expect(discoverFramework({ path: "infra/Dockerfile", content: "" })).toBe("dockerfile");
    expect(discoverFramework({ path: "Dockerfile.web", content: "" })).toBe("dockerfile");
    expect(discoverFramework({ path: "build.dockerfile", content: "" })).toBe("dockerfile");
  });

  it("sniffs YAML/JSON for cloudformation", () => {
    expect(
      discoverFramework({
        path: "stack.yaml",
        content: "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  X: { Type: AWS::S3::Bucket }",
      }),
    ).toBe("cloudformation");
    expect(
      discoverFramework({
        path: "stack.json",
        content: '{"Resources":{"X":{"Type":"AWS::S3::Bucket"}}}',
      }),
    ).toBe("cloudformation");
  });

  it("sniffs YAML for kubernetes", () => {
    expect(
      discoverFramework({
        path: "deploy.yaml",
        content: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n",
      }),
    ).toBe("kubernetes");
  });

  it("returns null for unrecognized YAML (e.g. GitHub Actions)", () => {
    expect(
      discoverFramework({
        path: ".github/workflows/ci.yml",
        content: "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
      }),
    ).toBeNull();
  });

  it("returns null for unsupported extensions", () => {
    expect(discoverFramework({ path: "src/index.ts", content: "" })).toBeNull();
    expect(discoverFramework({ path: "README.md", content: "" })).toBeNull();
  });
});
