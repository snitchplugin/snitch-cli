import { describe, expect, it } from "vitest";
import { dockerLatestBaseRule } from "../../../src/_shared/iac/rules/docker-latest-base.js";
import { parseDockerfile } from "../../../src/_shared/iac/parsers/dockerfile.js";

describe("IAC-DOCKER-LATEST-BASE", () => {
  it("flags FROM image:latest in the final stage", () => {
    const df = `FROM alpine:latest
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerLatestBaseRule.check(r!)?.evidence).toContain("latest");
  });

  it("flags FROM with no tag", () => {
    const df = `FROM alpine
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerLatestBaseRule.check(r!)?.evidence).toContain("no tag");
  });

  it("does not flag a digest-pinned base", () => {
    const df = `FROM alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerLatestBaseRule.check(r!)).toBeNull();
  });

  it("does not flag a versioned tag", () => {
    const df = `FROM alpine:3.19
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerLatestBaseRule.check(r!)).toBeNull();
  });
});
