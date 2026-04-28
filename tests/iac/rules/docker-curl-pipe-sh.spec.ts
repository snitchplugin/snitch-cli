import { describe, expect, it } from "vitest";
import { dockerCurlPipeShRule } from "../../../src/_shared/iac/rules/docker-curl-pipe-sh.js";
import { parseDockerfile } from "../../../src/_shared/iac/parsers/dockerfile.js";

describe("IAC-DOCKER-CURL-PIPE-SH", () => {
  it("flags curl ... | sh", () => {
    const df = `FROM alpine:3.19
RUN curl -fsSL https://example.com/install.sh | sh
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerCurlPipeShRule.check(r!)).not.toBeNull();
  });

  it("flags wget ... | bash", () => {
    const df = `FROM ubuntu:22.04
RUN wget -qO- https://example.com/script | bash
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerCurlPipeShRule.check(r!)).not.toBeNull();
  });

  it("does not flag a curl that downloads to a file then verifies", () => {
    const df = `FROM alpine:3.19
RUN curl -fsSLo /tmp/install.sh https://example.com/install.sh && sha256sum -c /tmp/install.sh.sha256 && sh /tmp/install.sh
USER 1000
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerCurlPipeShRule.check(r!)).toBeNull();
  });
});
