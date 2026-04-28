import { describe, expect, it } from "vitest";
import { dockerRunAsRootRule } from "../../../src/_shared/iac/rules/docker-run-as-root.js";
import { parseDockerfile } from "../../../src/_shared/iac/parsers/dockerfile.js";

describe("IAC-DOCKER-RUN-AS-ROOT", () => {
  it("flags a Dockerfile without USER", () => {
    const df = `FROM alpine:3.19
RUN apk add --no-cache curl
CMD ["sh"]
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerRunAsRootRule.check(r!)).not.toBeNull();
  });

  it("flags a Dockerfile that explicitly sets USER root", () => {
    const df = `FROM alpine:3.19
USER root
CMD ["sh"]
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerRunAsRootRule.check(r!)).not.toBeNull();
  });

  it("does not flag a Dockerfile with USER set to a non-root UID in the final stage", () => {
    const df = `FROM golang:1.22 AS build
USER root
RUN go build .

FROM alpine:3.19
COPY --from=build /app /app
USER 1000
CMD ["/app"]
`;
    const [r] = parseDockerfile(df, "Dockerfile");
    expect(dockerRunAsRootRule.check(r!)).toBeNull();
  });
});
