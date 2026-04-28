import { describe, expect, it } from "vitest";
import { parseDockerfile, type DockerInstruction } from "../../../src/_shared/iac/parsers/dockerfile.js";

describe("parseDockerfile", () => {
  it("parses single-line instructions", () => {
    const df = `FROM alpine:3.19
USER 1000
WORKDIR /app
COPY . .
`;
    const out = parseDockerfile(df, "Dockerfile");
    expect(out.length).toBe(1);
    const insns = (out[0]!.body as { instructions: DockerInstruction[] }).instructions;
    expect(insns.map((i) => i.instruction)).toEqual(["from", "user", "workdir", "copy"]);
    expect(insns[0]!.line).toBe(1);
    expect(insns[1]!.line).toBe(2);
  });

  it("merges backslash line continuations", () => {
    const df = `FROM ubuntu:22.04
RUN apt-get update && \\
    apt-get install -y curl && \\
    rm -rf /var/lib/apt/lists/*
`;
    const out = parseDockerfile(df, "Dockerfile");
    const insns = (out[0]!.body as { instructions: DockerInstruction[] }).instructions;
    expect(insns.length).toBe(2);
    expect(insns[1]!.instruction).toBe("run");
    expect(insns[1]!.args).toContain("apt-get install -y curl");
    expect(insns[1]!.line).toBe(2); // RUN started at line 2
  });

  it("ignores blank lines and comments", () => {
    const df = `# syntax=docker/dockerfile:1
# build stage

FROM golang:1.22 AS build

COPY go.mod .
`;
    const out = parseDockerfile(df, "Dockerfile");
    const insns = (out[0]!.body as { instructions: DockerInstruction[] }).instructions;
    expect(insns.map((i) => i.instruction)).toEqual(["from", "copy"]);
  });
});
