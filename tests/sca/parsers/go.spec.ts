import { describe, expect, it } from "vitest";
import { goParser } from "../../../src/_shared/sca/parsers/go.js";
import { GO_SUM } from "./_fixtures.js";

describe("goParser: go.sum", () => {
  const deps = goParser.parse(GO_SUM, "go.sum");
  it("dedupes the /go.mod companion lines", () => {
    expect(deps.length).toBe(2);
  });
  it("extracts module + version", () => {
    const spew = deps.find((d) => d.name === "github.com/davecgh/go-spew");
    expect(spew?.version).toBe("v1.1.1");
    expect(spew?.ecosystem).toBe("Go");
    const errs = deps.find((d) => d.name === "github.com/pkg/errors");
    expect(errs?.version).toBe("v0.9.1");
  });
});
