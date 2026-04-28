import { describe, it, expect } from "vitest";
import { goExtractor } from "../../../src/_shared/dca/imports/go.js";

describe("goExtractor", () => {
  it("extracts single-line import", () => {
    const r = goExtractor.extract(`import "github.com/user/repo"`, "f.go");
    expect(r.has("github.com/user/repo")).toBe(true);
  });

  it("extracts block imports", () => {
    const r = goExtractor.extract(
      `import (\n  "fmt"\n  "github.com/foo/bar"\n  "github.com/baz/qux"\n)`,
      "f.go",
    );
    expect(r.has("fmt")).toBe(true);
    expect(r.has("github.com/foo/bar")).toBe(true);
    expect(r.has("github.com/baz/qux")).toBe(true);
  });

  it("handles aliased imports", () => {
    const r = goExtractor.extract(
      `import alias "github.com/user/repo"\nimport _ "github.com/side/effect"`,
      "f.go",
    );
    expect(r.has("github.com/user/repo")).toBe(true);
    expect(r.has("github.com/side/effect")).toBe(true);
  });
});
