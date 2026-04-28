import { describe, it, expect } from "vitest";
import { routeExtractor } from "../../src/_shared/dca/discover.js";
import { npmExtractor } from "../../src/_shared/dca/imports/npm.js";
import { pythonExtractor } from "../../src/_shared/dca/imports/python.js";
import { goExtractor } from "../../src/_shared/dca/imports/go.js";

describe("routeExtractor", () => {
  it("routes by file extension", () => {
    expect(routeExtractor("src/foo.ts")).toBe(npmExtractor);
    expect(routeExtractor("src/foo.tsx")).toBe(npmExtractor);
    expect(routeExtractor("src/foo.js")).toBe(npmExtractor);
    expect(routeExtractor("a/b/c.py")).toBe(pythonExtractor);
    expect(routeExtractor("main.go")).toBe(goExtractor);
  });

  it("returns undefined for unknown extensions", () => {
    expect(routeExtractor("README.md")).toBeUndefined();
    expect(routeExtractor("Dockerfile")).toBeUndefined();
    expect(routeExtractor("config")).toBeUndefined();
  });

  it("is case-insensitive", () => {
    expect(routeExtractor("Foo.TS")).toBe(npmExtractor);
  });
});
