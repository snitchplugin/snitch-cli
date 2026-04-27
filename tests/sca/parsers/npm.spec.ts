import { describe, expect, it } from "vitest";
import { npmParser } from "../../../src/_shared/sca/parsers/npm.js";
import { PACKAGE_LOCK_V1, PACKAGE_LOCK_V3, PNPM_LOCK_V9, YARN_LOCK_V1 } from "./_fixtures.js";

describe("npmParser: package-lock.json v3", () => {
  const deps = npmParser.parse(PACKAGE_LOCK_V3, "package-lock.json");
  it("extracts every package entry", () => {
    expect(deps.length).toBeGreaterThanOrEqual(3);
    const names = deps.map((d) => d.name).sort();
    expect(names).toEqual(expect.arrayContaining(["lodash", "chalk", "ansi-styles"]));
  });
  it("returns npm ecosystem and correct versions", () => {
    const lodash = deps.find((d) => d.name === "lodash");
    expect(lodash).toMatchObject({ ecosystem: "npm", version: "4.17.21", manifestPath: "package-lock.json" });
  });
});

describe("npmParser: package-lock.json v1", () => {
  it("walks transitive dependencies recursively", () => {
    const deps = npmParser.parse(PACKAGE_LOCK_V1, "pkg/package-lock.json");
    const names = deps.map((d) => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("chalk");
    expect(names).toContain("ansi-styles");
  });
});

describe("npmParser: yarn.lock", () => {
  it("parses entries via @yarnpkg/parsers", () => {
    const deps = npmParser.parse(YARN_LOCK_V1, "yarn.lock");
    expect(deps.length).toBe(2);
    const lodash = deps.find((d) => d.name === "lodash");
    expect(lodash?.version).toBe("4.17.21");
    const chalk = deps.find((d) => d.name === "chalk");
    expect(chalk?.version).toBe("5.3.0");
  });
});

describe("npmParser: pnpm-lock.yaml", () => {
  it("parses v9-style name@version keys including scoped names", () => {
    const deps = npmParser.parse(PNPM_LOCK_V9, "pnpm-lock.yaml");
    const byName = Object.fromEntries(deps.map((d) => [d.name, d.version]));
    expect(byName["lodash"]).toBe("4.17.21");
    expect(byName["chalk"]).toBe("5.3.0");
    expect(byName["@types/node"]).toBe("20.14.0");
  });
});

describe("npmParser: malformed input", () => {
  it("returns [] for empty content", () => {
    expect(npmParser.parse("", "package-lock.json")).toEqual([]);
  });
  it("returns [] for invalid JSON without throwing", () => {
    expect(npmParser.parse("{not json", "package-lock.json")).toEqual([]);
  });
  it("returns [] for unknown filename", () => {
    expect(npmParser.parse(PACKAGE_LOCK_V3, "package.json")).toEqual([]);
  });
  it("returns [] for empty pnpm lockfile", () => {
    expect(npmParser.parse("lockfileVersion: '9.0'\n", "pnpm-lock.yaml")).toEqual([]);
  });
});
