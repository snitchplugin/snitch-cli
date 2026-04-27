import { describe, expect, it } from "vitest";
import { discoverManifests } from "../../src/_shared/sca/discover.js";
import { dotnetParser } from "../../src/_shared/sca/parsers/dotnet.js";
import { goParser } from "../../src/_shared/sca/parsers/go.js";
import { javaParser } from "../../src/_shared/sca/parsers/java.js";
import { npmParser } from "../../src/_shared/sca/parsers/npm.js";
import { pythonParser } from "../../src/_shared/sca/parsers/python.js";
import { rubyParser } from "../../src/_shared/sca/parsers/ruby.js";
import { rustParser } from "../../src/_shared/sca/parsers/rust.js";

describe("discoverManifests", () => {
  it("routes mixed manifest files to the right parser", () => {
    const files = [
      { path: "package-lock.json", content: "{}" },
      { path: "frontend/yarn.lock", content: "" },
      { path: "services/api/requirements.txt", content: "" },
      { path: "service/go.sum", content: "" },
      { path: "rust/Cargo.lock", content: "" },
      { path: "ruby_app/Gemfile.lock", content: "" },
      { path: "java/pom.xml", content: "<project/>" },
      { path: "dotnet/packages.lock.json", content: "{}" },
      { path: "dotnet/Demo.csproj", content: "<Project/>" },
    ];
    const matches = discoverManifests(files);
    const byPath = Object.fromEntries(matches.map((m) => [m.file.path, m.parser]));
    expect(byPath["package-lock.json"]).toBe(npmParser);
    expect(byPath["frontend/yarn.lock"]).toBe(npmParser);
    expect(byPath["services/api/requirements.txt"]).toBe(pythonParser);
    expect(byPath["service/go.sum"]).toBe(goParser);
    expect(byPath["rust/Cargo.lock"]).toBe(rustParser);
    expect(byPath["ruby_app/Gemfile.lock"]).toBe(rubyParser);
    expect(byPath["java/pom.xml"]).toBe(javaParser);
    expect(byPath["dotnet/packages.lock.json"]).toBe(dotnetParser);
    expect(byPath["dotnet/Demo.csproj"]).toBe(dotnetParser);
    expect(matches.length).toBe(files.length);
  });

  it("skips non-manifest files", () => {
    const files = [
      { path: "src/index.ts", content: "" },
      { path: "README.md", content: "" },
      { path: ".github/workflows/ci.yml", content: "" },
      { path: "package.json", content: "{}" }, // not a lockfile, ignored
    ];
    expect(discoverManifests(files)).toEqual([]);
  });

  it("matches by basename even for deeply nested paths", () => {
    const files = [{ path: "a/b/c/d/pnpm-lock.yaml", content: "" }];
    const matches = discoverManifests(files);
    expect(matches.length).toBe(1);
    expect(matches[0]?.parser).toBe(npmParser);
  });
});
