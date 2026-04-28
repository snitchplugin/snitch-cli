import { describe, it, expect } from "vitest";
import { extractDirectDeps, analyzeUnusedDeps } from "../../src/_shared/dca/unused-deps.js";
import type { Ecosystem } from "../../src/_shared/dca/types.js";

describe("extractDirectDeps", () => {
  it("parses package.json dependencies + devDependencies", () => {
    const deps = extractDirectDeps([
      {
        path: "package.json",
        content: JSON.stringify({
          dependencies: { react: "^18.0.0", lodash: "^4.0.0" },
          devDependencies: { vitest: "^2.0.0" },
        }),
      },
    ]);
    expect(deps.map((d) => d.name).sort()).toEqual(["lodash", "react", "vitest"]);
    expect(deps.every((d) => d.scope === "direct")).toBe(true);
  });

  it("parses requirements.txt skipping VCS / -r lines", () => {
    const deps = extractDirectDeps([
      {
        path: "requirements.txt",
        content: `requests==2.31.0\n# comment\n-r other.txt\nfoo @ git+https://x\nflask>=2`,
      },
    ]);
    const names = deps.map((d) => d.name);
    expect(names).toContain("requests");
    expect(names).toContain("flask");
    expect(names).not.toContain("foo");
  });

  it("parses Cargo.toml [dependencies]", () => {
    const deps = extractDirectDeps([
      {
        path: "Cargo.toml",
        content: `[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n[dev-dependencies]\ncriterion = "0.5"`,
      },
    ]);
    expect(deps.map((d) => d.name).sort()).toEqual(["criterion", "serde", "tokio"]);
  });

  it("parses go.mod skipping indirect", () => {
    const deps = extractDirectDeps([
      {
        path: "go.mod",
        content: `module example\nrequire (\n  github.com/foo/bar v1.0.0\n  github.com/baz/qux v2.0.0 // indirect\n)`,
      },
    ]);
    const names = deps.map((d) => d.name);
    expect(names).toContain("github.com/foo/bar");
    expect(names).not.toContain("github.com/baz/qux");
  });

  it("parses pom.xml direct deps", () => {
    const deps = extractDirectDeps([
      {
        path: "pom.xml",
        content: `<project><dependencies><dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8</version></dependency></dependencies></project>`,
      },
    ]);
    expect(deps.map((d) => d.name)).toEqual(["com.google.code.gson:gson"]);
  });
});

describe("analyzeUnusedDeps", () => {
  function imports(map: Record<string, string[]>): Map<Ecosystem, Set<string>> {
    const out = new Map<Ecosystem, Set<string>>();
    for (const [eco, list] of Object.entries(map)) out.set(eco as Ecosystem, new Set(list));
    return out;
  }

  it("flags an npm dep with no matching import", () => {
    const findings = analyzeUnusedDeps({
      deps: [
        { ecosystem: "npm", name: "react", version: "*", manifestPath: "package.json", scope: "direct" },
        { ecosystem: "npm", name: "lodash", version: "*", manifestPath: "package.json", scope: "direct" },
      ],
      importsByEcosystem: imports({ npm: ["react"] }),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.packageName).toBe("lodash");
  });

  it("PEP 503 normalization: my_pkg dep matches my-pkg import", () => {
    const findings = analyzeUnusedDeps({
      deps: [{ ecosystem: "PyPI", name: "my_pkg", version: "*", manifestPath: "requirements.txt", scope: "direct" }],
      importsByEcosystem: imports({ PyPI: ["my_pkg"] }),
    });
    expect(findings).toHaveLength(0);
  });

  it("crates.io: serde_json declared and imported as serde_json matches", () => {
    const findings = analyzeUnusedDeps({
      deps: [{ ecosystem: "crates.io", name: "serde_json", version: "*", manifestPath: "Cargo.toml", scope: "direct" }],
      importsByEcosystem: imports({ "crates.io": ["serde_json"] }),
    });
    expect(findings).toHaveLength(0);
  });

  it("Maven loose match: gson coord matches com.google.gson import", () => {
    const findings = analyzeUnusedDeps({
      deps: [{ ecosystem: "Maven", name: "com.google.code.gson:gson", version: "*", manifestPath: "pom.xml", scope: "direct" }],
      importsByEcosystem: imports({ Maven: ["com.google.gson"] }),
    });
    expect(findings).toHaveLength(0);
  });

  it("Packagist: vendor/pkg matches `Vendor` import", () => {
    const findings = analyzeUnusedDeps({
      deps: [{ ecosystem: "Packagist", name: "symfony/http-foundation", version: "*", manifestPath: "composer.json", scope: "direct" }],
      importsByEcosystem: imports({ Packagist: ["symfony"] }),
    });
    expect(findings).toHaveLength(0);
  });

  it("skips transitive deps", () => {
    const findings = analyzeUnusedDeps({
      deps: [
        { ecosystem: "npm", name: "deep-transitive", version: "*", manifestPath: "package.json", scope: "transitive" },
      ],
      importsByEcosystem: imports({ npm: [] }),
    });
    expect(findings).toHaveLength(0);
  });
});
