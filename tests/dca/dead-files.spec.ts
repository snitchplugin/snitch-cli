import { describe, it, expect } from "vitest";
import { analyzeDeadFiles } from "../../src/_shared/dca/dead-files.js";

describe("analyzeDeadFiles", () => {
  it("flags files with no inbound imports", () => {
    const findings = analyzeDeadFiles({
      files: [
        { path: "src/index.ts", content: `import { a } from "./a";` },
        { path: "src/a.ts", content: `export const a = 1;` },
        { path: "src/orphan.ts", content: `export const x = 1;` },
      ],
    });
    expect(findings.map((f) => f.path)).toEqual(["src/orphan.ts"]);
  });

  it("resolves directory imports via index files", () => {
    const findings = analyzeDeadFiles({
      files: [
        { path: "src/index.ts", content: `import { x } from "./b";` },
        { path: "src/b/index.ts", content: `export const x = 1;` },
      ],
    });
    expect(findings).toHaveLength(0);
  });

  it("treats Python __init__.py as entry; flags isolated module", () => {
    const findings = analyzeDeadFiles({
      files: [
        { path: "pkg/__init__.py", content: `from .core import run` },
        { path: "pkg/core.py", content: `def run(): pass` },
        { path: "pkg/orphan.py", content: `def x(): pass` },
      ],
    });
    expect(findings.map((f) => f.path)).toEqual(["pkg/orphan.py"]);
  });

  it("test files are entry-point-equivalent", () => {
    const findings = analyzeDeadFiles({
      files: [
        { path: "src/util.ts", content: `export const u = 1;` },
        { path: "src/util.test.ts", content: `import { u } from "./util";` },
      ],
    });
    // util.ts is reached from util.test.ts (test = entry); both reachable.
    expect(findings).toHaveLength(0);
  });

  it("respects package.json `main` as entry", () => {
    const findings = analyzeDeadFiles({
      files: [
        { path: "package.json", content: JSON.stringify({ main: "./dist/main.js" }) },
        { path: "dist/main.js", content: `require("./helpers");` },
        { path: "dist/helpers.js", content: `module.exports = {};` },
      ],
    });
    expect(findings).toHaveLength(0);
  });

  it("emits a single summary finding when > 50 candidates", () => {
    const files: { path: string; content: string }[] = [];
    for (let i = 0; i < 60; i++) {
      files.push({ path: `src/orphan${i}.ts`, content: `export const x${i} = 1;` });
    }
    const findings = analyzeDeadFiles({ files });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.path).toBe("(repository)");
    expect(findings[0]?.packageName).toMatch(/files/);
  });
});
