import { describe, it, expect } from "vitest";
import { javaExtractor } from "../../../src/_shared/dca/imports/java.js";

describe("javaExtractor", () => {
  it("extracts dotted namespace, drops trailing class", () => {
    const r = javaExtractor.extract(
      `import com.google.gson.Gson;\nimport org.springframework.web.bind.annotation.RestController;`,
      "F.java",
    );
    expect(r.has("com.google.gson")).toBe(true);
    expect(r.has("org.springframework.web.bind.annotation")).toBe(true);
  });

  it("handles wildcard imports", () => {
    const r = javaExtractor.extract(`import org.junit.jupiter.api.*;`, "F.java");
    expect(r.has("org.junit.jupiter.api")).toBe(true);
  });

  it("skips JDK + handles kotlin file", () => {
    const r = javaExtractor.extract(
      `import java.util.List;\nimport javax.annotation.PostConstruct;\nimport kotlinx.coroutines.flow.Flow;`,
      "F.kt",
    );
    expect(r.has("kotlinx.coroutines.flow")).toBe(true);
    expect(Array.from(r).some((s) => s.startsWith("java"))).toBe(false);
  });
});
