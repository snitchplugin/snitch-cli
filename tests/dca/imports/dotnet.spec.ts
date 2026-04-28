import { describe, it, expect } from "vitest";
import { dotnetExtractor } from "../../../src/_shared/dca/imports/dotnet.js";

describe("dotnetExtractor", () => {
  it("extracts using directives", () => {
    const r = dotnetExtractor.extract(
      `using Newtonsoft.Json;\nusing AutoMapper;`,
      "F.cs",
    );
    expect(r.has("Newtonsoft.Json")).toBe(true);
    expect(r.has("AutoMapper")).toBe(true);
  });

  it("skips System namespaces", () => {
    const r = dotnetExtractor.extract(
      `using System;\nusing System.Collections.Generic;\nusing Serilog;`,
      "F.cs",
    );
    expect(r.has("Serilog")).toBe(true);
    expect(Array.from(r).some((s) => s.startsWith("System"))).toBe(false);
  });
});
