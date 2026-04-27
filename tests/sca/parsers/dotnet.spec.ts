import { describe, expect, it } from "vitest";
import { dotnetParser } from "../../../src/_shared/sca/parsers/dotnet.js";
import { CSPROJ, PACKAGES_LOCK_JSON } from "./_fixtures.js";

describe("dotnetParser: packages.lock.json", () => {
  const deps = dotnetParser.parse(PACKAGES_LOCK_JSON, "packages.lock.json");
  it("flattens TFM groups into a single dep list", () => {
    expect(deps.length).toBe(2);
    expect(deps.find((d) => d.name === "Newtonsoft.Json")).toMatchObject({
      ecosystem: "NuGet",
      version: "13.0.3",
    });
    expect(deps.find((d) => d.name === "Serilog")?.version).toBe("3.1.1");
  });
});

describe("dotnetParser: csproj", () => {
  const deps = dotnetParser.parse(CSPROJ, "src/Demo.csproj");
  it("collects PackageReference Include/Version attributes", () => {
    expect(deps.length).toBe(2);
    expect(deps.find((d) => d.name === "Newtonsoft.Json")?.version).toBe("13.0.3");
    expect(deps.find((d) => d.name === "Serilog")?.version).toBe("3.1.1");
  });
});
