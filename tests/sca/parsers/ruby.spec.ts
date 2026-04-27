import { describe, expect, it } from "vitest";
import { rubyParser } from "../../../src/_shared/sca/parsers/ruby.js";
import { GEMFILE_LOCK } from "./_fixtures.js";

describe("rubyParser: Gemfile.lock", () => {
  const deps = rubyParser.parse(GEMFILE_LOCK, "Gemfile.lock");
  it("only counts top-level specs (4-space indent), not transitive constraint lines", () => {
    expect(deps.length).toBe(3);
    const names = deps.map((d) => d.name).sort();
    expect(names).toEqual(["activesupport", "rack", "rake"]);
  });
  it("emits RubyGems ecosystem with correct versions", () => {
    const rake = deps.find((d) => d.name === "rake");
    expect(rake).toMatchObject({ ecosystem: "RubyGems", version: "13.1.0" });
    expect(deps.find((d) => d.name === "rack")?.version).toBe("3.0.8");
    expect(deps.find((d) => d.name === "activesupport")?.version).toBe("7.1.2");
  });
});
