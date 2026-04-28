import { describe, it, expect } from "vitest";
import { rubyExtractor } from "../../../src/_shared/dca/imports/ruby.js";

describe("rubyExtractor", () => {
  it("extracts top gem name from require", () => {
    const r = rubyExtractor.extract(
      `require 'rails'\nrequire "nokogiri"`,
      "f.rb",
    );
    expect(r.has("rails")).toBe(true);
    expect(r.has("nokogiri")).toBe(true);
  });

  it("strips subpaths and skips stdlib", () => {
    const r = rubyExtractor.extract(
      `require 'rails/all'\nrequire 'json'\nrequire 'sidekiq/web'`,
      "f.rb",
    );
    expect(r.has("rails")).toBe(true);
    expect(r.has("sidekiq")).toBe(true);
    expect(r.has("json")).toBe(false); // stdlib
  });
});
