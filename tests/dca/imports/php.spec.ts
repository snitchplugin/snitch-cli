import { describe, it, expect } from "vitest";
import { phpExtractor } from "../../../src/_shared/dca/imports/php.js";

describe("phpExtractor", () => {
  it("extracts top vendor segment", () => {
    const r = phpExtractor.extract(
      `<?php\nuse Symfony\\HttpFoundation\\Request;\nuse Doctrine\\ORM\\EntityManager;`,
      "F.php",
    );
    expect(r.has("symfony")).toBe(true);
    expect(r.has("doctrine")).toBe(true);
  });

  it("handles aliased + multiple use lines", () => {
    const r = phpExtractor.extract(
      `<?php\nuse Monolog\\Logger as Log;\nuse Guzzle\\Http\\Client;`,
      "F.php",
    );
    expect(r.has("monolog")).toBe(true);
    expect(r.has("guzzle")).toBe(true);
  });
});
