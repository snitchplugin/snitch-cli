import { describe, expect, it } from "vitest";
import { phpParser } from "../../../src/_shared/sca/parsers/php.js";
import { COMPOSER_LOCK } from "./_fixtures.js";

describe("phpParser: composer.lock", () => {
  const deps = phpParser.parse(COMPOSER_LOCK, "composer.lock");
  it("merges packages and packages-dev sections", () => {
    expect(deps.length).toBe(3);
    const names = deps.map((d) => d.name).sort();
    expect(names).toEqual(["monolog/monolog", "phpunit/phpunit", "psr/log"]);
  });
  it("uses Packagist ecosystem with full vendor/name and exact version", () => {
    const monolog = deps.find((d) => d.name === "monolog/monolog");
    expect(monolog).toMatchObject({ ecosystem: "Packagist", version: "3.5.0" });
  });
});
