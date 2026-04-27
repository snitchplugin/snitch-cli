import { describe, expect, it } from "vitest";
import { rustParser } from "../../../src/_shared/sca/parsers/rust.js";
import { CARGO_LOCK } from "./_fixtures.js";

describe("rustParser: Cargo.lock", () => {
  const deps = rustParser.parse(CARGO_LOCK, "Cargo.lock");
  it("emits one DepEntry per [[package]]", () => {
    expect(deps.length).toBe(2);
  });
  it("uses crates.io ecosystem and correct versions", () => {
    const serde = deps.find((d) => d.name === "serde");
    expect(serde).toMatchObject({ ecosystem: "crates.io", version: "1.0.193" });
    const tokio = deps.find((d) => d.name === "tokio");
    expect(tokio?.version).toBe("1.35.0");
  });
});
