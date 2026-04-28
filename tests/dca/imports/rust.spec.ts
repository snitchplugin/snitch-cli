import { describe, it, expect } from "vitest";
import { rustExtractor } from "../../../src/_shared/dca/imports/rust.js";

describe("rustExtractor", () => {
  it("extracts use + extern crate", () => {
    const r = rustExtractor.extract(
      `use serde::Deserialize;\nuse tokio::net::TcpStream;\nextern crate libc;`,
      "f.rs",
    );
    expect(r.has("serde")).toBe(true);
    expect(r.has("tokio")).toBe(true);
    expect(r.has("libc")).toBe(true);
  });

  it("skips std/core/super/self/crate", () => {
    const r = rustExtractor.extract(
      `use std::collections::HashMap;\nuse core::mem;\nuse super::foo;\nuse self::bar;\nuse crate::baz;`,
      "f.rs",
    );
    expect(r.size).toBe(0);
  });

  it("handles pub use", () => {
    const r = rustExtractor.extract(`pub use anyhow::Result;`, "f.rs");
    expect(r.has("anyhow")).toBe(true);
  });
});
