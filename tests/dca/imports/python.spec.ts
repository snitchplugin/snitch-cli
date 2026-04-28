import { describe, it, expect } from "vitest";
import { pythonExtractor } from "../../../src/_shared/dca/imports/python.js";

describe("pythonExtractor", () => {
  it("extracts simple imports + from imports", () => {
    const r = pythonExtractor.extract(
      `import requests\nfrom flask import Flask\nimport numpy as np`,
      "f.py",
    );
    expect(r.has("requests")).toBe(true);
    expect(r.has("flask")).toBe(true);
    expect(r.has("numpy")).toBe(true);
  });

  it("handles dotted imports", () => {
    const r = pythonExtractor.extract(
      `import django.contrib.auth\nfrom sqlalchemy.orm import Session`,
      "f.py",
    );
    expect(r.has("django")).toBe(true);
    expect(r.has("sqlalchemy")).toBe(true);
  });

  it("skips relative imports", () => {
    const r = pythonExtractor.extract(
      `from . import foo\nfrom .utils import bar\nfrom ..parent import baz`,
      "f.py",
    );
    expect(r.size).toBe(0);
  });
});
