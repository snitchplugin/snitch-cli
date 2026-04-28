import { describe, it, expect } from "vitest";
import { npmExtractor } from "../../../src/_shared/dca/imports/npm.js";

describe("npmExtractor", () => {
  it("extracts ESM imports", () => {
    const r = npmExtractor.extract(
      `import React from 'react';\nimport { foo } from "lodash";\nexport { bar } from 'axios';`,
      "f.ts",
    );
    expect(r.has("react")).toBe(true);
    expect(r.has("lodash")).toBe(true);
    expect(r.has("axios")).toBe(true);
  });

  it("extracts require + dynamic import", () => {
    const r = npmExtractor.extract(
      `const x = require('zod');\nimport('next/router').then(...)`,
      "f.js",
    );
    expect(r.has("zod")).toBe(true);
    expect(r.has("next")).toBe(true);
  });

  it("normalizes scoped + subpath specifiers", () => {
    const r = npmExtractor.extract(
      `import { z } from "@scope/pkg/sub/path";\nimport "lodash/get";`,
      "f.ts",
    );
    expect(r.has("@scope/pkg")).toBe(true);
    expect(r.has("lodash")).toBe(true);
  });

  it("skips relative + absolute + node:builtin", () => {
    const r = npmExtractor.extract(
      `import a from './a';\nimport b from '../b';\nimport c from '/abs';\nimport fs from 'node:fs';`,
      "f.ts",
    );
    expect(r.size).toBe(0);
  });
});
