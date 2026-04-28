// Route a source file to the right import extractor by file extension.
// Opposite pattern from sca/discover (which matches manifest basenames).
import type { ImportExtractor } from "./types.js";
import { npmExtractor } from "./imports/npm.js";
import { pythonExtractor } from "./imports/python.js";
import { goExtractor } from "./imports/go.js";
import { rustExtractor } from "./imports/rust.js";
import { rubyExtractor } from "./imports/ruby.js";
import { javaExtractor } from "./imports/java.js";
import { phpExtractor } from "./imports/php.js";
import { dotnetExtractor } from "./imports/dotnet.js";

export const EXTRACTORS: ImportExtractor[] = [
  npmExtractor,
  pythonExtractor,
  goExtractor,
  rustExtractor,
  rubyExtractor,
  javaExtractor,
  phpExtractor,
  dotnetExtractor,
];

const EXT_TO_EXTRACTOR = new Map<string, ImportExtractor>();
for (const e of EXTRACTORS) {
  for (const ext of e.extensions) EXT_TO_EXTRACTOR.set(ext.toLowerCase(), e);
}

export function routeExtractor(path: string): ImportExtractor | undefined {
  const idx = path.lastIndexOf(".");
  if (idx === -1) return undefined;
  return EXT_TO_EXTRACTOR.get(path.slice(idx).toLowerCase());
}
