// Walk the file list we already have in memory and route each to a parser.
// Match by basename for fixed-name manifests; .csproj is matched by regex.
import type { ManifestParser } from "./types.js";
import { npmParser } from "./parsers/npm.js";
import { pythonParser } from "./parsers/python.js";
import { goParser } from "./parsers/go.js";
import { rustParser } from "./parsers/rust.js";
import { rubyParser } from "./parsers/ruby.js";
import { javaParser } from "./parsers/java.js";
import { phpParser } from "./parsers/php.js";
import { dotnetParser } from "./parsers/dotnet.js";

export const PARSERS: ManifestParser[] = [
  npmParser,
  pythonParser,
  goParser,
  rustParser,
  rubyParser,
  javaParser,
  phpParser,
  dotnetParser,
];

const CSPROJ_RE = /\.csproj$/i;

export interface ManifestMatch {
  parser: ManifestParser;
  file: { path: string; content: string };
}

function basename(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? path : path.slice(idx + 1);
}

export function discoverManifests(
  files: { path: string; content: string }[],
): ManifestMatch[] {
  const out: ManifestMatch[] = [];
  for (const file of files) {
    const base = basename(file.path);
    let matched: ManifestParser | undefined;
    for (const parser of PARSERS) {
      if (parser.filenames.includes(base)) {
        matched = parser;
        break;
      }
    }
    // .csproj is routed to the dotnet parser via filename suffix
    if (!matched && CSPROJ_RE.test(base)) matched = dotnetParser;
    if (matched) out.push({ parser: matched, file });
  }
  return out;
}
