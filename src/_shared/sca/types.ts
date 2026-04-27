export type Ecosystem =
  | "npm"
  | "PyPI"
  | "Go"
  | "crates.io"
  | "RubyGems"
  | "Maven"
  | "Packagist"
  | "NuGet";

export interface DepEntry {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Repo-relative path of the manifest file this dep was parsed from. */
  manifestPath: string;
  /** Optional: was this an explicit (top-level) or transitive dep? */
  scope?: "direct" | "transitive";
}

export interface ManifestParser {
  /** Filenames this parser handles (basename match). */
  filenames: string[];
  /** Parse manifest content, return the deps it declares. */
  parse(content: string, manifestPath: string): DepEntry[];
}
