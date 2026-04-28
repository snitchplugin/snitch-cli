// Parses CloudFormation templates (YAML or JSON). One ResourceContext per
// entry under the top-level `Resources:` map. We rely on the standard
// js-yaml + JSON.parse combo; CFN intrinsic functions (`!Ref`, `!Sub`,
// `!GetAtt`) come back as objects after js-yaml's CORE_SCHEMA, which is
// fine for our shallow rule checks.
import yaml from "js-yaml";
import type { ResourceContext } from "../types.js";

interface CfnResource {
  Type?: string;
  Properties?: unknown;
}

interface CfnTemplate {
  AWSTemplateFormatVersion?: string;
  Resources?: Record<string, CfnResource>;
}

export function parseCloudFormation(content: string, filePath: string): ResourceContext[] {
  let doc: unknown;
  try {
    // CFN-style intrinsic shorthand (`!Ref Foo`, `!Sub "${X}"`) is not in
    // js-yaml's default schema. Define minimal yaml types so loading doesn't
    // throw on a real CFN template — we don't need to interpret the values,
    // just keep the surrounding structure intact.
    doc = yaml.load(content, { schema: cfnSchema });
  } catch {
    try {
      doc = JSON.parse(content);
    } catch {
      return [];
    }
  }
  if (!doc || typeof doc !== "object") return [];
  const tpl = doc as CfnTemplate;
  const resources = tpl.Resources;
  if (!resources || typeof resources !== "object") return [];
  const out: ResourceContext[] = [];
  for (const [name, resource] of Object.entries(resources)) {
    if (!resource || typeof resource !== "object") continue;
    const resourceType = typeof resource.Type === "string" ? resource.Type : "";
    if (!resourceType) continue;
    out.push({
      framework: "cloudformation",
      resourceType,
      resourceName: name,
      filePath,
      // Best-effort line lookup: find the resource's logical id at column 4-ish.
      // We don't use a tracking parser, so this is approximate.
      line: findResourceLine(content, name),
      body: (resource as unknown) as Record<string, unknown>,
    });
  }
  return out;
}

// Build a yaml schema that no-ops every CFN intrinsic shorthand tag. This
// turns `!Ref X` into the string `X`, `!Sub "..."` into `...`, etc. — good
// enough that downstream rules see something stable instead of failing.
const CFN_TAGS = [
  "Ref", "Sub", "GetAtt", "GetAZs", "ImportValue", "Join", "Select", "Split",
  "FindInMap", "Base64", "Cidr", "Equals", "If", "Not", "And", "Or",
  "Condition", "Transform",
];
const cfnTypes = CFN_TAGS.flatMap((tag) => [
  new yaml.Type(`!${tag}`, { kind: "scalar", construct: (data) => data }),
  new yaml.Type(`!${tag}`, { kind: "sequence", construct: (data) => data }),
  new yaml.Type(`!${tag}`, { kind: "mapping", construct: (data) => data }),
]);
const cfnSchema = yaml.DEFAULT_SCHEMA.extend(cfnTypes);

function findResourceLine(content: string, name: string): number | undefined {
  // Match `^  Foo:` (YAML, two-space indent) OR `"Foo":` (JSON). Lightweight;
  // returns undefined if we can't pin it down rather than guessing wrong.
  const yamlRe = new RegExp(`^[ \\t]+${escapeRe(name)}\\s*:`, "m");
  const m = yamlRe.exec(content);
  if (m) return lineOfOffset(content, m.index);
  const jsonRe = new RegExp(`"${escapeRe(name)}"\\s*:`);
  const j = jsonRe.exec(content);
  if (j) return lineOfOffset(content, j.index);
  return undefined;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function lineOfOffset(s: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < s.length; i++) {
    if (s[i] === "\n") line++;
  }
  return line;
}

// Detect: does this YAML/JSON look like a CloudFormation template?
// Used by the discoverer when the file extension alone isn't enough.
export function looksLikeCloudFormation(content: string): boolean {
  if (/^\s*"?AWSTemplateFormatVersion"?\s*:/m.test(content)) return true;
  // Resources block with at least one AWS::Foo::Bar typed entry.
  if (/Resources\s*:/m.test(content) && /Type\s*:\s*["']?AWS::/m.test(content)) return true;
  if (/"Resources"\s*:/m.test(content) && /"Type"\s*:\s*"AWS::/m.test(content)) return true;
  return false;
}
