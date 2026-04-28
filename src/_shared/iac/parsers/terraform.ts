// Parses Terraform `*.tf` files via regex + brace-depth tracking.
//
// Why no real HCL parser: HCL2 has interpolations, heredocs, dynamic blocks,
// for_each, conditionals — a true parser is a project of its own. For v1 we
// only need to extract the body of `resource "<type>" "<name>" {...}` blocks
// well enough for shallow key=value matching. The cost of a false negative
// here is "we miss a misconfig in a heavily templated module"; the cost of
// pulling in a full HCL parser is a 200KB+ dep that breaks our no-new-deps
// rule and adds a parse-error surface for malformed user files.
import type { ResourceContext } from "../types.js";

const RESOURCE_HEADER = /^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{/gm;

/**
 * Parse a `.tf` file. One ResourceContext per `resource "type" "name" {}` block.
 * Skips data sources / variables / locals / providers — those don't carry
 * the kind of misconfig our v1 rules look at.
 */
export function parseTerraform(content: string, filePath: string): ResourceContext[] {
  const out: ResourceContext[] = [];
  RESOURCE_HEADER.lastIndex = 0;
  let header: RegExpExecArray | null;
  while ((header = RESOURCE_HEADER.exec(content)) !== null) {
    const resourceType = header[1]!;
    const resourceName = header[2]!;
    // Body starts at the char after the `{`. Walk forward, tracking depth,
    // until we close the outer brace. Strings (single + double quoted) and
    // line / block comments are masked so a `}` inside them doesn't unbalance.
    const bodyStart = RESOURCE_HEADER.lastIndex;
    const bodyEnd = findMatchingBrace(content, bodyStart);
    if (bodyEnd === -1) continue; // unterminated — bail rather than guess
    const rawBody = content.slice(bodyStart, bodyEnd);
    const line = lineOfOffset(content, header.index);
    out.push({
      framework: "terraform",
      resourceType,
      resourceName,
      filePath,
      line,
      body: { ...parseAttributes(rawBody), __raw: rawBody },
    });
    // Continue scanning AFTER this block so we don't accidentally re-enter it
    // as a child block via a nested `resource` keyword (rare but possible).
    RESOURCE_HEADER.lastIndex = bodyEnd + 1;
  }
  return out;
}

// Find the offset of the `}` that closes the block opened at `start`
// (which is the position immediately after the opening `{`). Returns -1 if
// unbalanced. We mask quoted strings and comments so braces inside them
// don't throw off the depth counter.
function findMatchingBrace(s: string, start: number): number {
  let depth = 1;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    // line comment: `#` or `//`
    if (c === "#" || (c === "/" && s[i + 1] === "/")) {
      const nl = s.indexOf("\n", i);
      if (nl === -1) return -1;
      i = nl + 1;
      continue;
    }
    // block comment: `/* */`
    if (c === "/" && s[i + 1] === "*") {
      const end = s.indexOf("*/", i + 2);
      if (end === -1) return -1;
      i = end + 2;
      continue;
    }
    // strings: skip past matching quote, respecting backslash escapes
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      while (i < s.length) {
        if (s[i] === "\\") {
          i += 2;
          continue;
        }
        if (s[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    // heredoc: `<<EOF` ... `EOF` on its own line. Cheap detection — we just
    // skip to the next newline starting with the marker.
    if (c === "<" && s[i + 1] === "<") {
      const nl = s.indexOf("\n", i);
      if (nl === -1) return -1;
      const markerMatch = s.slice(i, nl).match(/^<<-?([A-Za-z_][A-Za-z0-9_]*)/);
      if (markerMatch) {
        const marker = markerMatch[1]!;
        const endRe = new RegExp(`\\n\\s*${marker}\\b`);
        const m = endRe.exec(s.slice(nl));
        if (!m) return -1;
        i = nl + m.index + m[0].length;
        continue;
      }
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

// Pull `key = value` pairs out of a block body into a flat dict. Nested
// `key { ... }` blocks are stored as a raw string under the key (per-rule
// callers can re-scan). Multiple sibling blocks with the same key (e.g.
// repeated `ingress {}` under a security group) collapse into an array of
// raw bodies — security-group rules need that to enumerate every ingress.
function parseAttributes(body: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let i = 0;
  while (i < body.length) {
    // skip whitespace + comments
    while (i < body.length) {
      const c = body[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === ",") {
        i++;
      } else if (c === "#" || (c === "/" && body[i + 1] === "/")) {
        const nl = body.indexOf("\n", i);
        i = nl === -1 ? body.length : nl + 1;
      } else if (c === "/" && body[i + 1] === "*") {
        const end = body.indexOf("*/", i + 2);
        i = end === -1 ? body.length : end + 2;
      } else break;
    }
    if (i >= body.length) break;
    // identifier
    const idMatch = body.slice(i).match(/^[A-Za-z_][A-Za-z0-9_-]*/);
    if (!idMatch) {
      i++;
      continue;
    }
    const key = idMatch[0];
    i += key.length;
    while (body[i] === " " || body[i] === "\t") i++;
    const next = body[i];
    if (next === "=") {
      // attribute: key = <value-up-to-newline-or-comma-respecting-strings-and-braces>
      i++;
      while (body[i] === " " || body[i] === "\t") i++;
      const valueStart = i;
      const valueEnd = findValueEnd(body, i);
      const raw = body.slice(valueStart, valueEnd).trim();
      out[key] = raw;
      i = valueEnd;
    } else if (next === "{") {
      // nested block: capture until matching brace as raw string
      const blockEnd = findMatchingBrace(body, i + 1);
      if (blockEnd === -1) break;
      const blockBody = body.slice(i + 1, blockEnd);
      const existing = out[key];
      if (Array.isArray(existing)) existing.push(blockBody);
      else if (typeof existing === "string") out[key] = [existing, blockBody];
      else out[key] = blockBody;
      i = blockEnd + 1;
    } else {
      // bare identifier with no = or { — skip past it
      i++;
    }
  }
  return out;
}

// Walk to the end of an attribute value: a newline at depth 0, the end of
// the string, or a comma at depth 0. Tracks string + brace nesting so we
// don't truncate `["a", "b"]` or a multi-line `{ ... }` literal.
function findValueEnd(s: string, start: number): number {
  let depth = 0;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      while (i < s.length) {
        if (s[i] === "\\") {
          i += 2;
          continue;
        }
        if (s[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") {
      if (depth === 0) return i;
      depth--;
    } else if ((c === "\n" || c === ",") && depth === 0) {
      return i;
    }
    i++;
  }
  return i;
}

function lineOfOffset(s: string, offset: number): number {
  // 1-indexed line number for display in findings.
  let line = 1;
  for (let i = 0; i < offset && i < s.length; i++) {
    if (s[i] === "\n") line++;
  }
  return line;
}
