// IAC-DOCKER-LATEST-BASE — flag FROM lines that pull `:latest` or no tag.
//
// Same reasoning as IAC-K8S-LATEST-TAG: rebuilds become non-deterministic.
// We check the FINAL stage's FROM (the one that produces the image users
// will run); intermediate build stages on `:latest` are noisier and lower
// impact (they only affect build reproducibility, not runtime behavior).
import type { IacRule, ResourceContext } from "../types.js";
import type { DockerInstruction } from "../parsers/dockerfile.js";

export const dockerLatestBaseRule: IacRule = {
  id: "IAC-DOCKER-LATEST-BASE",
  title: "Dockerfile FROM uses :latest or no tag",
  description:
    "The image's final base layer references `:latest` or omits the tag entirely. The base " +
    "image pulled at build time may not match what was tested last week; rollbacks become guesswork.",
  severity: "Medium",
  frameworks: ["dockerfile"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    const insns = (ctx.body as Record<string, unknown>)["instructions"];
    if (!Array.isArray(insns)) return null;
    // Walk the whole list; the LAST FROM is the runtime base.
    let lastFrom: { args: string; line: number } | null = null;
    for (const ins of insns as DockerInstruction[]) {
      if (ins.instruction === "from") lastFrom = { args: ins.args, line: ins.line };
    }
    if (!lastFrom) return null;
    // FROM args may be `image[:tag][@digest] [AS name] [--platform=...]`.
    // Strip --platform= flags and any trailing `AS name`.
    let ref = lastFrom.args
      .replace(/^--platform=\S+\s+/i, "")
      .replace(/\s+AS\s+\S+$/i, "")
      .trim()
      .split(/\s+/)[0] ?? "";
    // Scratch + a leading `$` (build-arg interpolation) are out of scope —
    // a digest-pinned ARG is fine, and we can't statically resolve it.
    if (!ref || ref === "scratch" || ref.startsWith("$")) return null;
    if (ref.includes("@sha256:")) return null; // digest-pinned, ok
    const lastColon = ref.lastIndexOf(":");
    const lastSlash = ref.lastIndexOf("/");
    const tag = lastColon > lastSlash ? ref.slice(lastColon + 1) : "";
    if (!tag) {
      return {
        evidence: `FROM at line ${lastFrom.line}: \`${ref}\` has no tag (defaults to :latest)`,
        fix: `Pin the base image: \`${ref}@sha256:...\` for full immutability, or at minimum a versioned tag like \`${ref}:1.21.0\`.`,
      };
    }
    if (tag === "latest") {
      return {
        evidence: `FROM at line ${lastFrom.line}: \`${ref}\` pinned to :latest`,
        fix: "Replace `:latest` with a specific version tag, ideally an immutable digest reference.",
      };
    }
    return null;
  },
};
