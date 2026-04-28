// IAC-DOCKER-CURL-PIPE-SH — flag `RUN curl ... | sh` (and wget variants).
//
// The pattern is shorthand for "execute whatever this URL serves at the
// time the image is built." It bypasses the package signing / checksumming
// the underlying base image's package manager would have done, and bakes
// the result into a layer with no audit trail of which version was pulled.
// Even if the upstream is trusted today, the pattern means a future
// supply-chain compromise of that URL silently lands in your image.
//
// We deliberately don't flag every `curl ...` — only the pipe-to-shell
// variant, because that's the high-signal anti-pattern.
import type { IacRule, ResourceContext } from "../types.js";
import type { DockerInstruction } from "../parsers/dockerfile.js";

// Match `curl ... | sh` or `curl ... | bash`, with optional flags between.
// Also catch `wget -O- ... | sh` and `... | sudo sh`. The `[^|]*` is a guard
// against matching the next pipe stage.
const PIPE_SH_RE = /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/;

export const dockerCurlPipeShRule: IacRule = {
  id: "IAC-DOCKER-CURL-PIPE-SH",
  title: "Dockerfile pipes a remote download directly to a shell",
  description:
    "A RUN instruction fetches a remote script and executes it without verification " +
    "(`curl ... | sh` or `wget ... | sh`). This bakes whatever the URL serves at build time " +
    "into the image, bypassing package signing and creating a silent supply chain dependency.",
  severity: "High",
  frameworks: ["dockerfile"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    const insns = (ctx.body as Record<string, unknown>)["instructions"];
    if (!Array.isArray(insns)) return null;
    for (const ins of insns as DockerInstruction[]) {
      if (ins.instruction !== "run") continue;
      if (PIPE_SH_RE.test(ins.args)) {
        return {
          evidence: `RUN at line ${ins.line} fetches a script and pipes it to a shell`,
          fix: "Download the script to a file, verify its checksum or signature, and only then execute it. Better still: install the tool from the base image's package manager so signature verification is automatic.",
        };
      }
    }
    return null;
  },
};
