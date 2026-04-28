// IAC-DOCKER-RUN-AS-ROOT — flag Dockerfiles with no USER instruction.
//
// Default Docker behavior: if no USER is set, the container runs as root.
// Combined with default Kubernetes pod settings (no runAsNonRoot, no
// runAsUser), this means root in the container — not as catastrophic as
// host root, but a much shorter chain to abuse a container escape CVE.
//
// We treat "USER appears anywhere in the Dockerfile" as sufficient. If the
// final stage has a USER instruction we count it as set. Multi-stage builds
// with USER only in an intermediate stage and not in the final stage will
// still be flagged because we look at the LAST stage's USER state.
import type { IacRule, ResourceContext } from "../types.js";
import type { DockerInstruction } from "../parsers/dockerfile.js";

export const dockerRunAsRootRule: IacRule = {
  id: "IAC-DOCKER-RUN-AS-ROOT",
  title: "Dockerfile does not set USER (runs as root)",
  description:
    "The final build stage of this Dockerfile has no USER instruction. The image will run as " +
    "root by default, expanding the blast radius of any container escape or in-process RCE.",
  severity: "High",
  frameworks: ["dockerfile"],
  check(ctx: ResourceContext) {
    const insns = instructionsFrom(ctx);
    if (!insns) return null;
    // Walk forward, tracking which stage we're in. Each FROM starts a new
    // stage; we record the most recent USER value within that stage. The
    // final stage's USER state determines the runtime user.
    let lastUser: string | null = null;
    for (const ins of insns) {
      if (ins.instruction === "from") {
        lastUser = null; // new stage resets USER
      } else if (ins.instruction === "user") {
        lastUser = ins.args.split(/\s+/)[0] ?? null;
      }
    }
    if (lastUser === null) {
      return {
        evidence: `Dockerfile at ${ctx.filePath} never sets USER in its final stage`,
        fix: "Add a non-root user near the end of the final stage: `RUN adduser -D -u 1000 app && USER app` (alpine) or equivalent for your base image. Confirm the chosen UID owns or can read everything COPY'd in.",
      };
    }
    if (lastUser === "0" || lastUser.toLowerCase() === "root") {
      return {
        evidence: `Dockerfile at ${ctx.filePath} explicitly sets USER ${lastUser} in its final stage`,
        fix: "Switch to a non-zero UID such as `USER 1000` and ensure the user has access to the application files (chown during COPY: `COPY --chown=1000:1000 ...`).",
      };
    }
    return null;
  },
};

function instructionsFrom(ctx: ResourceContext): DockerInstruction[] | null {
  if (typeof ctx.body !== "object") return null;
  const insns = (ctx.body as Record<string, unknown>)["instructions"];
  if (!Array.isArray(insns)) return null;
  return insns as DockerInstruction[];
}
