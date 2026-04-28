// IAC-K8S-LATEST-TAG — flag container images pinned to `:latest` (or no tag).
//
// `:latest` is reproducibility poison: the image you tested in staging is
// not necessarily the image that gets pulled in prod, and there's no audit
// trail when "latest" silently rolls. Combined with `imagePullPolicy:
// Always` this means every pod restart can pull a different binary.
//
// Medium severity — supply chain integrity issue, not direct CVE.
import type { IacRule, ResourceContext } from "../types.js";
import { collectPodSpecs, walkK8sContainers } from "./_helpers.js";

export const k8sLatestTagRule: IacRule = {
  id: "IAC-K8S-LATEST-TAG",
  title: "Container image uses :latest or no tag",
  description:
    "A container references an image without a pinned tag (or with `:latest`). The image " +
    "pulled at runtime may not match what was tested; rollbacks become guesswork.",
  severity: "Medium",
  frameworks: ["kubernetes"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    if (collectPodSpecs(ctx.body).length === 0) return null;
    for (const { container } of walkK8sContainers(ctx.body)) {
      const image = container["image"];
      if (typeof image !== "string" || !image) continue;
      // Strip any trailing digest reference — `image@sha256:...` is fine
      // and overrides the tag, so we don't flag it.
      if (image.includes("@sha256:")) continue;
      // Split off registry+name from tag. `image:tag`, with potential ports
      // in the registry: `registry.io:5000/foo:latest`. The tag is what
      // follows the LAST colon, but only if there's no `/` after it (a
      // colon in the registry hostport doesn't introduce a tag).
      const lastColon = image.lastIndexOf(":");
      const lastSlash = image.lastIndexOf("/");
      const tag = lastColon > lastSlash ? image.slice(lastColon + 1) : "";
      const cname = typeof container["name"] === "string" ? container["name"] : "(unnamed)";
      if (!tag) {
        return {
          evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} container "${cname}" image "${image}" has no tag (defaults to :latest)`,
          fix: `Pin the image with an immutable digest (e.g. \`${image}@sha256:...\`) or at minimum a versioned tag like \`${image}:1.2.3\`.`,
        };
      }
      if (tag === "latest") {
        return {
          evidence: `${ctx.resourceType}/${ctx.resourceName ?? "(unnamed)"} container "${cname}" image "${image}" pinned to :latest`,
          fix: "Replace `:latest` with a specific version tag, ideally an immutable digest reference (`image@sha256:...`).",
        };
      }
    }
    return null;
  },
};
