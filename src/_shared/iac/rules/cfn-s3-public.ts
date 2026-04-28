// IAC-CFN-S3-PUBLIC — same intent as IAC-AWS-S3-PUBLIC, but for
// CloudFormation `AWS::S3::Bucket` resources.
//
// CFN exposes the bucket-level controls under two distinct properties:
//   - AccessControl: "PublicRead" | "PublicReadWrite"
//   - PublicAccessBlockConfiguration: { Block...: true|false }
// CFN templates often have both set; the PAB block at false overrides the
// otherwise-private ACL, so we check both independently.
import type { IacRule, ResourceContext } from "../types.js";

export const cfnS3PublicRule: IacRule = {
  id: "IAC-CFN-S3-PUBLIC",
  title: "S3 bucket allows public access (CloudFormation)",
  description:
    "The CloudFormation bucket exposes a public AccessControl value or disables one of the " +
    "PublicAccessBlockConfiguration flags. PAB is the account-level safety net for accidental " +
    "object-level public ACLs; flipping any block flag to false re-opens that vector.",
  severity: "Critical",
  frameworks: ["cloudformation"],
  check(ctx: ResourceContext) {
    if (ctx.resourceType !== "AWS::S3::Bucket") return null;
    if (typeof ctx.body !== "object") return null;
    const props = ((ctx.body as Record<string, unknown>)["Properties"] ?? {}) as Record<string, unknown>;
    const accessControl = props["AccessControl"];
    if (accessControl === "PublicRead" || accessControl === "PublicReadWrite") {
      return {
        evidence: `${ctx.resourceName} sets AccessControl: ${String(accessControl)}`,
        fix: "Remove the AccessControl property (default is Private) and add a PublicAccessBlockConfiguration with all four Block* set to true.",
      };
    }
    const pab = props["PublicAccessBlockConfiguration"];
    if (pab && typeof pab === "object") {
      const flipped: string[] = [];
      for (const key of [
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
      ]) {
        const v = (pab as Record<string, unknown>)[key];
        if (v === false || v === "false") flipped.push(key);
      }
      if (flipped.length > 0) {
        return {
          evidence: `${ctx.resourceName} disables: ${flipped.join(", ")}`,
          fix: "Set every Block* property to true. If a public bucket is intentional, remove the PublicAccessBlockConfiguration entirely so the account-level block stays in effect.",
        };
      }
    }
    return null;
  },
};
