// IAC-AWS-S3-PUBLIC — flag S3 buckets readable by the world.
//
// Two distinct shapes can introduce public S3 access in Terraform:
//   1. `aws_s3_bucket` with `acl = "public-read"` / `"public-read-write"`
//   2. `aws_s3_bucket_public_access_block` with any of the four block_*
//      settings flipped to `false` — that's a deliberate bypass of S3's
//      account-level "Block Public Access" guardrail.
// We consider both Critical: a misconfigured bucket leaks data the moment
// anything is uploaded to it.
import type { IacRule, ResourceContext } from "../types.js";
import { unquoteHcl } from "./_helpers.js";

export const awsS3PublicRule: IacRule = {
  id: "IAC-AWS-S3-PUBLIC",
  title: "S3 bucket allows public access",
  description:
    "The bucket exposes a public ACL or disables one of the public access block settings. " +
    "S3's account-level `Block Public Access` is the last line of defense against accidental " +
    "object-level ACL changes; turning any of the four block_* flags to false re-opens that path.",
  severity: "Critical",
  frameworks: ["terraform"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    const body = ctx.body as Record<string, unknown>;

    if (ctx.resourceType === "aws_s3_bucket") {
      const acl = typeof body["acl"] === "string" ? unquoteHcl(body["acl"] as string) : undefined;
      if (acl === "public-read" || acl === "public-read-write") {
        return {
          evidence: `aws_s3_bucket.${ctx.resourceName} sets acl to a public value`,
          fix: "Remove the `acl` attribute (default is private), or use `aws_s3_bucket_acl` with a private/log-delivery-write ACL and ensure `aws_s3_bucket_public_access_block` is enabled.",
        };
      }
    }

    if (ctx.resourceType === "aws_s3_bucket_public_access_block") {
      const flipped: string[] = [];
      for (const key of [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
      ]) {
        const raw = body[key];
        if (typeof raw === "string" && unquoteHcl(raw).toLowerCase() === "false") {
          flipped.push(key);
        }
      }
      if (flipped.length > 0) {
        return {
          evidence: `aws_s3_bucket_public_access_block disables: ${flipped.join(", ")}`,
          fix: "Set every block_* attribute to true. If a public bucket is intentional, remove this resource entirely so the global account-level block stays in effect.",
        };
      }
    }

    return null;
  },
};
