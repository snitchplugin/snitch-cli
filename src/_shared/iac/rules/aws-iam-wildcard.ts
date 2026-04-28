// IAC-AWS-IAM-WILDCARD — flag IAM policy documents that grant `*` action on
// `*` resource with `Allow` effect. That's the canonical "god mode" policy
// and almost never what's intended outside of a deliberate admin role.
//
// Why we require ALL THREE conditions (action=*, resource=*, effect=Allow):
// false positives are expensive in IaC scans (developers tune them out),
// and any one of these alone is sometimes legitimate (e.g. `Action = "*"`
// on a resource-scoped policy is loose but bounded). All three together is
// almost never anything but an oversight or copy-paste from an example.
import type { IacRule, ResourceContext } from "../types.js";
import { unquoteHcl } from "./_helpers.js";

export const awsIamWildcardRule: IacRule = {
  id: "IAC-AWS-IAM-WILDCARD",
  title: "IAM policy grants wildcard action on wildcard resource",
  description:
    "An IAM policy document allows the `*` action on the `*` resource with effect `Allow`. " +
    "This is admin access. Scope at least one of action or resource down to what the principal " +
    "actually needs.",
  severity: "High",
  frameworks: ["terraform"],
  check(ctx: ResourceContext) {
    if (typeof ctx.body !== "object") return null;
    if (
      ctx.resourceType !== "aws_iam_policy" &&
      ctx.resourceType !== "aws_iam_role_policy" &&
      ctx.resourceType !== "aws_iam_user_policy" &&
      ctx.resourceType !== "aws_iam_group_policy"
    ) {
      return null;
    }
    const body = ctx.body as Record<string, unknown>;
    // The policy attribute is typically a heredoc'd JSON document or a
    // jsonencode({...}) call. We do shallow string matching on the raw
    // body — if all three patterns appear in the same document we flag.
    // This is a deliberate trade-off vs. parsing JSON inside HCL inside
    // an interpolation: simpler, only false-positives on weird hand-crafted
    // strings that mention all three tokens for unrelated reasons.
    const raw = typeof body["__raw"] === "string" ? (body["__raw"] as string) : "";
    const polValue = typeof body["policy"] === "string" ? unquoteHcl(body["policy"] as string) : "";
    const haystack = `${raw}\n${polValue}`;
    const hasActionStar = /"Action"\s*[:=]\s*"\*"|"Action"\s*[:=]\s*\[\s*"\*"\s*\]/.test(haystack);
    const hasResourceStar = /"Resource"\s*[:=]\s*"\*"|"Resource"\s*[:=]\s*\[\s*"\*"\s*\]/.test(haystack);
    const hasEffectAllow = /"Effect"\s*[:=]\s*"Allow"/.test(haystack);
    if (hasActionStar && hasResourceStar && hasEffectAllow) {
      return {
        evidence: `${ctx.resourceType}.${ctx.resourceName} contains an Allow statement with Action=* and Resource=*`,
        fix: "Replace `*` with the specific actions and ARNs the principal needs. Use IAM Access Analyzer or CloudTrail to identify the actual permissions in use.",
      };
    }
    return null;
  },
};
