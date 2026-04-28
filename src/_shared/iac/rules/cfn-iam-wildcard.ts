// IAC-CFN-IAM-WILDCARD — CFN equivalent of IAC-AWS-IAM-WILDCARD.
//
// Walks PolicyDocument / AssumeRolePolicyDocument / inline Policies on
// AWS::IAM::Policy / AWS::IAM::Role / AWS::IAM::ManagedPolicy. Unlike the
// Terraform variant we have proper structured access here, so we can be
// strict (Effect=Allow + Action=* + Resource=* on the same Statement) with
// no false-positive risk from regex bleed.
import type { IacRule, ResourceContext } from "../types.js";
import { fieldContainsWildcard, walkCfnPolicyStatements } from "./_helpers.js";

const TARGET_TYPES = new Set([
  "AWS::IAM::Policy",
  "AWS::IAM::Role",
  "AWS::IAM::ManagedPolicy",
  "AWS::IAM::User",
  "AWS::IAM::Group",
]);

export const cfnIamWildcardRule: IacRule = {
  id: "IAC-CFN-IAM-WILDCARD",
  title: "IAM policy grants wildcard action on wildcard resource (CloudFormation)",
  description:
    "A CloudFormation IAM resource includes a Statement with Effect Allow, Action `*`, and " +
    "Resource `*`. That's admin access — scope at least one of action or resource down.",
  severity: "High",
  frameworks: ["cloudformation"],
  check(ctx: ResourceContext) {
    if (!TARGET_TYPES.has(ctx.resourceType)) return null;
    if (typeof ctx.body !== "object") return null;
    const props = ((ctx.body as Record<string, unknown>)["Properties"] ?? {}) as Record<string, unknown>;
    for (const stmt of walkCfnPolicyStatements(props)) {
      if (stmt["Effect"] !== "Allow") continue;
      if (!fieldContainsWildcard(stmt["Action"])) continue;
      if (!fieldContainsWildcard(stmt["Resource"])) continue;
      return {
        evidence: `${ctx.resourceName} (${ctx.resourceType}) has an Allow statement with Action=* and Resource=*`,
        fix: "Replace the wildcards with specific actions and resource ARNs the principal actually needs. Use IAM Access Analyzer or CloudTrail to discover the in-use permission set.",
      };
    }
    return null;
  },
};
