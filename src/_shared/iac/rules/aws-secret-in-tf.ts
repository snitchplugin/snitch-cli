// IAC-AWS-SECRET-IN-TF — flag what looks like a hardcoded secret in a
// Terraform file. State files leak; modules get vendored into other repos;
// `terraform plan` output gets posted in PR comments. Anything that lives
// in a .tf file is effectively public-by-default.
//
// We deliberately keep the pattern set narrow + high-signal:
//  - AWS access key ids are AKIA-prefixed and 20 chars (well-known)
//  - Stripe live secret keys are sk_live_-prefixed
//  - PEM private key blocks are unmistakable
//  - Slack tokens are xox[abp]- prefixed
// Anything looser (e.g. random 32-char hex) generates noise out of proportion
// to the catch rate. Customers who want broader secret scanning should run
// gitleaks/trufflehog separately.
import type { IacRule, ResourceContext } from "../types.js";

const PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "Stripe live secret key", re: /\bsk_live_[0-9a-zA-Z]{16,}/ },
  { name: "PEM private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "Slack token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}/ },
];

export const awsSecretInTfRule: IacRule = {
  id: "IAC-AWS-SECRET-IN-TF",
  title: "Hardcoded secret detected in Terraform source",
  description:
    "A value matching a well-known credential pattern is embedded directly in the .tf file. " +
    "Terraform state, plan output, and committed source all expose this verbatim — assume " +
    "it is already compromised once it lands in version control.",
  severity: "Critical",
  // We don't restrict to specific resource types — secrets can show up in any
  // resource attribute. The framework filter (terraform only) is enough.
  frameworks: ["terraform"],
  check(ctx: ResourceContext) {
    const haystack = typeof ctx.body === "object"
      ? (((ctx.body as Record<string, unknown>)["__raw"] as string | undefined) ?? "")
      : typeof ctx.body === "string" ? ctx.body : "";
    for (const { name, re } of PATTERNS) {
      if (re.test(haystack)) {
        return {
          evidence: `${ctx.resourceType}.${ctx.resourceName} body matches ${name} pattern`,
          fix: "Move the value to a Terraform variable sourced from `TF_VAR_*`, an `aws_secretsmanager_secret`, an `aws_ssm_parameter` of type SecureString, or a CI secret. Then rotate the exposed credential — assume it is compromised.",
        };
      }
    }
    return null;
  },
};
