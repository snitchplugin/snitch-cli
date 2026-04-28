import { describe, expect, it } from "vitest";
import { awsSecretInTfRule } from "../../../src/_shared/iac/rules/aws-secret-in-tf.js";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

// We deliberately use synthetic-but-shape-valid sentinel values built from
// concatenation so the tokens themselves don't get flagged by repo-wide
// secret scanners. The pattern detection in the rule only cares about
// shape, not provenance.
// "AKIA" + exactly 16 [0-9A-Z] chars = 20-char total (canonical AWS access key id length).
const FAKE_AWS_KEY = "AKIA" + "EXAMPLE012345678";
const FAKE_STRIPE_KEY = "sk_live_" + "X".repeat(24);

describe("IAC-AWS-SECRET-IN-TF", () => {
  it("flags an AWS access key id embedded in a resource body", () => {
    const tf = `
resource "aws_secretsmanager_secret_version" "leak" {
  secret_id     = aws_secretsmanager_secret.x.id
  secret_string = "${FAKE_AWS_KEY}"
}
`;
    const [r] = parseTerraform(tf, "secrets.tf");
    expect(awsSecretInTfRule.check(r!)).not.toBeNull();
  });

  it("flags a Stripe live key", () => {
    const tf = `
resource "aws_ssm_parameter" "stripe" {
  name  = "/stripe/key"
  value = "${FAKE_STRIPE_KEY}"
}
`;
    const [r] = parseTerraform(tf, "ssm.tf");
    expect(awsSecretInTfRule.check(r!)).not.toBeNull();
  });

  it("does not flag a resource referencing values from elsewhere", () => {
    const tf = `
resource "aws_secretsmanager_secret_version" "ok" {
  secret_id     = aws_secretsmanager_secret.x.id
  secret_string = var.stripe_secret
}
`;
    const [r] = parseTerraform(tf, "secrets.tf");
    expect(awsSecretInTfRule.check(r!)).toBeNull();
  });
});
