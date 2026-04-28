import { describe, expect, it } from "vitest";
import { awsIamWildcardRule } from "../../../src/_shared/iac/rules/aws-iam-wildcard.js";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

describe("IAC-AWS-IAM-WILDCARD", () => {
  it("flags a wildcard policy heredoc", () => {
    const tf = `
resource "aws_iam_policy" "god" {
  name = "god"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
}
POLICY
}
`;
    const [r] = parseTerraform(tf, "iam.tf");
    expect(awsIamWildcardRule.check(r!)).not.toBeNull();
  });

  it("does not flag a scoped policy", () => {
    const tf = `
resource "aws_iam_policy" "scoped" {
  name = "scoped"
  policy = <<POLICY
{ "Statement": [{ "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*" }] }
POLICY
}
`;
    const [r] = parseTerraform(tf, "iam.tf");
    expect(awsIamWildcardRule.check(r!)).toBeNull();
  });
});
