import { describe, expect, it } from "vitest";
import { awsS3PublicRule } from "../../../src/_shared/iac/rules/aws-s3-public.js";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

describe("IAC-AWS-S3-PUBLIC", () => {
  it("flags a bucket with acl = public-read", () => {
    const tf = `
resource "aws_s3_bucket" "leak" {
  bucket = "demo"
  acl    = "public-read"
}
`;
    const [r] = parseTerraform(tf, "main.tf");
    expect(awsS3PublicRule.check(r!)).not.toBeNull();
  });

  it("flags a public_access_block that disables blocks", () => {
    const tf = `
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.x.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`;
    const [r] = parseTerraform(tf, "main.tf");
    const result = awsS3PublicRule.check(r!);
    expect(result?.evidence).toContain("block_public_acls");
  });

  it("does not flag a private bucket", () => {
    const tf = `
resource "aws_s3_bucket" "ok" {
  bucket = "ok"
  acl    = "private"
}
`;
    const [r] = parseTerraform(tf, "main.tf");
    expect(awsS3PublicRule.check(r!)).toBeNull();
  });
});
