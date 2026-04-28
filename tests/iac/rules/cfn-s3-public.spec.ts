import { describe, expect, it } from "vitest";
import { cfnS3PublicRule } from "../../../src/_shared/iac/rules/cfn-s3-public.js";
import { parseCloudFormation } from "../../../src/_shared/iac/parsers/cloudformation.js";

describe("IAC-CFN-S3-PUBLIC", () => {
  it("flags AccessControl: PublicRead", () => {
    const yaml = `
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
`;
    const [r] = parseCloudFormation(yaml, "stack.yaml");
    expect(cfnS3PublicRule.check(r!)).not.toBeNull();
  });

  it("flags PublicAccessBlockConfiguration with a block disabled", () => {
    const yaml = `
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`;
    const [r] = parseCloudFormation(yaml, "stack.yaml");
    expect(cfnS3PublicRule.check(r!)?.evidence).toContain("BlockPublicAcls");
  });

  it("does not flag a private bucket with PAB fully enabled", () => {
    const yaml = `
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`;
    const [r] = parseCloudFormation(yaml, "stack.yaml");
    expect(cfnS3PublicRule.check(r!)).toBeNull();
  });
});
