import { describe, expect, it } from "vitest";
import { cfnIamWildcardRule } from "../../../src/_shared/iac/rules/cfn-iam-wildcard.js";
import { parseCloudFormation } from "../../../src/_shared/iac/parsers/cloudformation.js";

describe("IAC-CFN-IAM-WILDCARD", () => {
  it("flags an IAM Policy with Allow * on *", () => {
    const yaml = `
Resources:
  P:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: god
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
`;
    const [r] = parseCloudFormation(yaml, "iam.yaml");
    expect(cfnIamWildcardRule.check(r!)).not.toBeNull();
  });

  it("flags an inline Policy on a Role", () => {
    const yaml = `
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Action: sts:AssumeRole
            Principal:
              Service: ec2.amazonaws.com
      Policies:
        - PolicyName: too-wide
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: ["*"]
                Resource: "*"
`;
    const [r] = parseCloudFormation(yaml, "iam.yaml");
    expect(cfnIamWildcardRule.check(r!)).not.toBeNull();
  });

  it("does not flag a scoped policy", () => {
    const yaml = `
Resources:
  P:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: scoped
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::bucket/*"
`;
    const [r] = parseCloudFormation(yaml, "iam.yaml");
    expect(cfnIamWildcardRule.check(r!)).toBeNull();
  });
});
