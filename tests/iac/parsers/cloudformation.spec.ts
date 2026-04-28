import { describe, expect, it } from "vitest";
import { parseCloudFormation, looksLikeCloudFormation } from "../../../src/_shared/iac/parsers/cloudformation.js";

describe("parseCloudFormation", () => {
  it("extracts resources from a YAML template", () => {
    const yaml = `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  LogBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
`;
    const out = parseCloudFormation(yaml, "stack.yaml");
    expect(out.length).toBe(2);
    const bucket = out.find((r) => r.resourceName === "LogBucket")!;
    expect(bucket.resourceType).toBe("AWS::S3::Bucket");
    const props = (bucket.body as Record<string, unknown>)["Properties"] as Record<string, unknown>;
    expect(props["AccessControl"]).toBe("PublicRead");
  });

  it("parses JSON templates", () => {
    const json = JSON.stringify({
      AWSTemplateFormatVersion: "2010-09-09",
      Resources: {
        Bucket: { Type: "AWS::S3::Bucket", Properties: { AccessControl: "Private" } },
      },
    });
    const out = parseCloudFormation(json, "stack.json");
    expect(out.length).toBe(1);
    expect(out[0]!.resourceName).toBe("Bucket");
  });

  it("tolerates CFN intrinsic shorthand without throwing", () => {
    // !Ref / !Sub etc would normally crash a vanilla js-yaml load; our schema
    // has them registered as no-ops so the rest of the document is usable.
    const yaml = `
Resources:
  Q:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub "\${AWS::StackName}-q"
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt DLQ.Arn
        maxReceiveCount: 5
  DLQ:
    Type: AWS::SQS::Queue
`;
    const out = parseCloudFormation(yaml, "queues.yaml");
    expect(out.length).toBe(2);
  });
});

describe("looksLikeCloudFormation", () => {
  it("recognizes AWSTemplateFormatVersion", () => {
    expect(looksLikeCloudFormation("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  X: {}")).toBe(true);
  });

  it("recognizes Resources block with AWS:: typed entries", () => {
    expect(looksLikeCloudFormation("Resources:\n  X:\n    Type: AWS::S3::Bucket\n")).toBe(true);
  });

  it("rejects generic YAML", () => {
    expect(looksLikeCloudFormation("name: foo\nversion: 1.2.3\n")).toBe(false);
  });
});
