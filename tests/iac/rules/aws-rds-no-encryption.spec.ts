import { describe, expect, it } from "vitest";
import { awsRdsNoEncryptionRule } from "../../../src/_shared/iac/rules/aws-rds-no-encryption.js";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

describe("IAC-AWS-RDS-NO-ENCRYPTION", () => {
  it("flags a db_instance with storage_encrypted = false", () => {
    const tf = `
resource "aws_db_instance" "primary" {
  engine            = "postgres"
  storage_encrypted = false
}
`;
    const [r] = parseTerraform(tf, "rds.tf");
    expect(awsRdsNoEncryptionRule.check(r!)).not.toBeNull();
  });

  it("flags a db_instance with storage_encrypted unset", () => {
    const tf = `
resource "aws_db_instance" "primary" {
  engine = "postgres"
}
`;
    const [r] = parseTerraform(tf, "rds.tf");
    expect(awsRdsNoEncryptionRule.check(r!)).not.toBeNull();
  });

  it("does not flag a db_instance with storage_encrypted = true", () => {
    const tf = `
resource "aws_db_instance" "primary" {
  storage_encrypted = true
}
`;
    const [r] = parseTerraform(tf, "rds.tf");
    expect(awsRdsNoEncryptionRule.check(r!)).toBeNull();
  });
});
