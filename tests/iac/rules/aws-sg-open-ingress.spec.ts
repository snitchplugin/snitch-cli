import { describe, expect, it } from "vitest";
import { awsSgOpenIngressRule } from "../../../src/_shared/iac/rules/aws-sg-open-ingress.js";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

describe("IAC-AWS-SG-OPEN-INGRESS", () => {
  it("flags 0.0.0.0/0 on port 22 inside a security_group ingress block", () => {
    const tf = `
resource "aws_security_group" "ssh" {
  name = "ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const [r] = parseTerraform(tf, "sg.tf");
    const result = awsSgOpenIngressRule.check(r!);
    expect(result?.evidence).toContain("SSH");
  });

  it("flags 0.0.0.0/0 on a port-range covering postgres via security_group_rule", () => {
    const tf = `
resource "aws_security_group_rule" "open" {
  type        = "ingress"
  from_port   = 5000
  to_port     = 6000
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
`;
    const [r] = parseTerraform(tf, "sg.tf");
    const result = awsSgOpenIngressRule.check(r!);
    expect(result?.evidence).toContain("PostgreSQL");
  });

  it("does not flag 0.0.0.0/0 on port 443", () => {
    const tf = `
resource "aws_security_group" "https" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const [r] = parseTerraform(tf, "sg.tf");
    expect(awsSgOpenIngressRule.check(r!)).toBeNull();
  });
});
