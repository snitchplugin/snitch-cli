import { describe, expect, it } from "vitest";
import { parseTerraform } from "../../../src/_shared/iac/parsers/terraform.js";

describe("parseTerraform", () => {
  it("extracts resource blocks with attributes and nested blocks", () => {
    const tf = `
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
  acl    = "private"

  versioning {
    enabled = true
  }
}

resource "aws_db_instance" "db" {
  storage_encrypted = false
}
`;
    const out = parseTerraform(tf, "main.tf");
    expect(out.length).toBe(2);
    const bucket = out.find((r) => r.resourceType === "aws_s3_bucket");
    expect(bucket?.resourceName).toBe("logs");
    expect(bucket?.framework).toBe("terraform");
    const body = bucket!.body as Record<string, unknown>;
    expect(body["bucket"]).toBe('"my-logs"');
    expect(body["acl"]).toBe('"private"');
    // nested blocks captured as raw strings
    expect(typeof body["versioning"]).toBe("string");
    expect(body["versioning"]).toContain("enabled = true");

    const db = out.find((r) => r.resourceType === "aws_db_instance");
    expect((db!.body as Record<string, unknown>)["storage_encrypted"]).toBe("false");
  });

  it("collects sibling blocks with the same name into an array", () => {
    const tf = `
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 80
    to_port   = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const out = parseTerraform(tf, "sg.tf");
    expect(out.length).toBe(1);
    const ingress = (out[0]!.body as Record<string, unknown>)["ingress"];
    expect(Array.isArray(ingress)).toBe(true);
    expect((ingress as string[]).length).toBe(2);
  });

  it("ignores braces inside strings, comments, and heredocs", () => {
    const tf = `
resource "aws_iam_policy" "p" {
  # this { is not a block
  description = "value with } brace"
  policy = <<EOF
{ "Statement": { "Effect": "Allow" } }
EOF
}
`;
    const out = parseTerraform(tf, "iam.tf");
    expect(out.length).toBe(1);
    expect(out[0]!.resourceName).toBe("p");
  });
});
